use crate::core::events::{EventBus, EventKind, ScanEvent};
use crate::core::rate_limit::RateLimiter;
use crate::core::scope::ScopeGuard;
use crate::core::types::{Endpoint, ParamLocation, Parameter};
use crate::discovery::endpoints::from_url;
use crate::discovery::javascript;
use crate::discovery::parser::parse_html;
use crate::network::client::{Fetched, HttpEngine};
use crate::network::response::RecordedResponse;
use std::collections::{HashSet, VecDeque};
use tokio_util::sync::CancellationToken;
use url::Url;

pub struct CrawlResult {
    pub pages: Vec<Fetched>,
    pub endpoints: Vec<Endpoint>,
}

pub async fn crawl(
    start: &Url,
    depth: u32,
    http: &HttpEngine,
    scope: &ScopeGuard,
    rate: &RateLimiter,
    cancel: &CancellationToken,
    events: &EventBus,
    case_id: &str,
) -> crate::Result<CrawlResult> {
    let mut queue: VecDeque<(Url, u32)> = VecDeque::new();
    queue.push_back((start.clone(), 0));
    let mut seen: HashSet<String> = HashSet::new();
    let mut pages = Vec::new();
    let mut endpoints: Vec<Endpoint> = Vec::new();

    while let Some((url, d)) = queue.pop_front() {
        if cancel.is_cancelled() {
            break;
        }
        if d > depth {
            continue;
        }
        let key = canonical(&url);
        if !seen.insert(key) {
            continue;
        }
        if scope.allows_url(&url).is_err() {
            continue;
        }
        let fetched = match http.get(&url, scope, rate, cancel).await {
            Ok(f) => f,
            Err(crate::SherlockError::Cancelled) => break,
            Err(_) => continue,
        };
        events.emit(
            ScanEvent::new(
                EventKind::PageDiscovered,
                case_id,
                fetched.response.final_url.clone(),
            )
            .with_endpoint("GET", url.path()),
        );
        let ep = from_url("GET", &url);
        events.emit(
            ScanEvent::new(EventKind::EndpointDiscovered, case_id, ep.key())
                .with_endpoint(&ep.method, &ep.normalized_path),
        );
        merge_endpoint(&mut endpoints, ep);

        if fetched.response.is_html() {
            if let Some(text) = &fetched.response.body_text {
                let parsed = parse_html(&url, text);
                for form in &parsed.forms {
                    if let Ok(fu) = Url::parse(&form.action) {
                        if scope.allows_url(&fu).is_ok() {
                            let mut ep = from_url(&form.method, &fu);
                            for (name, typ) in &form.inputs {
                                ep.parameters.push(Parameter {
                                    name: name.clone(),
                                    location: if form.method == "GET" {
                                        ParamLocation::Query
                                    } else {
                                        ParamLocation::Form
                                    },
                                    sample: None,
                                    inferred_type: typ.clone(),
                                });
                            }
                            events.emit(ScanEvent::new(
                                EventKind::EndpointDiscovered,
                                case_id,
                                ep.key(),
                            ));
                            merge_endpoint(&mut endpoints, ep);
                            if d < depth {
                                queue.push_back((fu, d + 1));
                            }
                        }
                    }
                }
                for link in parsed.links {
                    if let Ok(u) = Url::parse(&link) {
                        if d < depth {
                            queue.push_back((u, d + 1));
                        }
                    }
                }
                for script in parsed.scripts {
                    if let Ok(su) = Url::parse(&script) {
                        if d < depth && scope.allows_url(&su).is_ok() {
                            queue.push_back((su, d + 1));
                        }
                    }
                }
            }
        }

        let ct = fetched.response.content_type.clone().unwrap_or_default();
        if ct.contains("javascript") || fetched.response.final_url.ends_with(".js") {
            if let Some(text) = &fetched.response.body_text {
                for api in javascript::extract_api_paths(&url, text) {
                    if let Ok(u) = Url::parse(&api) {
                        if scope.allows_url(&u).is_ok() {
                            let ep = from_url("GET", &u);
                            events.emit(ScanEvent::new(
                                EventKind::EndpointDiscovered,
                                case_id,
                                ep.key(),
                            ));
                            merge_endpoint(&mut endpoints, ep);
                            if d < depth {
                                queue.push_back((u, d + 1));
                            }
                        }
                    }
                }
            }
        }

        pages.push(fetched);
    }

    Ok(CrawlResult { pages, endpoints })
}

fn canonical(u: &Url) -> String {
    let mut c = u.clone();
    c.set_fragment(None);
    format!(
        "{}://{}{}",
        c.scheme(),
        c.host_str().unwrap_or(""),
        c.path()
    )
}

fn merge_endpoint(list: &mut Vec<Endpoint>, ep: Endpoint) {
    if let Some(existing) = list
        .iter_mut()
        .find(|e| e.method == ep.method && e.normalized_path == ep.normalized_path)
    {
        for p in ep.parameters {
            if !existing
                .parameters
                .iter()
                .any(|x| x.name == p.name && x.location == p.location)
            {
                existing.parameters.push(p);
            }
        }
    } else {
        list.push(ep);
    }
}

pub fn sensitive_probe_paths() -> &'static [&'static str] {
    &[
        "/.env",
        "/.git/HEAD",
        "/.git/config",
        "/robots.txt",
        "/sitemap.xml",
        "/server-status",
        "/.DS_Store",
        "/backup.zip",
        "/web.config",
        "/phpinfo.php",
        "/api/docs",
        "/swagger.json",
        "/openapi.json",
        "/graphql",
        "/.well-known/security.txt",
        "/debug",
        "/actuator/health",
        "/source-map",
    ]
}

/// Safe GET probes for common sensitive files (non-destructive).
pub async fn probe_sensitive(
    base: &Url,
    http: &HttpEngine,
    scope: &ScopeGuard,
    rate: &RateLimiter,
    cancel: &CancellationToken,
) -> Vec<(String, RecordedResponse)> {
    let mut out = Vec::new();
    for p in sensitive_probe_paths() {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(u) = base.join(p) else { continue };
        if scope.allows_url(&u).is_err() {
            continue;
        }
        if let Ok(f) = http.get(&u, scope, rate, cancel).await {
            if f.response.status != 404 && f.response.status != 0 {
                out.push((p.to_string(), f.response));
            }
        }
    }
    out
}
