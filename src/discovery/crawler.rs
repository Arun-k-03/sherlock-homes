use crate::core::events::{EventBus, EventKind, ScanEvent};
use crate::core::rate_limit::RateLimiter;
use crate::core::scope::ScopeGuard;
use crate::core::types::{Endpoint, ParamLocation, Parameter};
use crate::discovery::endpoints::from_url;
use crate::discovery::javascript;
use crate::discovery::parser::parse_html;
use crate::discovery::safety::{
    is_generated_artifact_path, looks_like_generated_child, parent_dir,
};
use crate::network::client::{Fetched, HttpEngine};
use crate::network::response::RecordedResponse;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone)]
pub struct CrawlLimits {
    pub max_depth: u32,
    pub max_pages: u32,
    pub max_requests: u32,
    pub max_queue: usize,
    pub max_children_per_parent: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_pages: 250,
            max_requests: 500,
            max_queue: 1000,
            max_children_per_parent: 80,
        }
    }
}

pub struct CrawlResult {
    pub pages: Vec<Fetched>,
    pub endpoints: Vec<Endpoint>,
    pub budget_exhausted: bool,
}

pub async fn crawl(
    start: &Url,
    http: &HttpEngine,
    scope: &ScopeGuard,
    rate: &RateLimiter,
    cancel: &CancellationToken,
    events: &EventBus,
    case_id: &str,
    limits: &CrawlLimits,
) -> crate::Result<CrawlResult> {
    events.emit(ScanEvent::new(
        EventKind::DiscoveryStarted,
        case_id,
        "following request trails",
    ));

    let mut queue: VecDeque<(Url, u32)> = VecDeque::new();
    queue.push_back((start.clone(), 0));
    let mut seen: HashSet<String> = HashSet::new();
    let mut pages = Vec::new();
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut children: HashMap<String, usize> = HashMap::new();
    let mut requests = 0u32;
    let mut budget_exhausted = false;

    while let Some((url, d)) = queue.pop_front() {
        if cancel.is_cancelled() {
            break;
        }
        if d > limits.max_depth {
            continue;
        }
        if is_generated_artifact_path(url.path()) {
            continue;
        }
        let key = canonical(&url);
        if !seen.insert(key) {
            continue;
        }
        if scope.allows_url(&url).is_err() {
            continue;
        }
        if pages.len() as u32 >= limits.max_pages || requests >= limits.max_requests {
            budget_exhausted = true;
            emit_guard(
                events,
                case_id,
                "Crawl request budget reached. Discovery stopped safely.",
            );
            break;
        }
        requests += 1;
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
        emit_clue(events, case_id, &ep);
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
                            emit_clue(events, case_id, &ep);
                            merge_endpoint(&mut endpoints, ep);
                            enqueue(
                                &mut queue,
                                fu,
                                d + 1,
                                limits,
                                &mut children,
                                &mut budget_exhausted,
                                events,
                                case_id,
                            );
                        }
                    }
                }
                for link in parsed.links {
                    if let Ok(u) = Url::parse(&link) {
                        enqueue(
                            &mut queue,
                            u,
                            d + 1,
                            limits,
                            &mut children,
                            &mut budget_exhausted,
                            events,
                            case_id,
                        );
                    }
                }
                for script in parsed.scripts {
                    if let Ok(su) = Url::parse(&script) {
                        if scope.allows_url(&su).is_ok() {
                            enqueue(
                                &mut queue,
                                su,
                                d + 1,
                                limits,
                                &mut children,
                                &mut budget_exhausted,
                                events,
                                case_id,
                            );
                        }
                    }
                }
            }
        }

        let ct = fetched.response.content_type.clone().unwrap_or_default();
        if ct.contains("javascript") || fetched.response.final_url.ends_with(".js") {
            if let Some(text) = &fetched.response.body_text {
                for api in javascript::extract_confirmed_request_urls(&url, text) {
                    if let Ok(u) = Url::parse(&api) {
                        if scope.allows_url(&u).is_ok() {
                            let ep = from_url("GET", &u);
                            emit_clue(events, case_id, &ep);
                            merge_endpoint(&mut endpoints, ep);
                            enqueue(
                                &mut queue,
                                u,
                                d + 1,
                                limits,
                                &mut children,
                                &mut budget_exhausted,
                                events,
                                case_id,
                            );
                        }
                    }
                }
                for raw in javascript::extract_string_api_candidates(text) {
                    let mut ep = from_url("GET", &url);
                    ep.normalized_path = raw.clone();
                    ep.auth_hint = Some("js-string-reference".into());
                    ep.url = format!("js-ref:{raw}");
                    merge_endpoint(&mut endpoints, ep);
                }
            }
        }

        pages.push(fetched);
        if budget_exhausted {
            break;
        }
    }

    events.emit(ScanEvent::new(
        EventKind::DiscoveryCompleted,
        case_id,
        "attack surface mapped",
    ));

    Ok(CrawlResult {
        pages,
        endpoints,
        budget_exhausted,
    })
}

fn emit_clue(events: &EventBus, case_id: &str, ep: &Endpoint) {
    events.emit(
        ScanEvent::new(EventKind::EndpointDiscovered, case_id, ep.key())
            .with_endpoint(&ep.method, &ep.normalized_path),
    );
}

fn emit_guard(events: &EventBus, case_id: &str, msg: &str) {
    events.emit(ScanEvent::new(
        EventKind::Warning,
        case_id,
        format!("[GUARD] {msg}"),
    ));
}

fn enqueue(
    queue: &mut VecDeque<(Url, u32)>,
    url: Url,
    depth: u32,
    limits: &CrawlLimits,
    children: &mut HashMap<String, usize>,
    budget_exhausted: &mut bool,
    events: &EventBus,
    case_id: &str,
) {
    if depth > limits.max_depth {
        return;
    }
    if is_generated_artifact_path(url.path()) {
        return;
    }
    if queue.len() >= limits.max_queue {
        if !*budget_exhausted {
            *budget_exhausted = true;
            emit_guard(
                events,
                case_id,
                "Crawl queue budget reached. Discovery stopped safely.",
            );
        }
        return;
    }
    let parent = parent_dir(url.path());
    let name = url.path().rsplit('/').next().unwrap_or("");
    let count = children.entry(parent).or_insert(0);
    *count += 1;
    if *count > limits.max_children_per_parent && looks_like_generated_child(name) {
        return;
    }
    if *count > limits.max_children_per_parent.saturating_mul(2) {
        return;
    }
    queue.push_back((url, depth));
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
        if existing.auth_hint.is_none() {
            existing.auth_hint = ep.auth_hint;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_conservative() {
        let l = CrawlLimits::default();
        assert!(l.max_pages <= 500);
        assert!(l.max_requests <= 1000);
        assert!(l.max_queue <= 2000);
    }

    #[test]
    fn queue_budget_marks_exhausted() {
        let mut q = VecDeque::new();
        let mut children = HashMap::new();
        let mut exhausted = false;
        let events = EventBus::new(16);
        let limits = CrawlLimits {
            max_queue: 3,
            ..Default::default()
        };
        let base = Url::parse("http://127.0.0.1/").unwrap();
        for i in 0..10 {
            let u = base.join(&format!("/n{i}")).unwrap();
            enqueue(
                &mut q,
                u,
                1,
                &limits,
                &mut children,
                &mut exhausted,
                &events,
                "SH-Q",
            );
        }
        assert!(exhausted);
        assert!(q.len() <= 3);
    }
}
