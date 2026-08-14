use crate::core::config::ScanMode;
use crate::core::types::{CandidateFinding, Confidence, Endpoint, ParamLocation, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use async_trait::async_trait;
use url::Url;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(OpenRedirect)]
}

struct OpenRedirect;

#[async_trait]
impl Detector for OpenRedirect {
    fn id(&self) -> &'static str {
        "open_redirect"
    }
    fn name(&self) -> &'static str {
        "Open redirect behavior"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        endpoint.parameters.iter().any(|p| {
            p.location == ParamLocation::Query
                && matches!(
                    p.name.to_ascii_lowercase().as_str(),
                    "next"
                        | "url"
                        | "redirect"
                        | "return"
                        | "returnurl"
                        | "goto"
                        | "dest"
                        | "destination"
                        | "continue"
                        | "r"
                )
        })
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        if matches!(ctx.mode, ScanMode::Passive) {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for p in &endpoint.parameters {
            if !self.supports(endpoint) {
                break;
            }
            if p.location != ParamLocation::Query {
                continue;
            }
            let Ok(mut url) = Url::parse(&endpoint.url) else {
                continue;
            };
            let marker = "https://sherlock-probe.invalid/clue";
            {
                let mut pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                if pairs.iter().any(|(k, _)| k == &p.name) {
                    for (k, v) in pairs.iter_mut() {
                        if k == &p.name {
                            *v = marker.into();
                        }
                    }
                } else {
                    pairs.push((p.name.clone(), marker.into()));
                }
                url.set_query(None);
                url.query_pairs_mut().extend_pairs(&pairs);
            }
            let fetched = match ctx
                .http
                .execute("GET", &url, None, None, ctx.scope, ctx.rate, ctx.cancel)
                .await
            {
                Ok(f) => f,
                Err(_) => continue,
            };
            let loc = fetched.response.header("location").unwrap_or("");
            let bounced = loc.contains("sherlock-probe.invalid")
                || fetched
                    .response
                    .redirects
                    .iter()
                    .any(|r| r.contains("sherlock-probe.invalid"));
            if bounced {
                out.push(CandidateFinding {
                    detector_id: "open_redirect".into(),
                    detector_name: "Open redirect".into(),
                    title: format!("Open redirect via parameter '{}'", p.name),
                    description: format!(
                        "Setting {}={} produced a redirect toward the probe host.",
                        p.name, marker
                    ),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    cwe: Some("CWE-601".into()),
                    owasp: Some("A01:2021 Broken Access Control".into()),
                    method: endpoint.method.clone(),
                    endpoint: endpoint.normalized_path.clone(),
                    parameter: Some(p.name.clone()),
                    evidence_summary: format!("Location: {loc}"),
                    fingerprint: fingerprint(
                        &endpoint.host,
                        &endpoint.method,
                        &endpoint.normalized_path,
                        Some(&p.name),
                        "open_redirect",
                    ),
                    source_engine: "sherlock-core".into(),
                    host: endpoint.host.clone(),
                    ..Default::default()
                });
            }
        }
        Ok(out)
    }
}
