use crate::core::config::ScanMode;
use crate::core::types::{CandidateFinding, Confidence, Endpoint, ParamLocation, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use crate::verification::differential::compare;
use async_trait::async_trait;
use url::Url;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(ReflectedXss)]
}

struct ReflectedXss;

const CANARY: &str = "shx7m3q";
const PAYLOAD: &str = r#"shx7m3q"><svg/onload=prompt(1)>"#;

#[async_trait]
impl Detector for ReflectedXss {
    fn id(&self) -> &'static str {
        "reflected_xss"
    }
    fn name(&self) -> &'static str {
        "Reflected input / XSS candidates"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        endpoint
            .parameters
            .iter()
            .any(|p| p.location == ParamLocation::Query || p.location == ParamLocation::Form)
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        if matches!(ctx.mode, ScanMode::Passive) {
            return Ok(vec![]);
        }
        let Ok(base) = Url::parse(&endpoint.url) else {
            return Ok(vec![]);
        };
        let baseline = match ctx
            .http
            .execute("GET", &base, None, None, ctx.scope, ctx.rate, ctx.cancel)
            .await
        {
            Ok(f) => f.response,
            Err(_) => return Ok(vec![]),
        };
        let mut out = Vec::new();
        for p in &endpoint.parameters {
            if p.location != ParamLocation::Query {
                continue;
            }
            let Ok(mut url) = Url::parse(&endpoint.url) else {
                continue;
            };
            let mut pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            if pairs.iter().any(|(k, _)| k == &p.name) {
                for (k, v) in pairs.iter_mut() {
                    if k == &p.name {
                        *v = PAYLOAD.into();
                    }
                }
            } else {
                pairs.push((p.name.clone(), PAYLOAD.into()));
            }
            url.set_query(None);
            url.query_pairs_mut().extend_pairs(&pairs);
            let fetched = match ctx
                .http
                .execute("GET", &url, None, None, ctx.scope, ctx.rate, ctx.cancel)
                .await
            {
                Ok(f) => f,
                Err(_) => continue,
            };
            let body = fetched.response.text();
            if !body.contains(CANARY) {
                continue;
            }
            let unescaped = body.contains(PAYLOAD) || body.contains(r#"shx7m3q"><svg"#);
            let diff = compare(&baseline, &fetched.response);
            let confidence = if unescaped && diff.reflection {
                Confidence::HighConfidence
            } else if body.contains(CANARY) {
                Confidence::Likely
            } else {
                continue;
            };
            let title = if unescaped {
                "Reflected Cross-Site Scripting"
            } else {
                "Reflected input (encoding unknown / candidate XSS)"
            };
            out.push(CandidateFinding {
                detector_id: "reflected_xss".into(),
                detector_name: self.name().into(),
                title: title.into(),
                description: format!(
                    "Parameter '{}' reflected the investigation canary in the response{}.",
                    p.name,
                    if unescaped {
                        " without HTML encoding of quotes/tags"
                    } else {
                        ""
                    }
                ),
                severity: if unescaped {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence,
                cwe: Some("CWE-79".into()),
                owasp: Some("A03:2021 Injection".into()),
                method: endpoint.method.clone(),
                endpoint: endpoint.normalized_path.clone(),
                parameter: Some(p.name.clone()),
                evidence_summary: format!(
                    "canary={CANARY} unescaped={unescaped} status_delta={} length_delta={}",
                    diff.status_diff, diff.length_diff
                ),
                fingerprint: fingerprint(
                    &endpoint.host,
                    &endpoint.method,
                    &endpoint.normalized_path,
                    Some(&p.name),
                    "reflected_xss",
                ),
                source_engine: "sherlock-core".into(),
            });
        }
        Ok(out)
    }
}
