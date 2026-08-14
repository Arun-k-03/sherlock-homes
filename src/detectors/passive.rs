use crate::core::types::{CandidateFinding, Confidence, Endpoint, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use crate::network::response::RecordedResponse;
use async_trait::async_trait;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(SecurityHeaders),
        Box::new(CookieFlags),
        Box::new(CorsPassive),
    ]
}

fn page_for<'a>(ctx: &'a DetectorContext<'a>, ep: &Endpoint) -> Option<&'a RecordedResponse> {
    ctx.pages.iter().find(|p| {
        url::Url::parse(&p.final_url)
            .ok()
            .map(|u| crate::discovery::normalize_path(u.path()) == ep.normalized_path)
            .unwrap_or(false)
    })
}

struct SecurityHeaders;
struct CookieFlags;
struct CorsPassive;

#[async_trait]
impl Detector for SecurityHeaders {
    fn id(&self) -> &'static str {
        "security_headers"
    }
    fn name(&self) -> &'static str {
        "Security header weaknesses"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        endpoint.method == "GET"
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(page) = page_for(ctx, endpoint) else {
            return Ok(vec![]);
        };
        if page.status >= 400 {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let checks = [
            (
                "content-security-policy",
                "missing_csp",
                "Missing Content-Security-Policy",
                "CWE-693",
                "A05:2021 Security Misconfiguration",
                Severity::Low,
            ),
            (
                "strict-transport-security",
                "missing_hsts",
                "Missing Strict-Transport-Security",
                "CWE-319",
                "A02:2021 Cryptographic Failures",
                Severity::Low,
            ),
            (
                "x-content-type-options",
                "missing_xcto",
                "Missing X-Content-Type-Options",
                "CWE-693",
                "A05:2021 Security Misconfiguration",
                Severity::Low,
            ),
            (
                "x-frame-options",
                "x_frame_options",
                "Missing X-Frame-Options / frame-ancestors",
                "CWE-1021",
                "A05:2021 Security Misconfiguration",
                Severity::Low,
            ),
            (
                "referrer-policy",
                "missing_referrer_policy",
                "Missing Referrer-Policy",
                "CWE-200",
                "A05:2021 Security Misconfiguration",
                Severity::Informational,
            ),
        ];
        let has_csp = page.header("content-security-policy").is_some();
        for (hdr, class, title, cwe, owasp, sev) in checks {
            if hdr == "x-frame-options" {
                let framed = page.header("x-frame-options").is_some()
                    || page
                        .header("content-security-policy")
                        .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
                        .unwrap_or(false);
                if framed {
                    continue;
                }
            } else if page.header(hdr).is_some() {
                continue;
            }
            if hdr == "strict-transport-security" && !endpoint.url.starts_with("https://") {
                continue;
            }
            let _ = has_csp;
            out.push(finding(
                ctx,
                endpoint,
                class,
                title,
                format!(
                    "Response to {} {} did not include the '{hdr}' header.",
                    endpoint.method, endpoint.normalized_path
                ),
                sev,
                Confidence::Confirmed,
                Some(cwe),
                Some(owasp),
                format!("Observed response headers did not contain {hdr}."),
            ));
        }
        Ok(out)
    }
}

#[async_trait]
impl Detector for CookieFlags {
    fn id(&self) -> &'static str {
        "cookie_flags"
    }
    fn name(&self) -> &'static str {
        "Cookie security weaknesses"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        endpoint.method == "GET"
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(page) = page_for(ctx, endpoint) else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        for c in crate::network::cookies::parse_set_cookie(&page.headers) {
            if c.name.is_empty() {
                continue;
            }
            let mut missing = Vec::new();
            if !c.http_only {
                missing.push("HttpOnly");
            }
            if endpoint.url.starts_with("https://") && !c.secure {
                missing.push("Secure");
            }
            if c.same_site.is_none() {
                missing.push("SameSite");
            }
            if missing.is_empty() {
                continue;
            }
            out.push(finding(
                ctx,
                endpoint,
                "cookie_flags",
                &format!("Cookie '{}' missing flags", c.name),
                format!(
                    "Set-Cookie for '{}' is missing: {}.",
                    c.name,
                    missing.join(", ")
                ),
                Severity::Low,
                Confidence::Confirmed,
                Some("CWE-614"),
                Some("A05:2021 Security Misconfiguration"),
                format!("cookie={} missing={}", c.name, missing.join("/")),
            ));
        }
        Ok(out)
    }
}

#[async_trait]
impl Detector for CorsPassive {
    fn id(&self) -> &'static str {
        "cors_passive"
    }
    fn name(&self) -> &'static str {
        "CORS configuration (passive)"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(page) = page_for(ctx, endpoint) else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        if let Some(acao) = page.header("access-control-allow-origin") {
            if acao.trim() == "*" {
                let creds = page
                    .header("access-control-allow-credentials")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let sev = if creds {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    ctx,
                    endpoint,
                    "cors_misconfig",
                    "CORS Access-Control-Allow-Origin is wildcard",
                    format!(
                        "The response reflected Access-Control-Allow-Origin: *{}.",
                        if creds {
                            " together with Access-Control-Allow-Credentials: true"
                        } else {
                            ""
                        }
                    ),
                    sev,
                    Confidence::Confirmed,
                    Some("CWE-942"),
                    Some("A05:2021 Security Misconfiguration"),
                    format!("ACAO=* credentials={creds}"),
                ));
            }
        }
        Ok(out)
    }
}

fn finding(
    _ctx: &DetectorContext<'_>,
    endpoint: &Endpoint,
    class: &str,
    title: &str,
    description: String,
    severity: Severity,
    confidence: Confidence,
    cwe: Option<&str>,
    owasp: Option<&str>,
    evidence: String,
) -> CandidateFinding {
    CandidateFinding {
        detector_id: class.to_string(),
        detector_name: title.to_string(),
        title: title.to_string(),
        description,
        severity,
        confidence,
        cwe: cwe.map(|s| s.to_string()),
        owasp: owasp.map(|s| s.to_string()),
        method: endpoint.method.clone(),
        endpoint: endpoint.normalized_path.clone(),
        parameter: None,
        evidence_summary: evidence,
        fingerprint: fingerprint(
            &endpoint.host,
            &endpoint.method,
            &endpoint.normalized_path,
            None,
            class,
        ),
        source_engine: "sherlock-core".into(),
    }
}
