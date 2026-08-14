use crate::core::config::ScanMode;
use crate::core::types::{CandidateFinding, Confidence, Endpoint, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use async_trait::async_trait;
use std::collections::HashMap;
use url::Url;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(CorsActive)]
}

struct CorsActive;

#[async_trait]
impl Detector for CorsActive {
    fn id(&self) -> &'static str {
        "cors_active"
    }
    fn name(&self) -> &'static str {
        "CORS verification"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        if matches!(ctx.mode, ScanMode::Passive) {
            return Ok(vec![]);
        }
        let Ok(url) = Url::parse(&endpoint.url) else {
            return Ok(vec![]);
        };
        let mut headers = HashMap::new();
        headers.insert("Origin".into(), "https://sherlock-probe.invalid".into());
        let fetched = match ctx
            .http
            .execute(
                "GET",
                &url,
                Some(&headers),
                None,
                ctx.scope,
                ctx.rate,
                ctx.cancel,
            )
            .await
        {
            Ok(f) => f,
            Err(_) => return Ok(vec![]),
        };
        let acao = fetched.response.header("access-control-allow-origin");
        let Some(acao) = acao else {
            return Ok(vec![]);
        };
        if acao.contains("sherlock-probe.invalid") || acao.trim() == "*" {
            let creds = fetched
                .response
                .header("access-control-allow-credentials")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            return Ok(vec![CandidateFinding {
                detector_id: "cors_misconfig".into(),
                detector_name: "CORS reflects arbitrary origin".into(),
                title: "CORS reflects attacker-controlled Origin".into(),
                description: format!(
                    "A request with Origin https://sherlock-probe.invalid received Access-Control-Allow-Origin: {acao}."
                ),
                severity: if creds { Severity::High } else { Severity::Medium },
                confidence: Confidence::Confirmed,
                cwe: Some("CWE-942".into()),
                owasp: Some("A05:2021 Security Misconfiguration".into()),
                method: endpoint.method.clone(),
                endpoint: endpoint.normalized_path.clone(),
                parameter: None,
                evidence_summary: format!("ACAO={acao} credentials={creds}"),
                fingerprint: fingerprint(
                    &endpoint.host,
                    &endpoint.method,
                    &endpoint.normalized_path,
                    None,
                    "cors_misconfig",
                ),
                source_engine: "sherlock-core".into(),
            }]);
        }
        Ok(vec![])
    }
}
