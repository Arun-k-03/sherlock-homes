use crate::core::types::{CandidateFinding, Confidence, Endpoint, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(InfoDisclosure),
        Box::new(VerboseErrors),
        Box::new(SourceMaps),
        Box::new(Secrets),
        Box::new(ExposedFiles),
    ]
}

struct InfoDisclosure;
struct VerboseErrors;
struct SourceMaps;
struct Secrets;
struct ExposedFiles;

static STACK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(Traceback \(most recent call last\)|at [\w$.]+\(.*\.js:\d+|System\.NullReferenceException|org\.springframework|django\.(core|http)|Warning:.*on line \d+)").expect("re")
});

fn page<'a>(
    ctx: &'a DetectorContext<'a>,
    ep: &Endpoint,
) -> Option<&'a crate::network::response::RecordedResponse> {
    ctx.pages.iter().find(|p| {
        url::Url::parse(&p.final_url)
            .ok()
            .map(|u| crate::discovery::normalize_path(u.path()) == ep.normalized_path)
            .unwrap_or(false)
    })
}

#[async_trait]
impl Detector for InfoDisclosure {
    fn id(&self) -> &'static str {
        "info_disclosure"
    }
    fn name(&self) -> &'static str {
        "Information disclosure"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(p) = page(ctx, endpoint) else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        if let Some(server) = p.header("server") {
            if !server.is_empty() {
                out.push(cf(
                    endpoint,
                    "server_banner",
                    "Server banner disclosure",
                    format!("The Server header reveals '{server}'."),
                    Severity::Informational,
                    format!("Server: {server}"),
                    Some("CWE-200"),
                ));
            }
        }
        if let Some(pb) = p.header("x-powered-by") {
            out.push(cf(
                endpoint,
                "server_banner",
                "X-Powered-By disclosure",
                format!("X-Powered-By reveals '{pb}'."),
                Severity::Low,
                format!("X-Powered-By: {pb}"),
                Some("CWE-200"),
            ));
        }
        Ok(out)
    }
}

#[async_trait]
impl Detector for VerboseErrors {
    fn id(&self) -> &'static str {
        "verbose_errors"
    }
    fn name(&self) -> &'static str {
        "Verbose errors"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(p) = page(ctx, endpoint) else {
            return Ok(vec![]);
        };
        if p.is_binary_asset() {
            return Ok(vec![]);
        }
        let text = p.text();
        if STACK.is_match(text) {
            return Ok(vec![cf(
                endpoint,
                "verbose_error",
                "Verbose error / stack trace",
                "The response body contains a framework stack trace or verbose diagnostic error."
                    .into(),
                Severity::Low,
                "stack-trace signature matched in body".into(),
                Some("CWE-209"),
            )]);
        }
        Ok(vec![])
    }
}

#[async_trait]
impl Detector for SourceMaps {
    fn id(&self) -> &'static str {
        "source_maps"
    }
    fn name(&self) -> &'static str {
        "Source map exposure"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(p) = page(ctx, endpoint) else {
            return Ok(vec![]);
        };
        if p.is_binary_asset() {
            return Ok(vec![]);
        }
        let refs = crate::discovery::javascript::source_map_refs(p.text());
        if refs.is_empty() && !p.text().contains("sourceMappingURL") {
            return Ok(vec![]);
        }
        Ok(vec![cf(
            endpoint,
            "source_map",
            "JavaScript source map reference",
            format!("A sourceMappingURL was observed: {}", refs.join(", ")),
            Severity::Low,
            format!("sourceMappingURL={:?}", refs),
            Some("CWE-540"),
        )])
    }
}

#[async_trait]
impl Detector for Secrets {
    fn id(&self) -> &'static str {
        "secrets"
    }
    fn name(&self) -> &'static str {
        "Potential secret exposure"
    }
    fn supports(&self, _: &Endpoint) -> bool {
        true
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(p) = page(ctx, endpoint) else {
            return Ok(vec![]);
        };
        if p.is_binary_asset() {
            return Ok(vec![]);
        }
        Ok(crate::detectors::secrets::findings_for(endpoint, p.text()))
    }
}

#[async_trait]
impl Detector for ExposedFiles {
    fn id(&self) -> &'static str {
        "exposed_files"
    }
    fn name(&self) -> &'static str {
        "Exposed sensitive files"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        crate::discovery::crawler::sensitive_probe_paths()
            .iter()
            .any(|p| endpoint.normalized_path == *p || endpoint.url.contains(p))
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        let Some(p) = page(ctx, endpoint) else {
            return Ok(vec![]);
        };
        if p.status != 200 {
            return Ok(vec![]);
        }
        let path = endpoint.normalized_path.as_str();
        let interesting = matches!(
            path,
            "/.env"
                | "/.git/HEAD"
                | "/.git/config"
                | "/phpinfo.php"
                | "/web.config"
                | "/backup.zip"
        );
        if !interesting {
            return Ok(vec![]);
        }
        let body_ok = match path {
            "/.git/HEAD" => p.text().starts_with("ref:") || p.text().contains("refs/heads"),
            "/.env" => p.text().contains('=') && p.status == 200 && p.text().len() < 50_000,
            "/phpinfo.php" => p.text().to_ascii_lowercase().contains("phpinfo"),
            _ => p.status == 200 && p.body.len() > 8,
        };
        if !body_ok {
            return Ok(vec![]);
        }
        Ok(vec![cf(
            endpoint,
            "exposed_file",
            &format!("Sensitive file available: {path}"),
            format!(
                "GET {path} returned HTTP {} with content consistent with a sensitive artifact.",
                p.status
            ),
            Severity::High,
            format!("status={} hash={}", p.status, p.body_hash),
            Some("CWE-538"),
        )])
    }
}

fn cf(
    endpoint: &Endpoint,
    class: &str,
    title: &str,
    description: String,
    severity: Severity,
    evidence: String,
    cwe: Option<&str>,
) -> CandidateFinding {
    CandidateFinding {
        detector_id: class.into(),
        detector_name: title.into(),
        title: title.into(),
        description,
        severity,
        confidence: Confidence::Confirmed,
        cwe: cwe.map(|s| s.into()),
        owasp: Some("A01:2021 / A05:2021".into()),
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
        host: endpoint.host.clone(),
        ..Default::default()
    }
}
