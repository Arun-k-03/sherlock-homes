//! Optional Nuclei adapter. Never a hard dependency.

use crate::core::error::{Result, SherlockError};
use crate::core::types::{CandidateFinding, Confidence, Severity};
use crate::detectors::fingerprint;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use url::Url;

pub async fn run_if_present(
    target: &str,
    cancel: &CancellationToken,
) -> Result<Vec<CandidateFinding>> {
    let Ok(bin) = which::which("nuclei") else {
        return Ok(vec![]);
    };
    if cancel.is_cancelled() {
        return Err(SherlockError::Cancelled);
    }
    let mut child = Command::new(bin)
        .args(["-u", target, "-jsonl", "-silent", "-nc"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| SherlockError::Engine {
            engine: "nuclei".into(),
            message: e.to_string(),
        })?;
    let stdout = child.stdout.take();
    let mut findings = Vec::new();
    if let Some(out) = stdout {
        let mut lines = BufReader::new(out).lines();
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            if let Some(c) = parse_line(&line, target) {
                                findings.push(c);
                            }
                        }
                        _ => break,
                    }
                }
                _ = cancel.cancelled() => {
                    let _ = child.start_kill();
                    return Err(SherlockError::Cancelled);
                }
            }
        }
    }
    let _ = child.wait().await;
    Ok(findings)
}

fn parse_line(line: &str, fallback_target: &str) -> Option<CandidateFinding> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let template = v.get("template-id")?.as_str()?.to_string();
    let name = v
        .pointer("/info/name")
        .and_then(|x| x.as_str())
        .unwrap_or(&template)
        .to_string();
    let sev = v
        .pointer("/info/severity")
        .and_then(|x| x.as_str())
        .unwrap_or("info");
    let matched = v
        .get("matched-at")
        .and_then(|x| x.as_str())
        .unwrap_or(fallback_target);
    let url = Url::parse(matched).ok()?;
    Some(CandidateFinding {
        detector_id: format!("nuclei:{template}"),
        detector_name: name.clone(),
        title: name,
        description: format!("Nuclei template '{template}' matched {matched}."),
        severity: map_sev(sev),
        confidence: Confidence::Likely,
        cwe: None,
        owasp: None,
        method: "GET".into(),
        endpoint: crate::discovery::normalize_path(url.path()),
        parameter: None,
        evidence_summary: crate::evidence::redact_text(line),
        fingerprint: fingerprint(
            url.host_str().unwrap_or(""),
            "GET",
            &crate::discovery::normalize_path(url.path()),
            None,
            &format!("nuclei:{template}"),
        ),
        source_engine: "nuclei".into(),
    })
}

fn map_sev(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nuclei_jsonl() {
        let line = r#"{"template-id":"missing-csp","info":{"name":"Missing CSP","severity":"low"},"matched-at":"https://example.com/"}"#;
        let c = parse_line(line, "https://example.com").unwrap();
        assert_eq!(c.source_engine, "nuclei");
        assert_eq!(c.severity, Severity::Low);
    }
}
