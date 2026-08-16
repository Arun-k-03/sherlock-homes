use crate::reports::ReportBundle;
use serde_json::json;
use std::fs;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let results: Vec<serde_json::Value> = bundle
        .findings
        .iter()
        .map(|f| {
            let endpoints = if f.affected_endpoints.is_empty() {
                vec![format!("{} {}", f.method, f.endpoint)]
            } else {
                f.affected_endpoints.clone()
            };
            let locations: Vec<serde_json::Value> = endpoints
                .iter()
                .map(|ep| {
                    let path = ep.split_whitespace().last().unwrap_or(ep);
                    json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": format!("{}{}", bundle.target.trim_end_matches('/'), path) },
                            "region": { "startLine": 1 }
                        }
                    })
                })
                .collect();
            json!({
                "ruleId": f.detector,
                "level": sarif_level(f.severity.as_str()),
                "message": { "text": f.title },
                "locations": locations,
                "properties": {
                    "caseId": f.case_id,
                    "findingId": f.id,
                    "confidence": f.confidence.as_str(),
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "parameter": f.parameter
                }
            })
        })
        .collect();
    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sherlock Homes",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Arun-k-03/sherlock-homes",
                    "rules": []
                }
            },
            "results": results
        }]
    });
    fs::write(path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

fn sarif_level(sev: &str) -> &'static str {
    match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}
