use crate::reports::ReportBundle;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let mut w =
        csv::Writer::from_path(path).map_err(|e| crate::SherlockError::Report(e.to_string()))?;
    w.write_record([
        "Case ID",
        "Finding ID",
        "Severity",
        "Confidence",
        "Title",
        "Host",
        "Method",
        "Endpoint",
        "Affected Endpoints",
        "Parameter",
        "CWE",
        "CVSS",
        "Detector",
        "Status",
    ])
    .map_err(|e| crate::SherlockError::Report(e.to_string()))?;
    for f in &bundle.findings {
        w.write_record([
            f.case_id.as_str(),
            f.id.as_str(),
            f.severity.as_str(),
            f.confidence.as_str(),
            f.title.as_str(),
            f.host.as_str(),
            f.method.as_str(),
            f.endpoint.as_str(),
            &f.affected_endpoints.join("; "),
            f.parameter.as_deref().unwrap_or(""),
            f.cwe.as_deref().unwrap_or(""),
            f.cvss.as_deref().unwrap_or(""),
            f.detector.as_str(),
            f.status.as_str(),
        ])
        .map_err(|e| crate::SherlockError::Report(e.to_string()))?;
    }
    w.flush()?;
    Ok(())
}
