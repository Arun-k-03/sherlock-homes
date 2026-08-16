use crate::database::Database;
use crate::reports::ReportBundle;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn write(bundle: &ReportBundle, db: &Database, path: &Path) -> crate::Result<()> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "{}",
        serde_json::json!({"event":"case_opened","case_id": bundle.case_id, "target": bundle.target})
    )?;
    for ep in db.list_endpoints(&bundle.case_id)? {
        writeln!(
            f,
            "{}",
            serde_json::json!({"event":"endpoint","method": ep.method, "path": ep.normalized_path})
        )?;
    }
    for finding in &bundle.findings {
        writeln!(
            f,
            "{}",
            serde_json::json!({
                "event": "finding",
                "id": finding.id,
                "display_id": finding.display_id,
                "internal_id": finding.internal_id,
                "severity": finding.severity.as_str(),
                "type": finding.detector,
                "title": finding.title,
                "affected_endpoints": finding.affected_endpoints,
            })
        )?;
    }
    writeln!(
        f,
        "{}",
        serde_json::json!({"event":"case_closed","case_id": bundle.case_id})
    )?;
    Ok(())
}
