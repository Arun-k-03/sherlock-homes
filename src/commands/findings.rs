use crate::database::Database;

pub fn list(db: &Database, case_id: &str) -> crate::Result<()> {
    let findings = db.list_findings(case_id)?;
    if findings.is_empty() {
        println!("No findings for {case_id}.");
        return Ok(());
    }
    println!("ID         SEV        CONF               TITLE");
    for f in findings {
        println!(
            "{:<10} {:<10} {:<18} {}",
            f.id,
            f.severity.label(),
            f.confidence.label(),
            f.title
        );
    }
    Ok(())
}

pub fn suspects(db: &Database, case_id: &str) -> crate::Result<()> {
    let cands = db.list_candidates(case_id)?;
    if cands.is_empty() {
        println!("No suspects (candidates) for {case_id}.");
        return Ok(());
    }
    for c in cands {
        println!(
            "[{}] {} :: {} {}  ({})",
            c.severity.label(),
            c.title,
            c.method,
            c.endpoint,
            c.confidence.label()
        );
    }
    Ok(())
}

pub fn verdict(db: &Database, case_id: &str) -> crate::Result<()> {
    let c = db
        .get_case(case_id)?
        .ok_or_else(|| crate::SherlockError::CaseNotFound(case_id.into()))?;
    let findings = db.list_findings(case_id)?;
    let (crit, high, med, low, info) = crate::core::scanner::severity_counts(&findings);
    println!("VERDICT — {}", c.id);
    println!("Target: {}", c.target_url);
    println!("Status: {}", c.status);
    println!("CRITICAL {crit}  HIGH {high}  MEDIUM {med}  LOW {low}  INFO {info}");
    println!("Automated coverage is not 100%. Review evidence before acting.");
    Ok(())
}
