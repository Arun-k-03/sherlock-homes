use crate::database::Database;

pub fn show(db: &Database, finding_id: &str) -> crate::Result<()> {
    let f = db
        .get_finding(finding_id)?
        .ok_or_else(|| crate::SherlockError::FindingNotFound(finding_id.into()))?;
    println!("Evidence for {}", f.id);
    println!("Finding: {}", f.title);
    let labels = f.affected_endpoint_labels();
    println!("Affected endpoints: {}", labels.len());
    let (sample, remaining) = f.sample_affected_endpoints(8);
    for ep in sample {
        println!("  {ep}");
    }
    if remaining > 0 {
        println!("  …and {remaining} more (full list retained in Evidence Vault / JSON report)");
    }
    println!("Summary: {}", f.evidence_summary);
    for e in db.list_evidence_for_finding(finding_id)? {
        println!("\n{} [{}]", e.id, e.kind);
        if !e.notes.is_empty() {
            println!("{}", e.notes);
        }
        if !e.request_redacted.is_empty() {
            println!("Request:\n{}", e.request_redacted);
        }
        if !e.response_redacted.is_empty() {
            println!("Response:\n{}", e.response_redacted);
        }
    }
    Ok(())
}
