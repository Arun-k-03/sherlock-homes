use crate::database::Database;

pub fn show(db: &Database, finding_id: &str) -> crate::Result<()> {
    let f = db
        .get_finding(finding_id)?
        .ok_or_else(|| crate::SherlockError::FindingNotFound(finding_id.into()))?;
    println!("Evidence for {}", f.id);
    println!("Finding: {}", f.title);
    println!("Endpoint: {} {}", f.method, f.endpoint);
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
