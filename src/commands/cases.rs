use crate::core::config::AppConfig;
use crate::core::scanner::{run_scan, ScanOptions};
use crate::database::Database;
use crate::ui::Renderer;
use tokio_util::sync::CancellationToken;

pub fn list(db: &Database, json: bool) -> crate::Result<()> {
    let cases = db.list_cases()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cases)?);
        return Ok(());
    }
    if cases.is_empty() {
        println!("No case files in the Evidence Vault.");
        return Ok(());
    }
    println!("CASE ID              STATUS     MODE      TARGET");
    for c in cases {
        println!(
            "{:<20} {:<10} {:<9} {}",
            c.id, c.status, c.mode, c.target_url
        );
    }
    Ok(())
}

pub fn show(db: &Database, id: &str) -> crate::Result<()> {
    let c = db
        .get_case(id)?
        .ok_or_else(|| crate::SherlockError::CaseNotFound(id.into()))?;
    println!("Case: {}", c.id);
    println!("Status: {}", c.status);
    println!("Target: {}", c.target_url);
    println!("Mode: {}", c.mode);
    println!("Opened: {}", c.created_at);
    println!("Updated: {}", c.updated_at);
    Ok(())
}

pub fn clues(db: &Database, id: &str) -> crate::Result<()> {
    let eps = db.list_endpoints(id)?;
    if eps.is_empty() {
        println!("No clues (endpoints) recorded for {id}.");
        return Ok(());
    }
    for e in eps {
        println!("{} {}", e.method, e.normalized_path);
        for p in e.parameters {
            println!("    {} ({})", p.name, p.location.as_str());
        }
    }
    Ok(())
}

pub async fn resume(
    db: &Database,
    cfg: &AppConfig,
    case_id: &str,
    renderer: &mut Renderer,
    cancel: CancellationToken,
) -> crate::Result<()> {
    let c = db
        .get_case(case_id)?
        .ok_or_else(|| crate::SherlockError::CaseNotFound(case_id.into()))?;
    let args = crate::cli::ScanArgs {
        target: c.target_url,
        mode: None,
        depth: None,
        rate: None,
        concurrency: None,
        timeout: None,
        allow: vec![],
        exclude: vec![],
        auth: None,
        i_authorize_full: false,
        resume: Some(case_id.into()),
    };
    let opts = ScanOptions::from_args(&args, cfg);
    run_scan(db, cfg, opts, renderer, cancel).await?;
    Ok(())
}
