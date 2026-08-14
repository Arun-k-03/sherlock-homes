use crate::cli::ReportArgs;
use crate::core::config::AppConfig;
use crate::database::Database;
use crate::reports::{write_reports, ReportFormat};
use std::path::PathBuf;

pub fn run(db: &Database, cfg: &AppConfig, args: ReportArgs) -> crate::Result<()> {
    let formats = args
        .format
        .as_deref()
        .or_else(|| cfg.reports.default_formats.first().map(|s| s.as_str()))
        .unwrap_or("pdf,html,json");
    let parsed = ReportFormat::parse_list(formats);
    if parsed.is_empty() {
        return Err(crate::SherlockError::Report(
            "no valid formats (pdf,html,json,jsonl,sarif,markdown,csv)".into(),
        ));
    }
    let out = args.output.unwrap_or_else(|| PathBuf::from("./reports"));
    let written = write_reports(db, &args.case_id, &parsed, &out)?;
    for (fmt, path) in written {
        println!("[REPORT] {}", fmt.label());
        println!("{}", path.display());
    }
    Ok(())
}
