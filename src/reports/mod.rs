pub mod csv;
pub mod html;
pub mod json;
pub mod jsonl;
pub mod markdown;
pub mod pdf;
pub mod sarif;

use crate::database::Database;
use crate::evidence::model::StoredFinding;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Pdf,
    Html,
    Json,
    Jsonl,
    Sarif,
    Markdown,
    Csv,
}

impl ReportFormat {
    pub fn parse_list(s: &str) -> crate::Result<Vec<Self>> {
        let mut out = Vec::new();
        for p in s.split(',') {
            let t = p.trim();
            if t.is_empty() {
                continue;
            }
            let fmt = match t.to_ascii_lowercase().as_str() {
                "pdf" => Self::Pdf,
                "html" => Self::Html,
                "json" => Self::Json,
                "jsonl" => Self::Jsonl,
                "sarif" => Self::Sarif,
                "md" | "markdown" => Self::Markdown,
                "csv" => Self::Csv,
                other => {
                    return Err(crate::SherlockError::Report(format!(
                        "unsupported report format '{other}'. Supported: pdf,html,json,jsonl,sarif,markdown,csv"
                    )));
                }
            };
            if !out.contains(&fmt) {
                out.push(fmt);
            }
        }
        Ok(out)
    }

    pub fn ext(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Sarif => "sarif",
            Self::Markdown => "md",
            Self::Csv => "csv",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pdf => "PDF",
            Self::Html => "HTML",
            Self::Json => "JSON",
            Self::Jsonl => "JSONL",
            Self::Sarif => "SARIF",
            Self::Markdown => "MARKDOWN",
            Self::Csv => "CSV",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReportBundle {
    pub schema: &'static str,
    pub case_id: String,
    pub target: String,
    pub generated: String,
    pub mode: String,
    pub findings: Vec<StoredFinding>,
}

pub fn build_bundle(db: &Database, case_id: &str) -> crate::Result<ReportBundle> {
    let case = db
        .get_case(case_id)?
        .ok_or_else(|| crate::SherlockError::CaseNotFound(case_id.into()))?;
    Ok(ReportBundle {
        schema: "sherlock-homes.report.v1",
        case_id: case.id,
        target: case.target_url,
        generated: chrono::Utc::now().to_rfc3339(),
        mode: case.mode,
        findings: db.list_findings(case_id)?,
    })
}

pub fn write_reports(
    db: &Database,
    case_id: &str,
    formats: &[ReportFormat],
    output: &Path,
) -> crate::Result<Vec<(ReportFormat, PathBuf)>> {
    std::fs::create_dir_all(output)?;
    let bundle = build_bundle(db, case_id)?;
    let mut written = Vec::new();
    for fmt in formats {
        let path = output.join(format!("{case_id}-report.{}", fmt.ext()));
        match fmt {
            ReportFormat::Json => json::write(&bundle, &path)?,
            ReportFormat::Jsonl => jsonl::write(&bundle, db, &path)?,
            ReportFormat::Html => html::write(&bundle, &path)?,
            ReportFormat::Markdown => markdown::write(&bundle, &path)?,
            ReportFormat::Csv => csv::write(&bundle, &path)?,
            ReportFormat::Sarif => sarif::write(&bundle, &path)?,
            ReportFormat::Pdf => pdf::write(&bundle, &path)?,
        }
        db.record_report(case_id, fmt.ext(), &path.display().to_string())?;
        written.push((*fmt, path));
    }
    Ok(written)
}
