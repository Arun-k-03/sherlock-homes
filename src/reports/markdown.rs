use crate::reports::ReportBundle;
use std::fs;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let mut md = String::new();
    md.push_str("# Sherlock Homes Investigation Report\n\n");
    md.push_str(&format!("**Case:** `{}`  \n", bundle.case_id));
    md.push_str(&format!("**Target:** {}  \n", bundle.target));
    md.push_str(&format!("**Generated:** {}  \n", bundle.generated));
    md.push_str(&format!("**Mode:** {}  \n\n", bundle.mode));
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!(
        "{} finding(s) recorded. Automated scanning cannot guarantee complete coverage.\n\n",
        bundle.findings.len()
    ));
    md.push_str("## Findings\n\n");
    for f in &bundle.findings {
        md.push_str(&format!("### {} — {}\n\n", f.id, f.title));
        md.push_str(&format!(
            "- **Severity:** {}  \n- **Confidence:** {}  \n- **CWE:** {}  \n\n",
            f.severity.label(),
            f.confidence.label(),
            f.cwe.as_deref().unwrap_or("n/a")
        ));
        md.push_str("**Affected endpoints:**\n\n");
        let (sample, remaining) = f.sample_affected_endpoints(8);
        for ep in &sample {
            md.push_str(&format!("- `{ep}`\n"));
        }
        if remaining > 0 {
            md.push_str(&format!(
                "- _…and {remaining} more (full list in JSON report / Evidence Vault)_\n"
            ));
        }
        md.push('\n');
        md.push_str(&format!("{}\n\n", f.description));
        md.push_str("**Evidence:**\n\n```\n");
        md.push_str(&f.evidence_summary);
        md.push_str("\n```\n\n**Remediation:** ");
        md.push_str(&f.remediation);
        md.push_str("\n\n");
    }
    fs::write(path, md)?;
    Ok(())
}
