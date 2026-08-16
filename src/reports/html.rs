use crate::core::types::Severity;
use crate::reports::ReportBundle;
use std::fs;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let mut cards = String::new();
    for (label, n, color) in [
        ("Critical", count(bundle, Severity::Critical), "#991b1b"),
        ("High", count(bundle, Severity::High), "#c45a28"),
        ("Medium", count(bundle, Severity::Medium), "#c99432"),
        ("Low", count(bundle, Severity::Low), "#2e8b57"),
        ("Info", count(bundle, Severity::Informational), "#468282"),
    ] {
        cards.push_str(&format!(
            r#"<div class="card" style="border-color:{color}"><div class="n">{n}</div><div>{label}</div></div>"#
        ));
    }
    let mut findings = String::new();
    for f in &bundle.findings {
        let evid = html_escape(&f.evidence_summary);
        findings.push_str(&format!(
            r#"<details class="finding"><summary><span class="sev {}">{}</span> {} — {}</summary>
<p>{}</p>
<p><strong>Affected endpoints:</strong></p>
<ul>{}</ul>
<p><strong>CWE:</strong> {} &nbsp; <strong>Confidence:</strong> {}</p>
<pre>{}</pre>
<p><strong>Remediation:</strong> {}</p>
</details>"#,
            f.severity.as_str(),
            f.severity.label(),
            f.id,
            html_escape(&f.title),
            html_escape(&f.description),
            {
                let (sample, remaining) = f.sample_affected_endpoints(8);
                let mut items: Vec<String> = sample
                    .iter()
                    .map(|e| format!("<li><code>{}</code></li>", html_escape(e)))
                    .collect();
                if remaining > 0 {
                    items.push(format!(
                        "<li><em>…and {remaining} more (full list in JSON report / Evidence Vault)</em></li>"
                    ));
                }
                items.join("")
            },
            html_escape(f.cwe.as_deref().unwrap_or("n/a")),
            f.confidence.label(),
            evid,
            html_escape(&f.remediation),
        ));
    }
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Sherlock Homes — {case}</title>
<style>
body{{margin:0;font-family:Georgia,serif;background:#1b1b1b;color:#f5f0e6}}
header{{background:#111;border-bottom:3px solid #c9a227;padding:2rem}}
h1{{color:#c9a227;margin:0;letter-spacing:.12em}}
.sub{{color:#8a8680}}
main{{max-width:960px;margin:2rem auto;padding:0 1rem}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}}
.card{{border:2px solid;padding:1rem 1.4rem;min-width:6rem;text-align:center}}
.card .n{{font-size:1.8rem;color:#c9a227}}
.finding{{background:#242424;margin:1rem 0;padding:1rem;border-left:4px solid #468282}}
.sev{{padding:.1rem .4rem;margin-right:.4rem}}
.sev.critical,.sev.high{{background:#991b1b}}
.sev.medium{{background:#c45a28}}
.sev.low{{background:#2e8b57}}
pre{{background:#111;padding:1rem;overflow:auto;color:#dcd6c8}}
@media print{{body{{background:#fff;color:#111}} header{{border-bottom-color:#c9a227}}}}
</style></head>
<body>
<header>
<h1>SHERLOCK HOMES</h1>
<div class="sub">Cyber Investigation Report</div>
<p>Case: {case}<br>Target: {target}<br>Generated: {gen}<br>Mode: {mode}</p>
</header>
<main>
<h2>Executive Summary</h2>
<p>{count} evidence-backed finding(s). This report does not claim complete vulnerability coverage.</p>
<div class="cards">{cards}</div>
<h2>Findings</h2>
{findings}
<p class="sub">Every request leaves a clue.</p>
</main></body></html>"#,
        case = html_escape(&bundle.case_id),
        target = html_escape(&bundle.target),
        gen = html_escape(&bundle.generated),
        mode = html_escape(&bundle.mode),
        count = bundle.findings.len(),
        cards = cards,
        findings = findings,
    );
    fs::write(path, html)?;
    Ok(())
}

fn count(b: &ReportBundle, s: Severity) -> usize {
    b.findings.iter().filter(|f| f.severity == s).count()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
