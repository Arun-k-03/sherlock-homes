use crate::core::types::Severity;
use crate::reports::ReportBundle;
use printpdf::*;
use std::fs;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let mut doc = PdfDocument::new("Sherlock Homes Investigation Report");
    let mut pages = Vec::new();

    // Title page
    let mut ops = Vec::new();
    fill_title(&mut ops, bundle);
    pages.push(a4_page(ops));

    // Summary page
    let mut ops = Vec::new();
    fill_summary(&mut ops, bundle);
    pages.push(a4_page(ops));

    // One page per finding
    for (i, finding) in bundle.findings.iter().enumerate() {
        let mut ops = Vec::new();
        fill_finding(&mut ops, finding, i + 1);
        pages.push(a4_page(ops));
    }

    // Appendix
    let mut ops = Vec::new();

    text(
        &mut ops,
        BuiltinFont::HelveticaBold,
        14.0,
        Mm(20.0),
        Mm(270.0),
        "10. Technical Appendix",
    );

    text(
        &mut ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(255.0),
        "Sherlock Homes records evidence in the local Evidence Vault (SQLite).",
    );

    text(
        &mut ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(248.0),
        "Automated scanning cannot guarantee 100% vulnerability detection.",
    );

    text(
        &mut ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(241.0),
        "Destructive testing, credential attacks, and DoS are out of scope for default SAFE mode.",
    );

    pages.push(a4_page(ops));

    doc.with_pages(pages);

    let mut warnings = Vec::new();
    let pdf_bytes = doc.save(&PdfSaveOptions::default(), &mut warnings);

    fs::write(path, pdf_bytes)?;

    Ok(())
}

fn a4_page(ops: Vec<Op>) -> PdfPage {
    PdfPage::new(Mm(210.0), Mm(297.0), ops)
}

fn fill_title(ops: &mut Vec<Op>, b: &ReportBundle) {
    text(
        ops,
        BuiltinFont::HelveticaBold,
        22.0,
        Mm(20.0),
        Mm(275.0),
        "SHERLOCK HOMES",
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        12.0,
        Mm(20.0),
        Mm(262.0),
        "Cyber Investigation Report",
    );

    text(
        ops,
        BuiltinFont::HelveticaBold,
        12.0,
        Mm(20.0),
        Mm(220.0),
        &format!("Case: {}", b.case_id),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        11.0,
        Mm(20.0),
        Mm(208.0),
        &format!("Target: {}", trunc(&b.target, 80)),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        11.0,
        Mm(20.0),
        Mm(196.0),
        &format!("Generated: {}", b.generated),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        11.0,
        Mm(20.0),
        Mm(184.0),
        &format!("Mode: {}", b.mode),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(40.0),
        "EVERY REQUEST LEAVES A CLUE.",
    );
}

fn fill_summary(ops: &mut Vec<Op>, b: &ReportBundle) {
    text(
        ops,
        BuiltinFont::HelveticaBold,
        16.0,
        Mm(20.0),
        Mm(275.0),
        "1. Executive Summary",
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(262.0),
        &format!(
            "{} evidence-backed finding(s) on {}. Coverage is not claimed to be complete.",
            b.findings.len(),
            trunc(&b.target, 50)
        ),
    );

    text(
        ops,
        BuiltinFont::HelveticaBold,
        14.0,
        Mm(20.0),
        Mm(240.0),
        "5. Severity Distribution",
    );

    let crit = count(b, Severity::Critical) as f32;
    let high = count(b, Severity::High) as f32;
    let med = count(b, Severity::Medium) as f32;
    let low = count(b, Severity::Low) as f32;
    let info = count(b, Severity::Informational) as f32;

    let max = crit.max(high).max(med).max(low).max(info).max(1.0);

    draw_bar(
        ops,
        Mm(20.0),
        Mm(210.0),
        crit / max,
        "Critical",
        crit as u32,
    );

    draw_bar(ops, Mm(20.0), Mm(195.0), high / max, "High", high as u32);

    draw_bar(ops, Mm(20.0), Mm(180.0), med / max, "Medium", med as u32);

    draw_bar(ops, Mm(20.0), Mm(165.0), low / max, "Low", low as u32);

    draw_bar(ops, Mm(20.0), Mm(150.0), info / max, "Info", info as u32);

    text(
        ops,
        BuiltinFont::HelveticaBold,
        12.0,
        Mm(20.0),
        Mm(125.0),
        "2-4. Scope / Methodology / Overview",
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(115.0),
        "Scope is the authorized target host plus --allow hosts.",
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(108.0),
        "Methodology: discover, map, observe, test (safe), verify, correlate, score.",
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(101.0),
        "Changed responses are treated as evidence, not automatic confirmation.",
    );
}

fn fill_finding(ops: &mut Vec<Op>, f: &crate::evidence::model::StoredFinding, n: usize) {
    text(
        ops,
        BuiltinFont::HelveticaBold,
        14.0,
        Mm(20.0),
        Mm(275.0),
        &format!("7. Finding {n}: {}", f.id),
    );

    text(
        ops,
        BuiltinFont::HelveticaBold,
        12.0,
        Mm(20.0),
        Mm(262.0),
        &trunc(&f.title, 90),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(248.0),
        &format!(
            "Severity: {}   Confidence: {}",
            f.severity.label(),
            f.confidence.label()
        ),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(240.0),
        &format!(
            "CWE: {}   OWASP: {}",
            f.cwe.as_deref().unwrap_or("n/a"),
            f.owasp.as_deref().unwrap_or("n/a")
        ),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(232.0),
        &format!(
            "CVSS: {}",
            f.cvss
                .as_deref()
                .unwrap_or("not computed (metrics incomplete)")
        ),
    );

    let affected = {
        let (sample, remaining) = f.sample_affected_endpoints(8);
        let mut value = sample.join(" | ");

        if remaining > 0 {
            value.push_str(&format!(" | +{remaining} more (see appendix / JSON)"));
        }

        value
    };

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(224.0),
        &format!("Affected endpoints: {affected}"),
    );

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        Mm(20.0),
        Mm(216.0),
        &format!("Parameter: {}", f.parameter.as_deref().unwrap_or("-")),
    );

    wrap(
        ops,
        BuiltinFont::Helvetica,
        Mm(20.0),
        Mm(200.0),
        &f.description,
    );

    text(
        ops,
        BuiltinFont::HelveticaBold,
        11.0,
        Mm(20.0),
        Mm(150.0),
        "Observed evidence",
    );

    wrap(
        ops,
        BuiltinFont::Helvetica,
        Mm(20.0),
        Mm(140.0),
        &f.evidence_summary,
    );

    text(
        ops,
        BuiltinFont::HelveticaBold,
        11.0,
        Mm(20.0),
        Mm(90.0),
        "Remediation",
    );

    wrap(
        ops,
        BuiltinFont::Helvetica,
        Mm(20.0),
        Mm(80.0),
        &f.remediation,
    );
}

fn wrap(ops: &mut Vec<Op>, font: BuiltinFont, x: Mm, mut y: Mm, text_in: &str) {
    let value = trunc(text_in, 900);

    let mut line = String::new();
    let mut count = 0usize;

    for ch in value.chars() {
        if ch == '\n' || count >= 90 {
            if !line.is_empty() {
                text(ops, font, 9.0, x, y, &line);
                y = Mm(y.0 - 5.0);
            }

            if y.0 < 20.0 {
                return;
            }

            line.clear();
            count = 0;

            if ch == '\n' {
                continue;
            }
        }

        line.push(ch);
        count += 1;
    }

    if !line.is_empty() && y.0 >= 20.0 {
        text(ops, font, 9.0, x, y, &line);
    }
}

fn draw_bar(ops: &mut Vec<Op>, x: Mm, y: Mm, frac: f32, label: &str, n: u32) {
    let filled = if n == 0 {
        0
    } else {
        ((frac * 24.0) as usize).clamp(1, 24)
    };

    let bar = "#".repeat(filled);

    text(
        ops,
        BuiltinFont::Helvetica,
        10.0,
        x,
        y,
        &format!("{label:<10} {bar} ({n})"),
    );
}

fn text(ops: &mut Vec<Op>, font: BuiltinFont, size: f32, x: Mm, y: Mm, value: &str) {
    ops.push(Op::StartTextSection);

    ops.push(Op::SetTextCursor {
        pos: Point::new(x, y),
    });

    ops.push(Op::SetFont {
        font: PdfFontHandle::Builtin(font),
        size: Pt(size),
    });

    ops.push(Op::ShowText {
        items: vec![TextItem::Text(value.to_string())],
    });

    ops.push(Op::EndTextSection);
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn count(b: &ReportBundle, s: Severity) -> usize {
    b.findings.iter().filter(|f| f.severity == s).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Confidence;
    use crate::evidence::model::StoredFinding;

    #[test]
    fn writes_pdf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pdf");

        let bundle = ReportBundle {
            schema: "t",
            case_id: "SH-260814-TEST".into(),
            target: "https://example.test".into(),
            generated: "now".into(),
            mode: "safe".into(),
            findings: vec![StoredFinding {
                id: "SH-260814-TEST/F-0001".into(),
                internal_id: "11111111-1111-1111-1111-111111111111".into(),
                display_id: "F-0001".into(),
                case_id: "SH-260814-TEST".into(),
                title: "Missing CSP".into(),
                severity: Severity::Low,
                confidence: Confidence::Confirmed,
                cwe: Some("CWE-693".into()),
                owasp: None,
                cvss: None,
                method: "GET".into(),
                endpoint: "/".into(),
                parameter: None,
                detector: "missing_csp".into(),
                source_engine: "sherlock-core".into(),
                description: "no csp".into(),
                evidence_summary: "header absent".into(),
                remediation: "add csp".into(),
                fingerprint: "fp".into(),
                status: "confirmed".into(),
                host: "example.test".into(),
                affected_endpoints: vec!["GET /".into()],
            }],
        };

        write(&bundle, &path).unwrap();

        assert!(path.exists());
        assert!(path.metadata().unwrap().len() > 100);
    }
}
