use crate::core::types::Severity;
use crate::reports::ReportBundle;
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Sherlock Homes Investigation Report",
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| crate::SherlockError::Report(e.to_string()))?;
    let font_b = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| crate::SherlockError::Report(e.to_string()))?;

    let layer = doc.get_page(page1).get_layer(layer1);
    fill_title(&layer, &font_b, &font, bundle);

    let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Summary");
    let layer = doc.get_page(page2).get_layer(layer2);
    fill_summary(&layer, &font_b, &font, bundle);

    for (i, f) in bundle.findings.iter().enumerate() {
        let (p, l) = doc.add_page(Mm(210.0), Mm(297.0), format!("Finding {}", i + 1));
        let layer = doc.get_page(p).get_layer(l);
        fill_finding(&layer, &font_b, &font, f, i + 1);
    }

    let (pa, la) = doc.add_page(Mm(210.0), Mm(297.0), "Appendix");
    let layer = doc.get_page(pa).get_layer(la);
    text(
        &layer,
        &font_b,
        14.0,
        Mm(20.0),
        Mm(270.0),
        "10. Technical Appendix",
    );
    text(
        &layer,
        &font,
        10.0,
        Mm(20.0),
        Mm(255.0),
        "Sherlock Homes records evidence in the local Evidence Vault (SQLite).",
    );
    text(
        &layer,
        &font,
        10.0,
        Mm(20.0),
        Mm(248.0),
        "Automated scanning cannot guarantee 100% vulnerability detection.",
    );
    text(
        &layer,
        &font,
        10.0,
        Mm(20.0),
        Mm(241.0),
        "Destructive testing, credential attacks, and DoS are out of scope for default SAFE mode.",
    );

    doc.save(&mut BufWriter::new(File::create(path)?))
        .map_err(|e| crate::SherlockError::Report(e.to_string()))?;
    Ok(())
}

fn fill_title(
    layer: &PdfLayerReference,
    bold: &IndirectFontRef,
    font: &IndirectFontRef,
    b: &ReportBundle,
) {
    text(layer, bold, 22.0, Mm(20.0), Mm(275.0), "SHERLOCK HOMES");
    text(
        layer,
        font,
        12.0,
        Mm(20.0),
        Mm(262.0),
        "Cyber Investigation Report",
    );
    text(
        layer,
        bold,
        12.0,
        Mm(20.0),
        Mm(220.0),
        &format!("Case: {}", b.case_id),
    );
    text(
        layer,
        font,
        11.0,
        Mm(20.0),
        Mm(208.0),
        &format!("Target: {}", trunc(&b.target, 80)),
    );
    text(
        layer,
        font,
        11.0,
        Mm(20.0),
        Mm(196.0),
        &format!("Generated: {}", b.generated),
    );
    text(
        layer,
        font,
        11.0,
        Mm(20.0),
        Mm(184.0),
        &format!("Mode: {}", b.mode),
    );
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(40.0),
        "EVERY REQUEST LEAVES A CLUE.",
    );
}

fn fill_summary(
    layer: &PdfLayerReference,
    bold: &IndirectFontRef,
    font: &IndirectFontRef,
    b: &ReportBundle,
) {
    text(
        layer,
        bold,
        16.0,
        Mm(20.0),
        Mm(275.0),
        "1. Executive Summary",
    );
    text(
        layer,
        font,
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
        layer,
        bold,
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
        layer,
        font,
        Mm(20.0),
        Mm(210.0),
        crit / max,
        "Critical",
        crit as u32,
    );
    draw_bar(
        layer,
        font,
        Mm(20.0),
        Mm(195.0),
        high / max,
        "High",
        high as u32,
    );
    draw_bar(
        layer,
        font,
        Mm(20.0),
        Mm(180.0),
        med / max,
        "Medium",
        med as u32,
    );
    draw_bar(
        layer,
        font,
        Mm(20.0),
        Mm(165.0),
        low / max,
        "Low",
        low as u32,
    );
    draw_bar(
        layer,
        font,
        Mm(20.0),
        Mm(150.0),
        info / max,
        "Info",
        info as u32,
    );
    text(
        layer,
        bold,
        12.0,
        Mm(20.0),
        Mm(125.0),
        "2-4. Scope / Methodology / Overview",
    );
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(115.0),
        "Scope is the authorized target host plus --allow hosts.",
    );
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(108.0),
        "Methodology: discover, map, observe, test (safe), verify, correlate, score.",
    );
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(101.0),
        "Changed responses are treated as evidence, not automatic confirmation.",
    );
}

fn fill_finding(
    layer: &PdfLayerReference,
    bold: &IndirectFontRef,
    font: &IndirectFontRef,
    f: &crate::evidence::model::StoredFinding,
    n: usize,
) {
    text(
        layer,
        bold,
        14.0,
        Mm(20.0),
        Mm(275.0),
        &format!("7. Finding {n}: {}", f.id),
    );
    text(layer, bold, 12.0, Mm(20.0), Mm(262.0), &trunc(&f.title, 90));
    text(
        layer,
        font,
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
        layer,
        font,
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
        layer,
        font,
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
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(224.0),
        &format!("Affected endpoints: {}", {
            let (sample, remaining) = f.sample_affected_endpoints(8);
            let mut s = sample.join(" | ");
            if remaining > 0 {
                s.push_str(&format!(" | +{remaining} more (see appendix / JSON)"));
            }
            s
        }),
    );
    text(
        layer,
        font,
        10.0,
        Mm(20.0),
        Mm(216.0),
        &format!("Parameter: {}", f.parameter.as_deref().unwrap_or("-")),
    );
    wrap(layer, font, Mm(20.0), Mm(200.0), &f.description);
    text(layer, bold, 11.0, Mm(20.0), Mm(150.0), "Observed evidence");
    wrap(layer, font, Mm(20.0), Mm(140.0), &f.evidence_summary);
    text(layer, bold, 11.0, Mm(20.0), Mm(90.0), "Remediation");
    wrap(layer, font, Mm(20.0), Mm(80.0), &f.remediation);
}

fn wrap(layer: &PdfLayerReference, font: &IndirectFontRef, x: Mm, mut y: Mm, text_in: &str) {
    let t = trunc(text_in, 900);
    for chunk in t.as_bytes().chunks(90) {
        let line = String::from_utf8_lossy(chunk);
        text(layer, font, 9.0, x, y, &line);
        y = Mm(y.0 - 5.0);
        if y.0 < 20.0 {
            break;
        }
    }
}

fn draw_bar(
    layer: &PdfLayerReference,
    font: &IndirectFontRef,
    x: Mm,
    y: Mm,
    frac: f32,
    label: &str,
    n: u32,
) {
    let filled = ((frac * 24.0) as usize).clamp(1, 24);
    let bar = "#".repeat(filled);
    text(layer, font, 10.0, x, y, &format!("{label:<10} {bar} ({n})"));
}

fn text(layer: &PdfLayerReference, font: &IndirectFontRef, size: f32, x: Mm, y: Mm, s: &str) {
    layer.use_text(s, size, x, y, font);
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
        assert!(path.metadata().unwrap().len() > 100);
    }
}
