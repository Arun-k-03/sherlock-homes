use sherlock_homes::core::types::{CandidateFinding, Confidence, Severity};
use sherlock_homes::correlation::dedup;
use sherlock_homes::database::Database;
use sherlock_homes::ids::CaseId;
use sherlock_homes::reports::{write_reports, ReportFormat};

fn csp(path: &str) -> CandidateFinding {
    CandidateFinding {
        detector_id: "missing_csp".into(),
        detector_name: "CSP".into(),
        title: "Missing Content-Security-Policy".into(),
        description: "The Content-Security-Policy header is absent.".into(),
        severity: Severity::Low,
        confidence: Confidence::Confirmed,
        cwe: Some("CWE-693".into()),
        method: "GET".into(),
        endpoint: path.into(),
        evidence_summary: "Content-Security-Policy absent".into(),
        fingerprint: format!("example.com|GET|{path}|-|missing_csp"),
        source_engine: "sherlock-core".into(),
        host: "example.com".into(),
        ..Default::default()
    }
}

fn banner(path: &str, n: usize) -> CandidateFinding {
    CandidateFinding {
        detector_id: "server_banner".into(),
        detector_name: "Server banner".into(),
        title: "Server banner disclosure".into(),
        description: "The Server header reveals 'nginx/1.24'.".into(),
        severity: Severity::Informational,
        confidence: Confidence::Confirmed,
        method: "GET".into(),
        endpoint: path.into(),
        evidence_summary: format!("Server: nginx/1.24 [obs {n}]"),
        fingerprint: format!("example.com|GET|{path}|-|server_banner"),
        source_engine: "sherlock-core".into(),
        host: "example.com".into(),
        ..Default::default()
    }
}

#[test]
fn two_cases_can_share_display_id_f0001() {
    let db = Database::open_in_memory().unwrap();
    let a = CaseId("SH-260814-AAAA".into());
    let b = CaseId("SH-260814-BBBB".into());
    db.create_case(&a, "https://a.example", "safe").unwrap();
    db.create_case(&b, "https://b.example", "safe").unwrap();
    let fa = db.persist_final_finding(&a.0, &csp("/")).unwrap();
    let fb = db.persist_final_finding(&b.0, &csp("/")).unwrap();
    assert_eq!(fa.display_id, "F-0001");
    assert_eq!(fb.display_id, "F-0001");
    assert_ne!(fa.internal_id, fb.internal_id);
    assert_eq!(fa.id, "SH-260814-AAAA/F-0001");
    assert_eq!(fb.id, "SH-260814-BBBB/F-0001");
}

#[test]
fn no_unique_constraint_across_cases() {
    let db = Database::open_in_memory().unwrap();
    for suffix in ["C001", "C002", "C003"] {
        let id = CaseId(format!("SH-260814-{suffix}"));
        db.create_case(&id, "https://example.com", "safe").unwrap();
        db.persist_final_finding(&id.0, &csp("/")).unwrap();
        db.persist_final_finding(&id.0, &csp("/login")).unwrap();
    }
    assert_eq!(
        db.list_findings("SH-260814-C001").unwrap()[0].display_id,
        "F-0001"
    );
    assert_eq!(
        db.list_findings("SH-260814-C002").unwrap()[0].display_id,
        "F-0001"
    );
}

#[test]
fn reprocessing_same_candidate_does_not_duplicate() {
    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-DUP1".into());
    db.create_case(&id, "https://example.com", "safe").unwrap();
    let first = db.persist_final_finding(&id.0, &csp("/search")).unwrap();
    let second = db.persist_final_finding(&id.0, &csp("/search")).unwrap();
    assert_eq!(first.internal_id, second.internal_id);
    assert_eq!(db.list_findings(&id.0).unwrap().len(), 1);
}

#[test]
fn ten_server_headers_one_host_finding() {
    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-BANR".into());
    db.create_case(&id, "https://example.com", "safe").unwrap();
    let paths = ["/", "/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i"];
    for (i, path) in paths.iter().enumerate() {
        let stored = db.persist_final_finding(&id.0, &banner(path, i)).unwrap();
        db.add_evidence(
            &id.0,
            &stored.internal_id,
            "http",
            "",
            "",
            &format!("GET {path} Server: nginx/1.24"),
        )
        .unwrap();
    }
    let findings = db.list_findings(&id.0).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector, "server_banner");
    assert_eq!(findings[0].affected_endpoints.len(), 10);
    let ev = db.list_evidence_for_finding(&findings[0].id).unwrap();
    assert_eq!(ev.len(), 10);
}

#[test]
fn missing_csp_correlates_endpoints() {
    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-CSP1".into());
    db.create_case(&id, "https://example.com", "safe").unwrap();
    let merged = dedup::merge(vec![
        csp("/"),
        csp("/login.html"),
        csp("/search"),
        csp("/api/profile"),
    ]);
    assert_eq!(merged.len(), 1);
    let stored = db.persist_final_finding(&id.0, &merged[0]).unwrap();
    assert_eq!(stored.affected_endpoints.len(), 4);
    assert!(stored
        .affected_endpoints
        .iter()
        .any(|e| e.contains("/login.html")));
    assert!(stored
        .affected_endpoints
        .iter()
        .any(|e| e.contains("/api/profile")));
}

#[test]
fn duplicate_observations_keep_evidence() {
    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-EVD1".into());
    db.create_case(&id, "https://example.com", "safe").unwrap();
    let a = db.persist_final_finding(&id.0, &csp("/")).unwrap();
    db.add_evidence(&id.0, &a.internal_id, "http", "GET /", "", "obs-1")
        .unwrap();
    let b = db.persist_final_finding(&id.0, &csp("/")).unwrap();
    db.add_evidence(&id.0, &b.internal_id, "http", "GET /", "", "obs-2")
        .unwrap();
    assert_eq!(a.internal_id, b.internal_id);
    let ev = db.list_evidence_for_finding(&a.id).unwrap();
    assert_eq!(ev.len(), 2);
    let notes: Vec<_> = ev.iter().map(|e| e.notes.as_str()).collect();
    assert!(notes.contains(&"obs-1"));
    assert!(notes.contains(&"obs-2"));
}

#[test]
fn report_lists_every_affected_path() {
    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-RPT1".into());
    db.create_case(&id, "https://example.com", "safe").unwrap();
    let merged = dedup::merge(vec![csp("/"), csp("/login.html"), csp("/search")]);
    db.persist_final_finding(&id.0, &merged[0]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let written = write_reports(
        &db,
        &id.0,
        &[
            ReportFormat::Markdown,
            ReportFormat::Html,
            ReportFormat::Csv,
        ],
        dir.path(),
    )
    .unwrap();
    for (_, path) in written {
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("/login.html"), "{path:?} missing /login.html");
        assert!(body.contains("/search"), "{path:?} missing /search");
        assert!(body.contains("GET /") || body.contains("`/`") || body.contains("/;"));
    }
}

#[test]
fn case_delete_and_lookup() {
    let db = Database::open_in_memory().unwrap();
    let keep = CaseId("SH-260814-KEEP".into());
    let drop = CaseId("SH-260814-DROP".into());
    db.create_case(&keep, "https://keep.example", "safe")
        .unwrap();
    db.create_case(&drop, "https://drop.example", "safe")
        .unwrap();
    let kept = db.persist_final_finding(&keep.0, &csp("/")).unwrap();
    db.persist_final_finding(&drop.0, &csp("/")).unwrap();
    assert!(db.delete_case(&drop.0).unwrap());
    assert!(db.get_case(&drop.0).unwrap().is_none());
    assert!(db.get_case(&keep.0).unwrap().is_some());
    let found = db.get_finding(&kept.id).unwrap().unwrap();
    assert_eq!(found.internal_id, kept.internal_id);
    assert_eq!(db.list_findings(&drop.0).unwrap().len(), 0);
    assert_eq!(db.list_findings(&keep.0).unwrap().len(), 1);
    assert!(db.get_finding("SH-260814-KEEP-F0001").unwrap().is_some());
}
