use rusqlite::Connection;
use sherlock_homes::core::types::{CandidateFinding, Confidence, Severity};
use sherlock_homes::database::migrations::{
    applied_versions, apply, column_exists, inspect, latest_schema_version,
    legacy_findings_id_unique_survives, INIT_SQL,
};
use sherlock_homes::database::Database;
use sherlock_homes::ids::CaseId;

fn old_finding_row(id: &str, case_id: &str, title: &str, fingerprint: &str) -> String {
    format!(
        "INSERT INTO findings (
            id, case_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter,
            detector, source_engine, description, evidence_summary, remediation, fingerprint, status, created_at
         ) VALUES (
            '{id}', '{case_id}', '{title}', 'low', 'confirmed', 'CWE-693', NULL, NULL, 'GET', '/', NULL,
            'missing_csp', 'sherlock-core', 'legacy row', 'header absent', 'add csp', '{fingerprint}', 'confirmed',
            '2026-08-14T00:00:00+00:00'
         )"
    )
}

fn seed_old_schema(conn: &Connection) {
    conn.execute_batch(INIT_SQL).unwrap();
    conn.execute_batch(
        "INSERT INTO cases (id, created_at, updated_at, status, target_url, mode)
         VALUES
         ('SH-260814-AAAA', '2026-08-14T00:00:00+00:00', '2026-08-14T00:00:00+00:00', 'closed', 'https://a.example', 'safe'),
         ('SH-260814-BBBB', '2026-08-14T00:00:00+00:00', '2026-08-14T00:00:00+00:00', 'closed', 'https://b.example', 'safe');",
    )
    .unwrap();
    conn.execute_batch(&old_finding_row(
        "SH-F-0001",
        "SH-260814-AAAA",
        "Missing CSP",
        "a.example|GET|/|-|missing_csp",
    ))
    .unwrap();
    conn.execute_batch(&old_finding_row(
        "SH-F-0002",
        "SH-260814-AAAA",
        "Missing HSTS",
        "a.example|GET|/|-|missing_hsts",
    ))
    .unwrap();
    conn.execute_batch(&old_finding_row(
        "SH-F-0003",
        "SH-260814-BBBB",
        "Server banner disclosure",
        "b.example|GET|/|-|server_banner",
    ))
    .unwrap();
    conn.execute(
        "INSERT INTO evidence (id, finding_id, case_id, kind, notes, created_at)
         VALUES ('SH-EV-0001', 'SH-F-0001', 'SH-260814-AAAA', 'http', 'obs-a', '2026-08-14T00:00:00+00:00')",
        [],
    )
    .unwrap();
}

#[test]
fn upgrades_real_old_schema_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-vault.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        seed_old_schema(&conn);
        assert!(column_exists(&conn, "findings", "id").unwrap());
        assert!(!column_exists(&conn, "findings", "internal_id").unwrap());
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            tables, 0,
            "old database must not already have migration history"
        );
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
    }

    let db = Database::open(&path).unwrap();
    let report = db.migration_report().unwrap();
    assert!(report.applied.iter().any(|v| v == "002_finding_identity"));
    assert_eq!(report.schema_version, 2);
    assert_eq!(report.latest_version, latest_schema_version());
    assert!(report.findings_has_internal_id);
    assert!(!report.findings_has_legacy_id);
    assert!(report.ready);

    let findings = db.list_findings("SH-260814-AAAA").unwrap();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.display_id == "F-0001"));
    assert!(findings.iter().any(|f| f.display_id == "F-0002"));
    assert_eq!(
        findings
            .iter()
            .find(|f| f.display_id == "F-0001")
            .unwrap()
            .title,
        "Missing CSP"
    );

    let b = db.list_findings("SH-260814-BBBB").unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].display_id, "F-0003");
    assert_eq!(b[0].title, "Server banner disclosure");

    let ev = db
        .list_evidence_for_finding("SH-260814-AAAA/F-0001")
        .unwrap();
    assert_eq!(ev.len(), 1);
    assert!(ev[0].notes.contains("obs-a"));

    {
        let conn = Connection::open(&path).unwrap();
        assert!(!legacy_findings_id_unique_survives(&conn).unwrap());
        assert!(column_exists(&conn, "findings", "internal_id").unwrap());
        assert!(column_exists(&conn, "findings", "display_id").unwrap());
        assert!(column_exists(&conn, "findings", "fingerprint").unwrap());
        assert!(!column_exists(&conn, "findings", "id").unwrap());
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let lower = sql.to_ascii_lowercase();
        assert!(lower.contains("internal_id text primary key"));
        assert!(lower.contains("unique(case_id, display_id)"));
        assert!(!column_exists(&conn, "findings", "id").unwrap());
    }

    let c = CaseId("SH-260814-CCCC".into());
    let d = CaseId("SH-260814-DDDD".into());
    db.create_case(&c, "https://c.example", "safe").unwrap();
    db.create_case(&d, "https://d.example", "safe").unwrap();
    let cand = CandidateFinding {
        detector_id: "missing_csp".into(),
        title: "Missing Content-Security-Policy".into(),
        description: "absent".into(),
        severity: Severity::Low,
        confidence: Confidence::Confirmed,
        method: "GET".into(),
        endpoint: "/".into(),
        fingerprint: "c.example|GET|/|-|missing_csp".into(),
        source_engine: "sherlock-core".into(),
        host: "c.example".into(),
        ..Default::default()
    };
    let fc = db.persist_final_finding(&c.0, &cand).unwrap();
    let mut cand_d = cand.clone();
    cand_d.host = "d.example".into();
    cand_d.fingerprint = "d.example|GET|/|-|missing_csp".into();
    let fd = db.persist_final_finding(&d.0, &cand_d).unwrap();
    assert_eq!(fc.display_id, "F-0001");
    assert_eq!(fd.display_id, "F-0001");
    assert_ne!(fc.internal_id, fd.internal_id);

    db.persist_final_finding(&c.0, &cand).unwrap();
    assert_eq!(db.list_findings(&c.0).unwrap().len(), 1);

    {
        let conn = Connection::open(&path).unwrap();
        apply(&conn).unwrap();
        apply(&conn).unwrap();
        let versions = applied_versions(&conn).unwrap();
        assert_eq!(
            versions
                .iter()
                .filter(|v| *v == "002_finding_identity")
                .count(),
            1
        );
        assert_eq!(versions.len(), 2);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 5);
        let report = inspect(&conn).unwrap();
        assert!(report.ready);
    }
}

#[test]
fn upgrades_when_001_already_recorded() {
    let conn = Connection::open_in_memory().unwrap();
    seed_old_schema(&conn);
    conn.execute_batch(
        "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
         INSERT INTO schema_migrations (version, applied_at) VALUES ('001_init', datetime('now'));",
    )
    .unwrap();
    apply(&conn).unwrap();
    assert!(column_exists(&conn, "findings", "internal_id").unwrap());
    assert!(!column_exists(&conn, "findings", "id").unwrap());
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3);
}

#[test]
fn reruns_002_if_history_lied_about_schema() {
    let conn = Connection::open_in_memory().unwrap();
    seed_old_schema(&conn);
    conn.execute_batch(
        "CREATE TABLE schema_migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            applied_at TEXT NOT NULL
         );
         INSERT INTO schema_migrations (version, name, applied_at)
         VALUES ('001_init', 'init', datetime('now')),
                ('002_finding_identity', 'finding_identity', datetime('now'));",
    )
    .unwrap();
    assert!(column_exists(&conn, "findings", "id").unwrap());
    apply(&conn).unwrap();
    assert!(column_exists(&conn, "findings", "internal_id").unwrap());
    assert!(!column_exists(&conn, "findings", "id").unwrap());
}

#[test]
fn fresh_database_applies_001_and_002() {
    let db = Database::open_in_memory().unwrap();
    let report = db.migration_report().unwrap();
    assert_eq!(report.applied, vec!["001_init", "002_finding_identity"]);
    assert_eq!(report.schema_version, 2);
    assert!(report.ready);
    assert!(!report.findings_has_legacy_id);
}

#[test]
fn persist_two_cases_does_not_hit_legacy_id_unique() {
    let db = Database::open_in_memory().unwrap();
    let a = CaseId("SH-260814-X001".into());
    let b = CaseId("SH-260814-X002".into());
    db.create_case(&a, "https://a.example", "safe").unwrap();
    db.create_case(&b, "https://b.example", "safe").unwrap();
    let cand = |host: &str| CandidateFinding {
        detector_id: "missing_csp".into(),
        title: "Missing Content-Security-Policy".into(),
        description: "absent".into(),
        severity: Severity::Low,
        confidence: Confidence::Confirmed,
        method: "GET".into(),
        endpoint: "/".into(),
        fingerprint: format!("{host}|GET|/|-|missing_csp"),
        source_engine: "sherlock-core".into(),
        host: host.into(),
        ..Default::default()
    };
    let fa = db.persist_final_finding(&a.0, &cand("a.example")).unwrap();
    let fb = db.persist_final_finding(&b.0, &cand("b.example")).unwrap();
    assert_eq!(fa.display_id, "F-0001");
    assert_eq!(fb.display_id, "F-0001");
}

#[test]
fn failed_002_is_not_recorded() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(INIT_SQL).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            applied_at TEXT NOT NULL
         );
         INSERT INTO schema_migrations (version, name, applied_at)
         VALUES ('001_init', 'init', datetime('now'));",
    )
    .unwrap();
    conn.execute("DROP TABLE findings", []).unwrap();
    let err = apply(&conn).unwrap_err().to_string();
    assert!(err.contains("002_finding_identity") || err.contains("findings"));
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = '002_finding_identity'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}
