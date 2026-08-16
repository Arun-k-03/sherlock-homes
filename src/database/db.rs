use crate::core::error::Result;
use crate::core::types::{
    CandidateFinding, Confidence, Endpoint, ParamLocation, Parameter, Severity,
};
use crate::database::migrations;
use crate::database::models::CaseRecord;
use crate::evidence::model::{StoredEvidence, StoredFinding};
use crate::ids::{CaseId, EvidenceId, FindingId, RequestId, ResponseId};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        migrations::apply(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrations::apply(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn migration_report(&self) -> Result<migrations::MigrationReport> {
        let conn = self.conn.lock();
        migrations::inspect(&conn)
    }

    pub fn create_case(&self, id: &CaseId, target: &str, mode: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO cases (id, created_at, updated_at, status, target_url, mode)
             VALUES (?1, ?2, ?2, 'running', ?3, ?4)",
            params![id.0, now, target, mode],
        )?;
        Ok(())
    }

    pub fn set_case_status(&self, id: &str, status: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.lock().execute(
            "UPDATE cases SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now, id],
        )?;
        Ok(())
    }

    pub fn set_resume_state(&self, id: &str, state: &str) -> Result<()> {
        self.conn.lock().execute(
            "UPDATE cases SET resume_state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state, chrono::Utc::now().to_rfc3339(), id],
        )?;
        Ok(())
    }

    pub fn get_case(&self, id: &str) -> Result<Option<CaseRecord>> {
        let conn = self.conn.lock();
        let rec = conn
            .query_row(
                "SELECT id, created_at, updated_at, status, title, target_url, mode, resume_state
                 FROM cases WHERE id = ?1",
                [id],
                |r| {
                    Ok(CaseRecord {
                        id: r.get(0)?,
                        created_at: r.get(1)?,
                        updated_at: r.get(2)?,
                        status: r.get(3)?,
                        title: r.get(4)?,
                        target_url: r.get(5)?,
                        mode: r.get(6)?,
                        resume_state: r.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(rec)
    }

    pub fn list_cases(&self) -> Result<Vec<CaseRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, created_at, updated_at, status, title, target_url, mode, resume_state
             FROM cases ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CaseRecord {
                id: r.get(0)?,
                created_at: r.get(1)?,
                updated_at: r.get(2)?,
                status: r.get(3)?,
                title: r.get(4)?,
                target_url: r.get(5)?,
                mode: r.get(6)?,
                resume_state: r.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn insert_host(&self, case_id: &str, hostname: &str, ip: Option<&str>) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO hosts (case_id, hostname, ip) VALUES (?1, ?2, ?3)",
            params![case_id, hostname, ip],
        )?;
        Ok(())
    }

    pub fn insert_page(
        &self,
        case_id: &str,
        url: &str,
        status: u16,
        content_type: Option<&str>,
        body_hash: &str,
        title: Option<&str>,
    ) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO pages (case_id, url, status, content_type, body_hash, title)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![case_id, url, status as i64, content_type, body_hash, title],
        )?;
        Ok(())
    }

    pub fn insert_endpoint(&self, case_id: &str, ep: &Endpoint) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO endpoints
             (case_id, method, url, host, path, normalized_path, content_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                case_id,
                ep.method,
                ep.url,
                ep.host,
                url::Url::parse(&ep.url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_default(),
                ep.normalized_path,
                ep.content_type,
            ],
        )?;
        let id: i64 = conn.query_row(
            "SELECT id FROM endpoints WHERE case_id = ?1 AND method = ?2 AND normalized_path = ?3",
            params![case_id, ep.method, ep.normalized_path],
            |r| r.get(0),
        )?;
        for p in &ep.parameters {
            conn.execute(
                "INSERT INTO parameters (case_id, endpoint_id, name, location, sample, inferred_type)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    case_id,
                    id,
                    p.name,
                    p.location.as_str(),
                    p.sample,
                    p.inferred_type
                ],
            )?;
        }
        Ok(id)
    }

    pub fn list_endpoints(&self, case_id: &str) -> Result<Vec<Endpoint>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, method, url, host, normalized_path, content_type FROM endpoints WHERE case_id = ?1",
        )?;
        let eps: Vec<(i64, Endpoint)> = stmt
            .query_map([case_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    Endpoint {
                        method: r.get(1)?,
                        url: r.get(2)?,
                        host: r.get(3)?,
                        normalized_path: r.get(4)?,
                        content_type: r.get(5)?,
                        parameters: vec![],
                        auth_hint: None,
                    },
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut out = Vec::new();
        for (id, mut ep) in eps {
            let mut ps = conn.prepare(
                "SELECT name, location, sample, inferred_type FROM parameters WHERE endpoint_id = ?1",
            )?;
            ep.parameters = ps
                .query_map([id], |r| {
                    Ok(Parameter {
                        name: r.get(0)?,
                        location: ParamLocation::parse(&r.get::<_, String>(1)?),
                        sample: r.get(2)?,
                        inferred_type: r.get(3)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            out.push(ep);
        }
        Ok(out)
    }

    pub fn next_finding_seq(&self, case_id: &str) -> Result<u32> {
        let conn = self.conn.lock();
        next_display_seq(&conn, case_id)
    }

    pub fn next_evidence_seq(&self, case_id: &str) -> Result<u32> {
        let n: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ?1",
            [case_id],
            |r| r.get(0),
        )?;
        Ok((n as u32) + 1)
    }

    pub fn next_request_seq(&self, case_id: &str) -> Result<u32> {
        let n: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM requests WHERE case_id = ?1",
            [case_id],
            |r| r.get(0),
        )?;
        Ok((n as u32) + 1)
    }

    pub fn insert_http_pair(
        &self,
        case_id: &str,
        method: &str,
        url: &str,
        req_headers: &str,
        req_body: &str,
        status: u16,
        resp_headers: &str,
        body_hash: &str,
        body_len: usize,
        content_type: Option<&str>,
        elapsed_ms: u128,
        excerpt: &str,
    ) -> Result<(RequestId, ResponseId)> {
        let seq = self.next_request_seq(case_id)?;
        let rid = RequestId::sequential(seq);
        let sid = ResponseId::sequential(seq);
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO requests (id, case_id, method, url, headers_redacted, body_redacted, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![rid.0, case_id, method, url, req_headers, req_body, now],
        )?;
        conn.execute(
            "INSERT INTO responses
             (id, request_id, case_id, status, headers_redacted, body_hash, body_len, content_type, elapsed_ms, body_excerpt_redacted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                sid.0,
                rid.0,
                case_id,
                status as i64,
                resp_headers,
                body_hash,
                body_len as i64,
                content_type,
                elapsed_ms as i64,
                excerpt
            ],
        )?;
        Ok((rid, sid))
    }

    /// Single ownership point for final finding persistence.
    /// Merges on `(case_id, correlate fingerprint)` instead of inserting duplicates.
    pub fn persist_final_finding(
        &self,
        case_id: &str,
        incoming: &CandidateFinding,
    ) -> Result<StoredFinding> {
        let c = crate::correlation::dedup::prepare(incoming);
        let rem = crate::remediation::for_detector(&c.detector_id);
        let endpoints_json = serde_json::to_string(&c.affected_endpoints)?;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let existing = select_finding_by_fingerprint(&tx, case_id, &c.fingerprint)?;
        if let Some(found) = existing {
            merge_existing_finding(&tx, &found, &c, &endpoints_json)?;
            tx.commit()?;
            return load_finding_by_internal(&conn, &found.internal_id)?
                .ok_or(crate::SherlockError::FindingNotFound(found.internal_id));
        }
        let seq = next_display_seq(&tx, case_id)?;
        let display_id = FindingId::display(seq).0;
        let internal_id = FindingId::new_internal();
        let now = chrono::Utc::now().to_rfc3339();
        let insert = tx.execute(
            "INSERT INTO findings
             (internal_id, case_id, display_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter,
              detector, source_engine, description, evidence_summary, remediation, fingerprint, status, created_at, host, affected_endpoints)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            params![
                internal_id,
                case_id,
                display_id,
                c.title,
                c.severity.as_str(),
                c.confidence.as_str(),
                c.cwe,
                c.owasp,
                c.method,
                c.endpoint,
                c.parameter,
                c.detector_id,
                c.source_engine,
                c.description,
                c.evidence_summary,
                rem,
                c.fingerprint,
                c.confidence.as_str(),
                now,
                c.host,
                endpoints_json,
            ],
        );
        match insert {
            Ok(_) => {}
            Err(e) if is_fingerprint_unique_violation(&e) => {
                let found = select_finding_by_fingerprint(&tx, case_id, &c.fingerprint)?
                    .ok_or_else(|| crate::SherlockError::Database(e.to_string()))?;
                let endpoints_json = serde_json::to_string(&c.affected_endpoints)?;
                merge_existing_finding(&tx, &found, &c, &endpoints_json)?;
                tx.commit()?;
                return load_finding_by_internal(&conn, &found.internal_id)?
                    .ok_or(crate::SherlockError::FindingNotFound(found.internal_id));
            }
            Err(e) => return Err(e.into()),
        }
        tx.commit()?;
        load_finding_by_internal(&conn, &internal_id)?
            .ok_or(crate::SherlockError::FindingNotFound(internal_id))
    }

    pub fn upsert_finding(&self, case_id: &str, c: &CandidateFinding) -> Result<String> {
        Ok(self.persist_final_finding(case_id, c)?.internal_id)
    }

    pub fn add_evidence(
        &self,
        case_id: &str,
        finding_id: &str,
        kind: &str,
        req: &str,
        resp: &str,
        notes: &str,
    ) -> Result<String> {
        let finding = self
            .get_finding(finding_id)?
            .ok_or_else(|| crate::SherlockError::FindingNotFound(finding_id.into()))?;
        let seq = self.next_evidence_seq(case_id)?;
        let id = format!("{case_id}/{}", EvidenceId::sequential(seq).0);
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.lock().execute(
            "INSERT INTO evidence (id, finding_id, case_id, kind, request_redacted, response_redacted, notes, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, finding.internal_id, case_id, kind, req, resp, notes, now],
        )?;
        Ok(id)
    }

    pub fn finding_by_fingerprint(&self, case_id: &str, fp: &str) -> Result<Option<StoredFinding>> {
        let conn = self.conn.lock();
        select_finding_by_fingerprint(&conn, case_id, fp)
    }

    pub fn list_findings(&self, case_id: &str) -> Result<Vec<StoredFinding>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&format!(
            "{FINDING_SELECT} FROM findings WHERE case_id = ?1 ORDER BY CAST(substr(display_id, 3) AS INTEGER)"
        ))?;
        let rows = stmt.query_map([case_id], map_finding_row)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_finding(&self, finding_id: &str) -> Result<Option<StoredFinding>> {
        let conn = self.conn.lock();
        resolve_finding(&conn, finding_id)
    }

    pub fn list_evidence_for_finding(&self, finding_id: &str) -> Result<Vec<StoredEvidence>> {
        let conn = self.conn.lock();
        let Some(finding) = resolve_finding(&conn, finding_id)? else {
            return Ok(vec![]);
        };
        let mut stmt = conn.prepare(
            "SELECT id, finding_id, case_id, kind, request_redacted, response_redacted, notes
             FROM evidence WHERE finding_id = ?1",
        )?;
        let rows = stmt.query_map([finding.internal_id], |r| {
            Ok(StoredEvidence {
                id: r.get(0)?,
                finding_id: r.get(1)?,
                case_id: r.get(2)?,
                kind: r.get(3)?,
                request_redacted: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                response_redacted: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                notes: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_case(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        if conn.query_row("SELECT COUNT(*) FROM cases WHERE id = ?1", [id], |r| {
            r.get::<_, i64>(0)
        })? == 0
        {
            return Ok(false);
        }
        conn.execute("DELETE FROM evidence WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM findings WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM candidate_findings WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM parameters WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM endpoints WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM responses WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM requests WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM pages WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM technologies WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM hosts WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM detector_results WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM scanner_events WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM reports WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM scan_configs WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM scans WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM targets WHERE case_id = ?1", [id])?;
        conn.execute("DELETE FROM cases WHERE id = ?1", [id])?;
        Ok(true)
    }

    pub fn insert_tech(&self, case_id: &str, name: &str, evidence: &str) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO technologies (case_id, name, evidence) VALUES (?1, ?2, ?3)",
            params![case_id, name, evidence],
        )?;
        Ok(())
    }

    pub fn list_tech(&self, case_id: &str) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, COALESCE(evidence,'') FROM technologies WHERE case_id = ?1")?;
        let rows = stmt.query_map([case_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn record_event(&self, case_id: &str, kind: &str, json: &str) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO scanner_events (case_id, kind, json, created_at) VALUES (?1,?2,?3,?4)",
            params![case_id, kind, json, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn record_report(&self, case_id: &str, format: &str, path: &str) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO reports (case_id, format, path, created_at) VALUES (?1,?2,?3,?4)",
            params![case_id, format, path, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn auth_add(
        &self,
        name: &str,
        kind: &str,
        headers_json: &str,
        cookies_json: &str,
    ) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO auth_profiles (name, kind, headers_json, cookies_json, created_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                name,
                kind,
                headers_json,
                cookies_json,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn auth_list(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT name, kind FROM auth_profiles ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn auth_remove(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .lock()
            .execute("DELETE FROM auth_profiles WHERE name = ?1", [name])?;
        Ok(n > 0)
    }

    pub fn auth_get(&self, name: &str) -> Result<Option<(String, String)>> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT COALESCE(headers_json,''), COALESCE(cookies_json,'') FROM auth_profiles WHERE name = ?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn insert_candidate(&self, case_id: &str, c: &CandidateFinding) -> Result<()> {
        let json = serde_json::to_string(c)?;
        self.conn.lock().execute(
            "INSERT INTO candidate_findings (case_id, fingerprint, json, status) VALUES (?1,?2,?3,?4)",
            params![case_id, c.fingerprint, json, c.confidence.as_str()],
        )?;
        Ok(())
    }

    pub fn list_candidates(&self, case_id: &str) -> Result<Vec<CandidateFinding>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT json FROM candidate_findings WHERE case_id = ?1")?;
        let rows = stmt.query_map([case_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows.flatten() {
            if let Ok(c) = serde_json::from_str(&j) {
                out.push(c);
            }
        }
        Ok(out)
    }
}

const FINDING_SELECT: &str = "SELECT internal_id, case_id, display_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter, detector, source_engine, description, evidence_summary, remediation, fingerprint, status, host, affected_endpoints";

fn next_display_seq(conn: &Connection, case_id: &str) -> Result<u32> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(MAX(CAST(substr(display_id, 3) AS INTEGER)), 0)
         FROM findings WHERE case_id = ?1 AND display_id LIKE 'F-%'",
        [case_id],
        |r| r.get(0),
    )?;
    Ok((n as u32) + 1)
}

fn map_finding_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFinding> {
    let internal_id: String = r.get(0)?;
    let case_id: String = r.get(1)?;
    let display_id: String = r.get(2)?;
    let affected_raw: String = r.get(20)?;
    let affected_endpoints: Vec<String> = serde_json::from_str(&affected_raw).unwrap_or_default();
    Ok(StoredFinding {
        id: FindingId::public(&case_id, &display_id),
        internal_id,
        case_id,
        display_id,
        title: r.get(3)?,
        severity: parse_sev(&r.get::<_, String>(4)?),
        confidence: parse_conf(&r.get::<_, String>(5)?),
        cwe: r.get(6)?,
        owasp: r.get(7)?,
        cvss: r.get(8)?,
        method: r.get(9)?,
        endpoint: r.get(10)?,
        parameter: r.get(11)?,
        detector: r.get(12)?,
        source_engine: r.get(13)?,
        description: r.get(14)?,
        evidence_summary: r.get(15)?,
        remediation: r.get(16)?,
        fingerprint: r.get(17)?,
        status: r.get(18)?,
        host: r.get(19)?,
        affected_endpoints,
    })
}

fn load_finding_by_internal(conn: &Connection, internal_id: &str) -> Result<Option<StoredFinding>> {
    let rec = conn
        .query_row(
            &format!("{FINDING_SELECT} FROM findings WHERE internal_id = ?1"),
            [internal_id],
            map_finding_row,
        )
        .optional()?;
    Ok(rec)
}

fn select_finding_by_fingerprint(
    conn: &Connection,
    case_id: &str,
    fp: &str,
) -> Result<Option<StoredFinding>> {
    let rec = conn
        .query_row(
            &format!("{FINDING_SELECT} FROM findings WHERE case_id = ?1 AND fingerprint = ?2"),
            params![case_id, fp],
            map_finding_row,
        )
        .optional()?;
    Ok(rec)
}

fn resolve_finding(conn: &Connection, token: &str) -> Result<Option<StoredFinding>> {
    let token = token.trim();
    if let Some(found) = load_finding_by_internal(conn, token)? {
        return Ok(Some(found));
    }
    if let Some((case_id, display_id)) = token.split_once('/') {
        return Ok(conn
            .query_row(
                &format!("{FINDING_SELECT} FROM findings WHERE case_id = ?1 AND display_id = ?2"),
                params![case_id, display_id],
                map_finding_row,
            )
            .optional()?);
    }
    if let Some(compact) = parse_compact_public_id(token) {
        return Ok(conn
            .query_row(
                &format!("{FINDING_SELECT} FROM findings WHERE case_id = ?1 AND display_id = ?2"),
                params![compact.0, compact.1],
                map_finding_row,
            )
            .optional()?);
    }
    if let Some(display) = legacy_display_id(token) {
        let mut stmt = conn.prepare(&format!(
            "{FINDING_SELECT} FROM findings WHERE display_id = ?1"
        ))?;
        let rows: Vec<StoredFinding> = stmt
            .query_map([display], map_finding_row)?
            .filter_map(|r| r.ok())
            .collect();
        if rows.len() == 1 {
            return Ok(rows.into_iter().next());
        }
    }
    Ok(None)
}

fn parse_compact_public_id(token: &str) -> Option<(String, String)> {
    // SH-260814-B55F-F0001
    let idx = token.rfind("-F")?;
    let case_id = token[..idx].to_string();
    let num = token.get(idx + 2..)?;
    if !case_id.starts_with("SH-") || !num.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u32 = num.parse().ok()?;
    Some((case_id, FindingId::display(n).0))
}

fn legacy_display_id(token: &str) -> Option<String> {
    if token.starts_with("F-") {
        return Some(token.to_string());
    }
    if let Some(rest) = token.strip_prefix("SH-F-") {
        if rest.chars().all(|c| c.is_ascii_digit()) {
            let n: u32 = rest.parse().ok()?;
            return Some(FindingId::display(n).0);
        }
    }
    None
}

fn merge_existing_finding(
    conn: &Connection,
    found: &StoredFinding,
    c: &CandidateFinding,
    incoming_endpoints_json: &str,
) -> Result<()> {
    let incoming: Vec<String> = serde_json::from_str(incoming_endpoints_json).unwrap_or_default();
    let mut endpoints = found.affected_endpoints.clone();
    for ep in incoming {
        if !ep.trim().is_empty() && !endpoints.iter().any(|e| e == &ep) {
            endpoints.push(ep);
        }
    }
    let evidence = crate::correlation::dedup::append_unique_evidence(
        &found.evidence_summary,
        &c.evidence_summary,
    );
    let confidence = if c.confidence > found.confidence {
        c.confidence
    } else {
        found.confidence
    };
    let mut description = found.description.clone();
    let n = endpoints.len();
    if n > 1 && !description.contains("Affected endpoints:") {
        description = format!("{}\n\nAffected endpoints: {n}", description.trim());
    } else if n > 1 {
        if let Some(idx) = description.rfind("Affected endpoints:") {
            description = format!("{}Affected endpoints: {n}", &description[..idx]);
        }
    }
    let endpoints_json = serde_json::to_string(&endpoints)?;
    conn.execute(
        "UPDATE findings SET affected_endpoints = ?1, evidence_summary = ?2, description = ?3,
         confidence = ?4, status = ?4 WHERE internal_id = ?5",
        params![
            endpoints_json,
            evidence,
            description,
            confidence.as_str(),
            found.internal_id
        ],
    )?;
    Ok(())
}

fn is_fingerprint_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(_, Some(msg)) => {
            msg.contains("UNIQUE constraint failed") && msg.contains("fingerprint")
        }
        _ => false,
    }
}

fn parse_sev(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

fn parse_conf(s: &str) -> Confidence {
    match s {
        "confirmed" => Confidence::Confirmed,
        "high_confidence" => Confidence::HighConfidence,
        "likely" => Confidence::Likely,
        "rejected" => Confidence::Rejected,
        _ => Confidence::Potential,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::CaseId;

    #[test]
    fn persist_case_and_finding() {
        let db = Database::open_in_memory().unwrap();
        let id = CaseId("SH-260814-TEST".into());
        db.create_case(&id, "https://example.com", "safe").unwrap();
        let c = CandidateFinding {
            detector_id: "missing_csp".into(),
            detector_name: "CSP".into(),
            title: "Missing CSP".into(),
            description: "no csp".into(),
            severity: Severity::Low,
            confidence: Confidence::Confirmed,
            cwe: Some("CWE-693".into()),
            owasp: Some("A05:2021".into()),
            method: "GET".into(),
            endpoint: "/".into(),
            parameter: None,
            evidence_summary: "header absent".into(),
            fingerprint: "example.com|GET|/|missing_csp".into(),
            source_engine: "sherlock-core".into(),
            ..Default::default()
        };
        let stored = db.persist_final_finding(&id.0, &c).unwrap();
        assert_eq!(stored.display_id, "F-0001");
        assert_eq!(stored.id, "SH-260814-TEST/F-0001");
        assert_eq!(db.list_findings(&id.0).unwrap().len(), 1);
        let fid2 = db.upsert_finding(&id.0, &c).unwrap();
        assert_eq!(stored.internal_id, fid2);
    }
}
