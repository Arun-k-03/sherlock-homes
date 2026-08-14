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
        let n: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM findings WHERE case_id = ?1",
            [case_id],
            |r| r.get(0),
        )?;
        Ok((n as u32) + 1)
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

    pub fn upsert_finding(&self, case_id: &str, c: &CandidateFinding) -> Result<String> {
        if let Some(existing) = self.finding_by_fingerprint(case_id, &c.fingerprint)? {
            return Ok(existing.id);
        }
        let seq = self.next_finding_seq(case_id)?;
        let id = FindingId::sequential(seq).0;
        let now = chrono::Utc::now().to_rfc3339();
        let rem = crate::remediation::for_detector(&c.detector_id);
        self.conn.lock().execute(
            "INSERT INTO findings
             (id, case_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter,
              detector, source_engine, description, evidence_summary, remediation, fingerprint, status, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                id,
                case_id,
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
            ],
        )?;
        Ok(id)
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
        let seq = self.next_evidence_seq(case_id)?;
        let id = EvidenceId::sequential(seq).0;
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.lock().execute(
            "INSERT INTO evidence (id, finding_id, case_id, kind, request_redacted, response_redacted, notes, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, finding_id, case_id, kind, req, resp, notes, now],
        )?;
        Ok(id)
    }

    pub fn finding_by_fingerprint(&self, case_id: &str, fp: &str) -> Result<Option<StoredFinding>> {
        self.list_findings(case_id)
            .map(|v| v.into_iter().find(|f| f.fingerprint == fp))
    }

    pub fn list_findings(&self, case_id: &str) -> Result<Vec<StoredFinding>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter,
                    detector, source_engine, description, evidence_summary, remediation, fingerprint, status
             FROM findings WHERE case_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([case_id], |r| {
            Ok(StoredFinding {
                id: r.get(0)?,
                case_id: r.get(1)?,
                title: r.get(2)?,
                severity: parse_sev(&r.get::<_, String>(3)?),
                confidence: parse_conf(&r.get::<_, String>(4)?),
                cwe: r.get(5)?,
                owasp: r.get(6)?,
                cvss: r.get(7)?,
                method: r.get(8)?,
                endpoint: r.get(9)?,
                parameter: r.get(10)?,
                detector: r.get(11)?,
                source_engine: r.get(12)?,
                description: r.get(13)?,
                evidence_summary: r.get(14)?,
                remediation: r.get(15)?,
                fingerprint: r.get(16)?,
                status: r.get(17)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_finding(&self, finding_id: &str) -> Result<Option<StoredFinding>> {
        let conn = self.conn.lock();
        let rec = conn
            .query_row(
                "SELECT id, case_id, title, severity, confidence, cwe, owasp, cvss, method, endpoint, parameter,
                        detector, source_engine, description, evidence_summary, remediation, fingerprint, status
                 FROM findings WHERE id = ?1",
                [finding_id],
                |r| {
                    Ok(StoredFinding {
                        id: r.get(0)?,
                        case_id: r.get(1)?,
                        title: r.get(2)?,
                        severity: parse_sev(&r.get::<_, String>(3)?),
                        confidence: parse_conf(&r.get::<_, String>(4)?),
                        cwe: r.get(5)?,
                        owasp: r.get(6)?,
                        cvss: r.get(7)?,
                        method: r.get(8)?,
                        endpoint: r.get(9)?,
                        parameter: r.get(10)?,
                        detector: r.get(11)?,
                        source_engine: r.get(12)?,
                        description: r.get(13)?,
                        evidence_summary: r.get(14)?,
                        remediation: r.get(15)?,
                        fingerprint: r.get(16)?,
                        status: r.get(17)?,
                    })
                },
            )
            .optional()?;
        Ok(rec)
    }

    pub fn list_evidence_for_finding(&self, finding_id: &str) -> Result<Vec<StoredEvidence>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, finding_id, case_id, kind, request_redacted, response_redacted, notes
             FROM evidence WHERE finding_id = ?1",
        )?;
        let rows = stmt.query_map([finding_id], |r| {
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
        };
        let fid = db.upsert_finding(&id.0, &c).unwrap();
        assert!(fid.starts_with("SH-F-"));
        assert_eq!(db.list_findings(&id.0).unwrap().len(), 1);
        let fid2 = db.upsert_finding(&id.0, &c).unwrap();
        assert_eq!(fid, fid2);
    }
}
