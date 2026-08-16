-- Rebuild findings/evidence identity. Invoked inside a rusqlite transaction
-- with foreign_keys disabled by the migration runner.
-- Do not mark this version applied unless the runner verifies internal_id exists.

DROP TABLE IF EXISTS evidence_v2;
DROP TABLE IF EXISTS findings_v2;

CREATE TABLE findings_v2 (
    internal_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    display_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    cwe TEXT,
    owasp TEXT,
    cvss TEXT,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    parameter TEXT,
    detector TEXT NOT NULL,
    source_engine TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    remediation TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    affected_endpoints TEXT NOT NULL DEFAULT '[]',
    UNIQUE(case_id, display_id),
    UNIQUE(case_id, fingerprint),
    FOREIGN KEY(case_id) REFERENCES cases(id)
);

INSERT INTO findings_v2 (
    internal_id, case_id, display_id, title, severity, confidence, cwe, owasp, cvss,
    method, endpoint, parameter, detector, source_engine, description, evidence_summary,
    remediation, fingerprint, status, created_at, host, affected_endpoints
)
SELECT
    case_id || '/' || CASE
        WHEN id LIKE 'SH-F-%' THEN 'F-' || substr(id, 6)
        ELSE id
    END,
    case_id,
    CASE
        WHEN id LIKE 'SH-F-%' THEN 'F-' || substr(id, 6)
        ELSE id
    END,
    title, severity, confidence, cwe, owasp, cvss,
    method, endpoint, parameter, detector, source_engine, description, evidence_summary,
    remediation, fingerprint, status, created_at,
    '',
    printf('["%s %s"]', method, endpoint)
FROM findings;

CREATE TABLE evidence_v2 (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    request_redacted TEXT,
    response_redacted TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings_v2(internal_id),
    FOREIGN KEY(case_id) REFERENCES cases(id)
);

INSERT INTO evidence_v2 (
    id, finding_id, case_id, kind, request_redacted, response_redacted, notes, created_at
)
SELECT
    e.case_id || '/' || e.id,
    f.case_id || '/' || CASE
        WHEN f.id LIKE 'SH-F-%' THEN 'F-' || substr(f.id, 6)
        ELSE f.id
    END,
    e.case_id,
    e.kind,
    e.request_redacted,
    e.response_redacted,
    e.notes,
    e.created_at
FROM evidence e
INNER JOIN findings f ON f.id = e.finding_id AND f.case_id = e.case_id;

DROP TABLE evidence;
DROP TABLE findings;
ALTER TABLE findings_v2 RENAME TO findings;
ALTER TABLE evidence_v2 RENAME TO evidence;

CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_display_id ON findings(display_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
