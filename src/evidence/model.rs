use crate::core::types::{Confidence, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub cvss: Option<String>,
    pub method: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub detector: String,
    pub source_engine: String,
    pub description: String,
    pub evidence_summary: String,
    pub remediation: String,
    pub fingerprint: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvidence {
    pub id: String,
    pub finding_id: String,
    pub case_id: String,
    pub kind: String,
    pub request_redacted: String,
    pub response_redacted: String,
    pub notes: String,
}
