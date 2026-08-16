use crate::core::types::{Confidence, Severity};
use crate::ids::FindingId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    /// User-facing identifier: `{case_id}/{display_id}`.
    pub id: String,
    pub internal_id: String,
    pub display_id: String,
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
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub affected_endpoints: Vec<String>,
}

impl StoredFinding {
    pub fn public_id(&self) -> String {
        FindingId::public(&self.case_id, &self.display_id)
    }

    pub fn affected_endpoint_labels(&self) -> Vec<String> {
        if self.affected_endpoints.is_empty() {
            vec![format!("{} {}", self.method, self.endpoint)]
        } else {
            self.affected_endpoints.clone()
        }
    }

    /// Sample for CLI/PDF/HTML. Full list remains on `affected_endpoints`.
    pub fn sample_affected_endpoints(&self, limit: usize) -> (Vec<String>, usize) {
        let all = self.affected_endpoint_labels();
        let total = all.len();
        let sample: Vec<String> = all.into_iter().take(limit.max(1)).collect();
        let remaining = total.saturating_sub(sample.len());
        (sample, remaining)
    }

    pub fn affected_paths_display(&self) -> String {
        if self.affected_endpoints.is_empty() {
            format!("{} {}", self.method, self.endpoint)
        } else {
            self.affected_endpoints.join("\n")
        }
    }
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
