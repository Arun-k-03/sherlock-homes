use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Potential,
    Likely,
    HighConfidence,
    Confirmed,
    Rejected,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Potential => "potential",
            Self::Likely => "likely",
            Self::HighConfidence => "high_confidence",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Potential => "POTENTIAL",
            Self::Likely => "LIKELY",
            Self::HighConfidence => "HIGH CONFIDENCE",
            Self::Confirmed => "CONFIRMED",
            Self::Rejected => "REJECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    Running,
    Paused,
    Closed,
    Failed,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "running" => Self::Running,
            "paused" => Self::Paused,
            "closed" => Self::Closed,
            "failed" => Self::Failed,
            _ => Self::Open,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    Query,
    Path,
    Json,
    Form,
    Multipart,
    Header,
    Cookie,
    Xml,
}

impl ParamLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Path => "path",
            Self::Json => "json",
            Self::Form => "form",
            Self::Multipart => "multipart",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Xml => "xml",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "path" => Self::Path,
            "json" => Self::Json,
            "form" => Self::Form,
            "multipart" => Self::Multipart,
            "header" => Self::Header,
            "cookie" => Self::Cookie,
            "xml" => Self::Xml,
            _ => Self::Query,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParamLocation,
    pub sample: Option<String>,
    pub inferred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub method: String,
    pub url: String,
    pub host: String,
    pub normalized_path: String,
    pub content_type: Option<String>,
    pub parameters: Vec<Parameter>,
    pub auth_hint: Option<String>,
}

impl Endpoint {
    pub fn key(&self) -> String {
        format!("{} {}", self.method.to_uppercase(), self.normalized_path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateFinding {
    pub detector_id: String,
    pub detector_name: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub method: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub evidence_summary: String,
    pub fingerprint: String,
    pub source_engine: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order() {
        assert!(Severity::Critical > Severity::High);
        assert!(Confidence::Confirmed > Confidence::Potential);
    }
}
