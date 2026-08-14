//! Typed identifiers: cases, findings, evidence, requests, responses.

use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CaseId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResponseId(pub String);

impl CaseId {
    pub fn generate() -> Self {
        let date = Utc::now().format("%y%m%d");
        let suffix: String = {
            let mut rng = rand::thread_rng();
            (0..4)
                .map(|_| format!("{:X}", rng.gen_range(0..16u8)))
                .collect()
        };
        Self(format!("SH-{date}-{suffix}"))
    }
}

impl FindingId {
    pub fn sequential(n: u32) -> Self {
        Self(format!("SH-F-{n:04}"))
    }
}

impl EvidenceId {
    pub fn sequential(n: u32) -> Self {
        Self(format!("SH-EV-{n:04}"))
    }
}

impl RequestId {
    pub fn sequential(n: u32) -> Self {
        Self(format!("SH-RQ-{n:04}"))
    }
}

impl ResponseId {
    pub fn sequential(n: u32) -> Self {
        Self(format!("SH-RS-{n:04}"))
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for ResponseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CaseId {
    type Err = crate::SherlockError;
    fn from_str(s: &str) -> crate::Result<Self> {
        let t = s.trim();
        if t.starts_with("SH-") && t.len() >= 10 {
            Ok(Self(t.to_string()))
        } else {
            Err(crate::SherlockError::InvalidId(t.to_string()))
        }
    }
}

impl AsRef<str> for CaseId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_shape() {
        let id = CaseId::generate();
        assert!(id.0.starts_with("SH-"));
        let parts: Vec<_> = id.0.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 6);
        assert_eq!(parts[2].len(), 4);
    }

    #[test]
    fn finding_id_pads() {
        assert_eq!(FindingId::sequential(1).0, "SH-F-0001");
    }
}
