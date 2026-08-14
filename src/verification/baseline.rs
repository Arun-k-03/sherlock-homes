use crate::network::response::RecordedResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub status: u16,
    pub body_hash: String,
    pub body_len: usize,
    pub elapsed_ms: u128,
    pub content_type: Option<String>,
    pub redirect_target: Option<String>,
}

impl Baseline {
    pub fn from_response(r: &RecordedResponse) -> Self {
        Self {
            status: r.status,
            body_hash: r.body_hash.clone(),
            body_len: r.body.len(),
            elapsed_ms: r.elapsed_ms,
            content_type: r.content_type.clone(),
            redirect_target: r.redirects.last().cloned(),
        }
    }
}
