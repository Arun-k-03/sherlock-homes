use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedResponse {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub body_text: Option<String>,
    pub body_hash: String,
    pub elapsed_ms: u128,
    pub redirects: Vec<String>,
}

impl RecordedResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == want)
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> &str {
        self.body_text.as_deref().unwrap_or("")
    }

    pub fn is_html(&self) -> bool {
        self.content_type
            .as_deref()
            .map(|c| c.contains("html"))
            .unwrap_or(false)
    }
}
