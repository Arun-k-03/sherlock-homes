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
        if self
            .content_type
            .as_deref()
            .map(|c| c.to_ascii_lowercase().contains("html"))
            .unwrap_or(false)
        {
            return true;
        }
        self.text().to_ascii_lowercase().contains("<html")
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn is_document_like(&self) -> bool {
        let ct = self
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if ct.is_empty() {
            return self.is_html() || self.body_text.is_some();
        }
        ct.contains("html")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("javascript")
            || ct.starts_with("text/")
    }

    pub fn is_binary_asset(&self) -> bool {
        let ct = self
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        ct.starts_with("image/")
            || ct.starts_with("audio/")
            || ct.starts_with("video/")
            || ct.starts_with("font/")
            || ct.contains("pdf")
            || ct.contains("octet-stream")
            || ct.contains("zip")
    }
}
