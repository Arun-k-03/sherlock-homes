use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub status: String,
    pub title: Option<String>,
    pub target_url: String,
    pub mode: String,
    pub resume_state: Option<String>,
}
