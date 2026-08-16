//! Real-time scanner events. The engine emits; UI renderers consume.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    CaseOpened,
    TargetValidated,
    HostResolved,
    DiscoveryStarted,
    DiscoveryCompleted,
    PageDiscovered,
    EndpointDiscovered,
    ParameterDiscovered,
    RequestSent,
    ResponseReceived,
    PassiveFinding,
    TestStarted,
    CandidateFound,
    VerificationStarted,
    FindingConfirmed,
    FindingRejected,
    ReportCreated,
    CaseClosed,
    Clue,
    PhaseProgress,
    Deduction,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub kind: EventKind,
    pub case_id: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl ScanEvent {
    pub fn new(kind: EventKind, case_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            case_id: case_id.into(),
            timestamp: Utc::now(),
            message: message.into(),
            method: None,
            path: None,
            parameter: None,
            severity: None,
            phase: None,
            progress: None,
            finding_id: None,
            extra: None,
        }
    }

    pub fn with_endpoint(mut self, method: impl Into<String>, path: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self.path = Some(path.into());
        self
    }

    pub fn with_phase(mut self, phase: impl Into<String>, progress: u8) -> Self {
        self.phase = Some(phase.into());
        self.progress = Some(progress);
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    pub fn with_finding_id(mut self, id: impl Into<String>) -> Self {
        self.finding_id = Some(id.into());
        self
    }
}

/// Single authoritative "METHOD path" label. Never prefixes a path that already
/// contains the method (`GET /search` must not become `GET GET /search`).
pub fn format_endpoint_label(method: Option<&str>, path: Option<&str>, message: &str) -> String {
    let method = method.unwrap_or("GET").trim();
    let raw = path.unwrap_or(message).trim();
    if raw.is_empty() {
        return method.to_string();
    }
    let first = raw.split_whitespace().next().unwrap_or("");
    if looks_like_http_method(first) {
        return raw.to_string();
    }
    if raw.starts_with('/') || raw.contains("://") {
        return format!("{method} {raw}");
    }
    format!("{method} {raw}")
}

fn looks_like_http_method(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
    )
}

#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<ScanEvent>,
    live: Option<Arc<dyn Fn(ScanEvent) + Send + Sync>>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self { tx, live: None }
    }

    pub fn with_ui(mut self, handler: Arc<dyn Fn(ScanEvent) + Send + Sync>) -> Self {
        self.live = Some(handler);
        self
    }

    pub fn emit(&self, event: ScanEvent) {
        if let Some(handler) = &self.live {
            handler(event.clone());
        }
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ScanEvent> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(2048)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clue_label_does_not_duplicate_method() {
        assert_eq!(
            format_endpoint_label(Some("GET"), Some("/search"), "GET /search"),
            "GET /search"
        );
        assert_eq!(
            format_endpoint_label(Some("GET"), None, "GET /search"),
            "GET /search"
        );
        assert_eq!(
            format_endpoint_label(Some("POST"), Some("/api/login"), "POST /api/login"),
            "POST /api/login"
        );
        assert_eq!(
            format_endpoint_label(Some("GET"), Some("GET /api/profile"), "ignored"),
            "GET /api/profile"
        );
        assert_eq!(
            format_endpoint_label(Some("GET"), Some("POST /api/login"), "POST /api/login"),
            "POST /api/login"
        );
        assert_eq!(
            format_endpoint_label(Some("GET"), Some("/api/profile"), "GET /api/profile"),
            "GET /api/profile"
        );
    }
}
