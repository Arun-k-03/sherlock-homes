//! Real-time scanner events. The engine emits; UI renderers consume.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    CaseOpened,
    TargetValidated,
    HostResolved,
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
}

#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<ScanEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self { tx }
    }

    pub fn emit(&self, event: ScanEvent) {
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
