//! Optional external engines. Sherlock core never requires these binaries.
//!
//! - Nuclei: JSONL import if `nuclei` is on PATH
//! - Katana / httpx / ZAP: presence detection only (placeholders)

pub mod httpx;
pub mod katana;
pub mod manager;
pub mod nuclei;
pub mod zap;

pub use manager::{EngineInfo, EngineManager, EngineStatus};
