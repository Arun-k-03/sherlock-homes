//! Sherlock Homes — Cyber Investigation Engine.
//!
//! CLI/TUI web-application vulnerability assessment for targets you own
//! or are explicitly authorized to test. Default scan mode is `safe`.
//! Automated scanning cannot guarantee 100% detection coverage.

pub mod cli;
pub mod commands;
pub mod core;
pub mod correlation;
pub mod database;
pub mod detectors;
pub mod discovery;
pub mod engines;
pub mod evidence;
pub mod fingerprint;
pub mod ids;
pub mod network;
pub mod platform;
pub mod remediation;
pub mod reports;
pub mod scoring;
pub mod ui;
pub mod verification;

pub use core::config::AppConfig;
pub use core::error::{Result, SherlockError};
pub use ids::CaseId;
