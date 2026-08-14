use crate::core::error::{Result, SherlockError};
use crate::platform::data_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    Minimal,
    #[default]
    Classic,
    Cinematic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Passive,
    #[default]
    Safe,
    Full,
    Api,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AnimationSpeed {
    Slow,
    #[default]
    Normal,
    Fast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnginePref {
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub mode: UiMode,
    pub animations: bool,
    pub animation_speed: AnimationSpeed,
    pub color: bool,
    pub ascii_only: bool,
    pub reduced_motion: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            mode: UiMode::Classic,
            animations: true,
            animation_speed: AnimationSpeed::Normal,
            color: true,
            ascii_only: false,
            reduced_motion: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub rate: u32,
    pub concurrency: u32,
    pub depth: u32,
    pub timeout_seconds: u64,
    pub max_response_bytes: usize,
    pub max_redirects: u32,
    pub user_agent: String,
    pub respect_robots: bool,
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    #[serde(default = "default_max_queue")]
    pub max_queue: usize,
    #[serde(default = "default_max_children")]
    pub max_children_per_parent: usize,
}

fn default_max_pages() -> u32 {
    250
}
fn default_max_requests() -> u32 {
    500
}
fn default_max_queue() -> usize {
    1000
}
fn default_max_children() -> usize {
    80
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Safe,
            rate: 5,
            concurrency: 10,
            depth: 5,
            timeout_seconds: 15,
            max_response_bytes: 2_000_000,
            max_redirects: 8,
            user_agent: "SherlockHomes/1.0 (Cyber Investigation Engine)".into(),
            respect_robots: false,
            max_pages: default_max_pages(),
            max_requests: default_max_requests(),
            max_queue: default_max_queue(),
            max_children_per_parent: default_max_children(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportsConfig {
    pub default_formats: Vec<String>,
}

impl Default for ReportsConfig {
    fn default() -> Self {
        Self {
            default_formats: vec!["pdf".into(), "html".into(), "json".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnginesConfig {
    pub nuclei: EnginePref,
    pub katana: EnginePref,
    pub httpx: EnginePref,
    pub zap: EnginePref,
}

impl Default for EnginesConfig {
    fn default() -> Self {
        Self {
            nuclei: EnginePref::Auto,
            katana: EnginePref::Auto,
            httpx: EnginePref::Auto,
            zap: EnginePref::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub reports: ReportsConfig,
    #[serde(default)]
    pub engines: EnginesConfig,
    pub database_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn config_path() -> Result<PathBuf> {
        Ok(data_dir()?.join("sherlock.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let cfg: AppConfig = toml::from_str(&raw).map_err(|e| {
                SherlockError::Config(format!("failed to parse {}: {e}", path.display()))
            })?;
            Ok(cfg)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self).map_err(|e| SherlockError::Config(e.to_string()))?;
        fs::write(path, raw)?;
        Ok(())
    }

    pub fn reset() -> Result<Self> {
        let cfg = Self::default();
        cfg.save(&Self::config_path()?)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_safe() {
        assert_eq!(ScanConfig::default().mode, ScanMode::Safe);
    }

    #[test]
    fn roundtrip_toml() {
        let cfg = AppConfig::default();
        let s = toml::to_string(&cfg).unwrap();
        let back: AppConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.scan.rate, 5);
    }
}
