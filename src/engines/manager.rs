use crate::core::config::{EnginePref, EnginesConfig};
use crate::platform::{detect_os, OsKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineStatus {
    Ready,
    NotInstalled,
    Disabled,
    Unsupported,
}

impl EngineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::NotInstalled => "NOT INSTALLED",
            Self::Disabled => "DISABLED",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineInfo {
    pub name: &'static str,
    pub purpose: &'static str,
    pub status: EngineStatus,
    pub detail: String,
}

pub struct EngineManager {
    pub core: EngineInfo,
    pub nuclei: EngineInfo,
    pub katana: EngineInfo,
    pub httpx: EngineInfo,
    pub zap: EngineInfo,
}

impl EngineManager {
    pub fn probe(cfg: &EnginesConfig) -> Self {
        let os = detect_os();
        Self {
            core: EngineInfo {
                name: "Sherlock Core",
                purpose: "Native security engine",
                status: EngineStatus::Ready,
                detail: "built-in".into(),
            },
            nuclei: optional("Nuclei", "Template analysis", "nuclei", cfg.nuclei, os),
            katana: optional("Katana", "Surface discovery", "katana", cfg.katana, os),
            httpx: optional("httpx", "HTTP intelligence", "httpx", cfg.httpx, os),
            zap: zap_status(cfg.zap, os),
        }
    }

    pub fn all(&self) -> Vec<&EngineInfo> {
        vec![
            &self.core,
            &self.nuclei,
            &self.katana,
            &self.httpx,
            &self.zap,
        ]
    }
}

fn optional(
    name: &'static str,
    purpose: &'static str,
    bin: &str,
    pref: EnginePref,
    os: OsKind,
) -> EngineInfo {
    if pref == EnginePref::Off {
        return EngineInfo {
            name,
            purpose,
            status: EngineStatus::Disabled,
            detail: "disabled by config".into(),
        };
    }
    match which::which(bin) {
        Ok(p) => EngineInfo {
            name,
            purpose,
            status: EngineStatus::Ready,
            detail: p.display().to_string(),
        },
        Err(_) => EngineInfo {
            name,
            purpose,
            status: EngineStatus::NotInstalled,
            detail: format!("optional / not installed ({os:?})"),
        },
    }
}

fn zap_status(pref: EnginePref, os: OsKind) -> EngineInfo {
    if pref == EnginePref::Off || os == OsKind::Termux {
        return EngineInfo {
            name: "ZAP",
            purpose: "DAST engine",
            status: if os == OsKind::Termux {
                EngineStatus::Unsupported
            } else {
                EngineStatus::Disabled
            },
            detail: if os == OsKind::Termux {
                "disabled in Termux core mode".into()
            } else {
                "disabled by config".into()
            },
        };
    }
    let found = ["zap.sh", "zap.bat", "zap", "zaproxy"]
        .iter()
        .find_map(|b| which::which(b).ok());
    match found {
        Some(p) => EngineInfo {
            name: "ZAP",
            purpose: "DAST engine",
            status: EngineStatus::Ready,
            detail: p.display().to_string(),
        },
        None => EngineInfo {
            name: "ZAP",
            purpose: "DAST engine",
            status: EngineStatus::NotInstalled,
            detail: "optional / not installed".into(),
        },
    }
}
