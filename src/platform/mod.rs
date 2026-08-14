pub mod linux;
pub mod macos;
pub mod termux;
pub mod windows;

use crate::core::error::{Result, SherlockError};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    Windows,
    Linux,
    Macos,
    Termux,
    Other,
}

impl OsKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::Macos => "macOS",
            Self::Termux => "Android / Termux",
            Self::Other => "Other",
        }
    }
}

pub fn detect_os() -> OsKind {
    if termux::is_termux() {
        return OsKind::Termux;
    }
    if cfg!(target_os = "windows") {
        OsKind::Windows
    } else if cfg!(target_os = "macos") {
        OsKind::Macos
    } else if cfg!(target_os = "linux") {
        OsKind::Linux
    } else {
        OsKind::Other
    }
}

pub fn data_dir() -> Result<PathBuf> {
    let dir = if termux::is_termux() {
        termux::data_dir()
    } else if cfg!(target_os = "windows") {
        windows::data_dir()
    } else if cfg!(target_os = "macos") {
        macos::data_dir()
    } else {
        linux::data_dir()
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn secrets_dir() -> Result<PathBuf> {
    let dir = data_dir()?.join("secrets");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

pub fn db_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("evidence-vault.sqlite"))
}

pub fn architecture() -> &'static str {
    std::env::consts::ARCH
}

pub fn ensure_writable(dir: &std::path::Path) -> Result<()> {
    let probe = dir.join(".write-probe");
    std::fs::write(&probe, b"ok").map_err(|e| {
        SherlockError::Config(format!(
            "data directory is not writable ({}): {e}",
            dir.display()
        ))
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_creates() {
        let d = data_dir().unwrap();
        assert!(d.exists());
    }
}
