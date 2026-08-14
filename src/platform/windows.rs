use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Some(base) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(base).join("SherlockHomes");
    }
    directories::BaseDirs::new()
        .map(|b| b.data_local_dir().join("SherlockHomes"))
        .unwrap_or_else(|| PathBuf::from(".").join("SherlockHomes"))
}
