use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("sherlock-homes");
    }
    if let Some(home) = directories::BaseDirs::new() {
        return home.home_dir().join(".local/share/sherlock-homes");
    }
    PathBuf::from(".").join("sherlock-homes")
}
