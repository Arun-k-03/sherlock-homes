use std::path::PathBuf;

pub fn is_termux() -> bool {
    if std::env::var("TERMUX_VERSION").is_ok() {
        return true;
    }
    if let Ok(prefix) = std::env::var("PREFIX") {
        if prefix.contains("com.termux") {
            return true;
        }
    }
    false
}

pub fn data_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".sherlock-homes");
    }
    PathBuf::from(".").join(".sherlock-homes")
}
