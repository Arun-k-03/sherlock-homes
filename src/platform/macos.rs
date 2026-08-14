use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Some(home) = directories::BaseDirs::new() {
        return home
            .home_dir()
            .join("Library/Application Support/SherlockHomes");
    }
    PathBuf::from(".").join("SherlockHomes")
}
