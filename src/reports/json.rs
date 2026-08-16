use crate::reports::ReportBundle;
use std::fs;
use std::path::Path;

pub fn write(bundle: &ReportBundle, path: &Path) -> crate::Result<()> {
    let json = serde_json::to_string_pretty(bundle)?;
    fs::write(path, json)?;
    Ok(())
}
