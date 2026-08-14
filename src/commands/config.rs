use crate::core::config::AppConfig;

pub fn show(cfg: &AppConfig) -> crate::Result<()> {
    let s = toml::to_string_pretty(cfg).map_err(|e| crate::SherlockError::Config(e.to_string()))?;
    print!("{s}");
    Ok(())
}

pub fn path() -> crate::Result<()> {
    println!("{}", AppConfig::config_path()?.display());
    Ok(())
}

pub fn reset() -> crate::Result<()> {
    AppConfig::reset()?;
    println!(
        "Configuration reset to defaults at {}",
        AppConfig::config_path()?.display()
    );
    Ok(())
}
