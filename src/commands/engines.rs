use crate::core::config::AppConfig;
use crate::engines::EngineManager;

pub fn run(cfg: &AppConfig) -> crate::Result<()> {
    let mgr = EngineManager::probe(&cfg.engines);
    println!("ENGINE             PURPOSE                     STATUS");
    for e in mgr.all() {
        println!("{:<18} {:<27} {}", e.name, e.purpose, e.status.as_str());
    }
    Ok(())
}
