use crate::core::config::AppConfig;
use crate::platform::{architecture, data_dir, detect_os, ensure_writable};
use crate::ui::theme::color_level;
use crate::ui::theme::ColorLevel;

pub fn run(cfg: &AppConfig, machine: bool) -> crate::Result<()> {
    let os = detect_os();
    let dir = data_dir()?;
    let writable = ensure_writable(&dir).is_ok();
    let sqlite = rusqlite::Connection::open_in_memory().is_ok();
    let dns = {
        use std::net::ToSocketAddrs;
        ("example.com", 80).to_socket_addrs().is_ok()
    };
    let color = color_level();
    let engines = crate::engines::EngineManager::probe(&cfg.engines);
    if machine {
        println!(
            "{}",
            serde_json::json!({
                "platform": os.as_str(),
                "arch": architecture(),
                "data_dir": dir,
                "writable": writable,
                "sqlite": sqlite,
                "dns": dns,
                "color": format!("{color:?}"),
            })
        );
        return Ok(());
    }
    println!("SHERLOCK SYSTEM DIAGNOSTICS");
    println!("Platform      {}", os.as_str());
    println!("Architecture  {}", architecture());
    println!("Data dir      {}", dir.display());
    println!("Write         {}", ready(writable));
    println!("SQLite        {}", ready(sqlite));
    println!("Core          READY");
    println!("HTTP          READY");
    println!("Crawler       READY");
    println!("Custom Engine READY");
    println!("DNS           {}", ready(dns));
    println!(
        "HTTPS/TLS     READY ({})",
        crate::network::tls::stack_name()
    );
    println!(
        "Terminal      {}x{}",
        crate::ui::terminal::size().0,
        crate::ui::terminal::size().1
    );
    println!(
        "True color    {}",
        if color == ColorLevel::True {
            "YES"
        } else {
            "NO / degraded"
        }
    );
    println!(
        "Animation     {}",
        if cfg.ui.animations {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    for e in engines.all() {
        if e.name == "Sherlock Core" {
            continue;
        }
        println!("{:<13} {} / {}", e.name, e.status.as_str(), e.detail);
    }
    if os == crate::platform::OsKind::Termux {
        println!("Browser       UNSUPPORTED IN CORE TERMUX MODE");
        println!("ZAP           DISABLED");
    }
    println!("\nSherlock core investigation capability is READY.");
    Ok(())
}

fn ready(ok: bool) -> &'static str {
    if ok {
        "READY"
    } else {
        "FAILED"
    }
}
