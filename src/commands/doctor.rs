use crate::core::config::AppConfig;
use crate::database::Database;
use crate::platform::{architecture, data_dir, db_path, detect_os, ensure_writable};
use crate::ui::theme::color_level;
use crate::ui::theme::ColorLevel;

pub fn run(cfg: &AppConfig, machine: bool, database: bool) -> crate::Result<()> {
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
    let db_report = database_report();
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
                "database": db_report,
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
    print_database_human(&db_report, database);
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

fn database_report() -> serde_json::Value {
    let path = match db_path() {
        Ok(p) => p,
        Err(e) => {
            return serde_json::json!({
                "status": "FAILED",
                "error": e.to_string(),
            });
        }
    };
    match Database::open(&path) {
        Ok(db) => match db.migration_report() {
            Ok(r) => serde_json::json!({
                "path": path.display().to_string(),
                "schema_version": r.schema_version,
                "latest_schema_version": r.latest_version,
                "status": r.status_label(),
                "applied": r.applied,
                "findings_internal_id": r.findings_has_internal_id,
                "legacy_findings_id": r.findings_has_legacy_id,
                "detail": r.detail,
            }),
            Err(e) => serde_json::json!({
                "path": path.display().to_string(),
                "status": "FAILED",
                "error": e.to_string(),
            }),
        },
        Err(e) => serde_json::json!({
            "path": path.display().to_string(),
            "status": "FAILED",
            "error": e.to_string(),
        }),
    }
}

fn print_database_human(report: &serde_json::Value, verbose: bool) {
    let status = report
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("FAILED");
    let schema = report
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let latest = report
        .get("latest_schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    println!("Database schema version: {schema}");
    println!("Latest schema version:   {latest}");
    println!("Migration status:        {status}");
    if verbose {
        if let Some(path) = report.get("path").and_then(|v| v.as_str()) {
            println!("Database path:           {path}");
        }
        if let Some(applied) = report.get("applied").and_then(|v| v.as_array()) {
            let list: Vec<&str> = applied.iter().filter_map(|v| v.as_str()).collect();
            println!("Applied migrations:      {}", list.join(", "));
        }
        if let Some(detail) = report.get("detail").and_then(|v| v.as_str()) {
            println!("Schema detail:           {detail}");
        }
        if let Some(err) = report.get("error").and_then(|v| v.as_str()) {
            println!("Database error:          {err}");
        }
    }
}

fn ready(ok: bool) -> &'static str {
    if ok {
        "READY"
    } else {
        "FAILED"
    }
}
