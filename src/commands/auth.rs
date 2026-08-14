use crate::database::Database;
use crate::platform::secrets_dir;
use std::io::{self, Write};

pub fn add(db: &Database, name: &str) -> crate::Result<()> {
    eprintln!(
        "Header lines as Header: value (empty line to finish). Secrets are not echoed in logs."
    );
    let mut headers = serde_json::Map::new();
    let stdin = io::stdin();
    loop {
        eprint!("> ");
        io::stderr().flush()?;
        let mut line = String::new();
        stdin.read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(
                k.trim().to_string(),
                serde_json::Value::String(v.trim().to_string()),
            );
        }
    }
    eprint!("Cookie header value (optional): ");
    io::stderr().flush()?;
    let mut cookies = String::new();
    stdin.read_line(&mut cookies)?;
    let headers_json = serde_json::Value::Object(headers).to_string();
    // Keep a copy under secrets dir as well (0600 on unix).
    let path = secrets_dir()?.join(format!("{name}.headers.json"));
    std::fs::write(&path, &headers_json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    db.auth_add(name, "headers", &headers_json, cookies.trim())?;
    println!("Auth profile '{name}' stored. Secrets will be redacted in evidence.");
    Ok(())
}

pub fn list(db: &Database) -> crate::Result<()> {
    for (n, k) in db.auth_list()? {
        println!("{n}\t{k}");
    }
    Ok(())
}

pub fn remove(db: &Database, name: &str) -> crate::Result<()> {
    if db.auth_remove(name)? {
        println!("Removed {name}");
    } else {
        println!("No profile named {name}");
    }
    Ok(())
}
