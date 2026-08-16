use crate::core::error::Result;
use rusqlite::{params, Connection};

pub const INIT_SQL: &str = include_str!("../../migrations/001_init.sql");
pub const FINDING_IDENTITY_SQL: &str = include_str!("../../migrations/002_finding_identity.sql");

pub struct Migration {
    pub version: &'static str,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "001_init",
        name: "init",
        sql: INIT_SQL,
    },
    Migration {
        version: "002_finding_identity",
        name: "finding_identity",
        sql: FINDING_IDENTITY_SQL,
    },
];

#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub applied: Vec<String>,
    pub schema_version: u32,
    pub latest_version: u32,
    pub findings_has_internal_id: bool,
    pub findings_has_legacy_id: bool,
    pub ready: bool,
    pub detail: String,
}

impl MigrationReport {
    pub fn status_label(&self) -> &'static str {
        if self.ready {
            "READY"
        } else {
            "NEEDS MIGRATION"
        }
    }
}

pub fn latest_schema_version() -> u32 {
    MIGRATIONS
        .iter()
        .map(|m| version_number(m.version))
        .max()
        .unwrap_or(0)
}

pub fn apply(conn: &Connection) -> Result<()> {
    ensure_history_table(conn)?;
    repair_incorrectly_recorded_002(conn)?;
    for migration in MIGRATIONS {
        if is_applied(conn, migration.version)? {
            continue;
        }
        apply_one(conn, migration)?;
    }
    if !findings_has_new_identity(conn)? {
        return Err(crate::SherlockError::Database(
            "migration 002_finding_identity did not install findings.internal_id; \
             the legacy findings.id primary key is still present"
                .into(),
        ));
    }
    Ok(())
}

pub fn inspect(conn: &Connection) -> Result<MigrationReport> {
    ensure_history_table(conn)?;
    let applied = applied_versions(conn)?;
    let schema_version = applied.iter().map(|v| version_number(v)).max().unwrap_or(0);
    let latest_version = latest_schema_version();
    let findings_has_internal_id = column_exists(conn, "findings", "internal_id")?;
    let findings_has_legacy_id = column_exists(conn, "findings", "id")?;
    let ready = findings_has_internal_id
        && !findings_has_legacy_id
        && schema_version >= latest_version
        && !legacy_findings_id_unique_survives(conn)?;
    let detail = if ready {
        "findings.internal_id is the primary key; UNIQUE(case_id, display_id) is in effect".into()
    } else if findings_has_legacy_id {
        "legacy findings.id uniqueness is still present".into()
    } else {
        format!("applied={applied:?} latest={latest_version}")
    };
    Ok(MigrationReport {
        applied,
        schema_version,
        latest_version,
        findings_has_internal_id,
        findings_has_legacy_id,
        ready,
        detail,
    })
}

pub fn applied_versions(conn: &Connection) -> Result<Vec<String>> {
    if !table_exists(conn, "schema_migrations")? {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

fn apply_one(conn: &Connection, migration: &Migration) -> Result<()> {
    if migration.version == "002_finding_identity" && findings_has_new_identity(conn)? {
        record_applied(conn, migration)?;
        return Ok(());
    }

    let fk_on = foreign_keys_enabled(conn)?;
    conn.pragma_update(None, "foreign_keys", false)
        .map_err(|e| crate::SherlockError::Database(e.to_string()))?;

    let result = apply_one_txn(conn, migration);

    let _ = conn.pragma_update(None, "foreign_keys", fk_on);
    result?;

    if migration.version == "002_finding_identity" {
        if !findings_has_new_identity(conn)? {
            return Err(crate::SherlockError::Database(
                "migration 002_finding_identity committed without replacing findings.id".into(),
            ));
        }
        if legacy_findings_id_unique_survives(conn)? {
            return Err(crate::SherlockError::Database(
                "migration 002_finding_identity left a UNIQUE constraint on findings.id".into(),
            ));
        }
    }
    Ok(())
}

fn apply_one_txn(conn: &Connection, migration: &Migration) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(migration.sql).map_err(|e| {
        crate::SherlockError::Database(format!(
            "migration {} ({}) failed: {e}",
            migration.version, migration.name
        ))
    })?;
    if migration.version == "002_finding_identity" && !findings_has_new_identity(&tx)? {
        return Err(crate::SherlockError::Database(
            "migration 002_finding_identity did not produce findings.internal_id; \
             not recording it as applied"
                .into(),
        ));
    }
    let now = unix_timestamp_rfc3339();
    tx.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
        params![migration.version, migration.name, now],
    )?;
    tx.commit()?;
    Ok(())
}

fn record_applied(conn: &Connection, migration: &Migration) -> Result<()> {
    let now = unix_timestamp_rfc3339();
    conn.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
        params![migration.version, migration.name, now],
    )?;
    Ok(())
}

fn repair_incorrectly_recorded_002(conn: &Connection) -> Result<()> {
    if is_applied(conn, "002_finding_identity")? && !findings_has_new_identity(conn)? {
        conn.execute(
            "DELETE FROM schema_migrations WHERE version = ?1",
            ["002_finding_identity"],
        )?;
    }
    Ok(())
}

fn ensure_history_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            applied_at TEXT NOT NULL
        );",
    )?;
    if !column_exists(conn, "schema_migrations", "name")? {
        conn.execute(
            "ALTER TABLE schema_migrations ADD COLUMN name TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

fn is_applied(conn: &Connection, version: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [version],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn findings_has_new_identity(conn: &Connection) -> Result<bool> {
    Ok(column_exists(conn, "findings", "internal_id")? && !column_exists(conn, "findings", "id")?)
}

fn foreign_keys_enabled(conn: &Connection) -> Result<bool> {
    let v: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    Ok(v != 0)
}

pub fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

pub fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    if !table_exists(conn, table)? {
        return Ok(false);
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(names.iter().any(|name| name == column))
}

pub fn legacy_findings_id_unique_survives(conn: &Connection) -> Result<bool> {
    column_exists(conn, "findings", "id")
}

fn version_number(version: &str) -> u32 {
    version
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn unix_timestamp_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_twice() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        apply(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM cases", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        assert!(column_exists(&conn, "findings", "internal_id").unwrap());
        assert!(!column_exists(&conn, "findings", "id").unwrap());
    }

    #[test]
    fn registered_in_order() {
        assert_eq!(MIGRATIONS[0].version, "001_init");
        assert_eq!(MIGRATIONS[1].version, "002_finding_identity");
        assert_eq!(latest_schema_version(), 2);
    }
}
