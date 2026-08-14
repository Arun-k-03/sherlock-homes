# Evidence Vault migrations

The vault is a local SQLite database. Schema history:

| Version | File | Role |
|---|---|---|
| 001 | `migrations/001_init.sql` | Initial cases, findings, evidence |
| 002 | `migrations/002_finding_identity.sql` | `internal_id` PK, `display_id` (`F-0001`), `UNIQUE(case_id, display_id)` |

**Never modify an already-released migration.** Add `003_*.sql`, `004_*.sql`, and so on.

## Rules

- Apply migrations in a transaction
- Record a migration only after it succeeds
- Validate schema after apply (`internal_id` present, legacy `findings.id` gone after 002)
- Running migrations twice must be safe (idempotent history)
- A failed migration must not be marked successful

## Upgrade tests

`tests/migration_upgrade.rs` builds a real schema-001 file, inserts legacy rows, runs the current migrator, and asserts cases, findings, and evidence survive.

## Backup before major upgrades

Copy the vault file (path from `sherlock doctor --database`) plus `-wal`/`-journal` if present.

Uninstalling `sherlock` does not delete the vault.

## Public finding IDs

- `internal_id` — globally unique UUID (storage)
- `display_id` — case-local `F-0001`
- Public: `SH-YYMMDD-XXXX/F-0001`
