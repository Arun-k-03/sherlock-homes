# Contributing to Sherlock Homes

## Workflow

1. Fork (or branch from `main` on a clone)
2. `git clone` and `cd sherlock-holmes`
3. `git checkout -b feature/short-name` (or `fix/…`)
4. Make changes
5. `cargo fmt`
6. `cargo clippy --all-targets -- -D warnings`
7. `cargo test`
8. Commit with a message that explains **why**
9. Open a pull request against `main`

Do not force-push `main`. Do not commit `target/`, vaults, or generated reports.

## Detector changes (required)

Every new or changed detector must include:

- Positive fixture (vulnerable)
- Negative fixture (secure)
- False-positive regression where relevant
- Severity rationale
- Confidence rationale
- Redaction behavior for any sensitive values
- Tests that do **not** scan the public Internet

## Database changes

Never edit a released migration. Add `003_…`, `004_…`, plus an old-schema upgrade test. See [docs/database-migrations.md](docs/database-migrations.md).

## CLI changes

Update `--help`, docs, and a CLI test. Treat command syntax as a public API. Prefer deprecation before removal.

## Safety

Scanner tests use localhost or controlled fixtures only.
