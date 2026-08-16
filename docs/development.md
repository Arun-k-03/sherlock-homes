# Development definition of done

## New detector

- Unit test
- Positive fixture
- Negative fixture
- False-positive regression
- Severity rationale
- Confidence rationale
- CWE/OWASP mapping where applicable
- Evidence structure
- Redaction test
- Report field still serializes

## Database change

- New migration file (never edit 001/002 after release)
- Old-schema upgrade test
- Fresh-install test
- Idempotence check
- Failed migration is not recorded as applied

## CLI change

- Help text
- Documentation
- CLI test
- Machine-output compatibility review
- Do not silently ignore flags

## Crawler / network

- Budgets honored
- No panic on malformed input
- Scope not expanded to third-party hosts

Run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```
