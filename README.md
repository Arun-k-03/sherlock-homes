# Sherlock Homes — Cyber Investigation Engine

**EVERY REQUEST LEAVES A CLUE.**

Sherlock Homes is a CLI/TUI web-application and API vulnerability assessment engine for systems **you own or are explicitly authorized to test**. Default scan mode is **safe**. Automated scanning cannot guarantee 100% vulnerability detection.

## Install

```bash
cargo install --path .
# binary name: sherlock
```

### Termux (Android)

```bash
pkg install rust binutils
cargo install --path .
sherlock doctor
```

## Quick start

```bash
sherlock doctor
sherlock scan https://authorized-target.example
sherlock cases
sherlock findings SH-YYMMDD-XXXX
sherlock report SH-YYMMDD-XXXX --format pdf,html,json,sarif --output ./reports
```

## Safety

- Active tests run only inside `--allow` scope (target host plus extras).
- `--exclude` paths are never requested.
- Rate limit and concurrency bound traffic (`--rate`, `--concurrency`).
- Destructive RCE, DoS, credential attacks, persistence, and file deletion are **not** performed.
- `full` mode still non-destructive; requires `--i-authorize-full`.

## Commands

`scan`, `hunt`, `crawl`, `inspect`, `cases`, `case`, `clues`, `suspects`, `findings`, `evidence`, `verdict`, `report`, `auth`, `engines`, `doctor`, `config`, `version`, `completion`.

## UI

```bash
sherlock scan TARGET --ui classic
sherlock scan TARGET --ui cinematic
sherlock scan TARGET --ui minimal
sherlock scan TARGET --format json   # clean stdout, no banners
```

## Configuration

`sherlock config path` — platform data directory `sherlock.toml`.

See [docs/configuration.md](docs/configuration.md).

## Reports

PDF, HTML, JSON, JSONL, SARIF, Markdown, CSV. Generated locally (no cloud API).

## License

MIT
