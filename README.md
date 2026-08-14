# Sherlock Homes — Cyber Investigation Engine

**EVERY REQUEST LEAVES A CLUE.**

Sherlock Homes is a CLI/TUI web-application and API vulnerability assessment engine. It maps an authorized target (the Scene), follows HTTP requests (Traces), records responses (Evidence), and produces investigation reports from a local Evidence Vault.

It is **not** Sherlock Holmes, a browser GUI, a cloud scanner, or a replacement for a human review.

Scan only systems **you own or are explicitly authorized to test**. Automated coverage is **not** 100%. Findings require evidence review.

## What it is not

- Not a pentest-as-a-service cloud
- Not a credential-stuffing or DoS tool
- Not a persistence / implant framework
- Not a guarantee of zero false negatives

## Features

- Passive, safe, and (non-destructive) full scan modes
- Bounded crawler with request/page/queue budgets
- Security-header, cookie, CORS, disclosure, secret, and related detectors
- Local SQLite Evidence Vault with schema migrations
- Classic / cinematic / minimal UI; machine JSON/JSONL/SARIF on stdout
- Reports: PDF, HTML, JSON, JSONL, SARIF, Markdown, CSV
- Optional engines (Nuclei, Katana, httpx, OWASP ZAP) if present on PATH — **core works without them**

## Platform support

| Platform | Status |
|---|---|
| Windows x86_64 | TESTED on maintainer GNU toolchain when release gates are run locally |
| Linux x86_64 | CI TESTED (GitHub `ubuntu-latest`) — not claimed from Windows compilation |
| macOS (GitHub runner) | CI TESTED when Actions run — architecture of runner may be Apple Silicon |
| macOS Intel | DESIGNED / CI-PARTIAL (release workflow can target `x86_64-apple-darwin`) |
| Android Termux ARM64 | DESIGNED / MANUAL VALIDATION REQUIRED |

Statuses mean: **TESTED** = executed on that OS in this workspace; **CI TESTED** = GitHub Actions job defined; **DESIGNED** = code paths exist; **MANUAL VALIDATION REQUIRED** = not executed here.

## Installation

### A. GitHub source

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd sherlock-holmes
cargo build --release
```

On Windows without MSVC `link.exe`, use the GNU toolchain (see [docs/windows-toolchain.md](docs/windows-toolchain.md)):

```powershell
cargo +stable-x86_64-pc-windows-gnu build --release
```

### B. Cargo local install

```bash
cargo install --path . --force
```

Binary name: `sherlock`. This is **not** published on crates.io unless a later release says so.

### C. Release binary

When a GitHub Release exists for tag `vX.Y.Z`:

1. Download the archive for your OS
2. Verify the SHA-256 checksum file
3. Place `sherlock` (or `sherlock.exe`) on `PATH`

## Quick start

```bash
sherlock doctor
sherlock doctor --database
sherlock inspect http://127.0.0.1:8080
sherlock scan http://127.0.0.1:8080 --mode passive
sherlock cases
sherlock findings SH-YYMMDD-XXXX
sherlock evidence SH-YYMMDD-XXXX/F-0001
sherlock verdict SH-YYMMDD-XXXX
sherlock report SH-YYMMDD-XXXX --format pdf,html,json --output ./reports
```

Use `example.com` only in documentation. Real scans in tests and CI use localhost fixtures.

## Commands

`scan`, `hunt`, `crawl`, `inspect`, `cases`, `case`, `clues`, `suspects`, `findings`, `evidence`, `verdict`, `report`, `auth`, `engines`, `doctor`, `config`, `version`, `completion`.

Reporting belongs to `sherlock report CASE --format ...`.  
`sherlock findings CASE --format pdf` is **rejected** (not silently ignored).

## Scan modes

| Mode | Intent |
|---|---|
| `passive` | Analyze captured responses; no extra active probes beyond crawl |
| `safe` (default) | Bounded extra checks; non-destructive |
| `full` | Extra non-destructive checks; requires `--i-authorize-full` |
| `api` | API-oriented investigation |

## Safety / authorization

- Active requests stay inside host scope (`--allow` / `--exclude`)
- Third-party CDNs and scripts may be recorded as clues without being scanned
- Rate limit and concurrency bound traffic
- Crawler budgets stop discovery without crashing
- Destructive RCE verification, DoS, credential attacks, and persistence are out of scope

## Optional engines

Nuclei / Katana / httpx / ZAP are **optional**. `sherlock doctor` reports `NOT INSTALLED` when missing. Katana, httpx, and ZAP integrations are currently **binary-presence placeholders** (no full crawl/DAST pipeline). Nuclei can import JSONL if the binary is present.

## Evidence Vault

Local SQLite. Path from `sherlock doctor --database` / `sherlock config path`. Uninstalling the binary does **not** delete the vault. Backup the vault before major upgrades. See [docs/database-migrations.md](docs/database-migrations.md).

## Configuration

Precedence actually implemented:

1. Built-in defaults  
2. User `sherlock.toml` (`sherlock config path`)  
3. CLI flags on scan/hunt/crawl (`--mode`, `--rate`, `--depth`, …)

Environment: `NO_COLOR`, `RUST_LOG`. There is no scan-rate environment override in v1.0.x.

See [docs/configuration.md](docs/configuration.md) and [templates/sherlock.toml](templates/sherlock.toml).

## Upgrading

Source install:

```bash
git pull
cargo install --path . --force
sherlock doctor --database
```

Release binary: replace the executable, then `sherlock doctor --database`.

## Uninstall

```bash
cargo uninstall sherlock-homes
```

User data (Evidence Vault, `sherlock.toml`) remains in the platform data directory.

## Building from source

Requires Rust 1.74+ (see `Cargo.toml` `rust-version`). SQLite is bundled via `rusqlite` `bundled`.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md).

## Known limitations

- Not 100% detector coverage
- Optional engines are stubs except Nuclei JSONL import
- Termux is designed, not maintainer-tested on device
- crates.io package is not published
- GitHub repository URL must be set by the maintainer (`Cargo.toml` `repository` is unset until then)

## License

MIT — see [LICENSE](LICENSE).
