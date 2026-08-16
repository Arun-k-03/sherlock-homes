# Configuration

User file: platform data directory `sherlock.toml` (`sherlock config path`).

## Precedence (as implemented)

1. Built-in defaults (`AppConfig::default`)
2. User config file (if present)
3. CLI flags on `scan` / `hunt` / `crawl` (`--mode`, `--rate`, `--concurrency`, `--depth`, `--timeout`, `--allow`, `--exclude`)

There is no environment-variable override for scan rate or depth in v1.0.x.

Environment that **is** honored:

| Variable | Effect |
|---|---|
| `NO_COLOR` | Disable color |
| `RUST_LOG` | Tracing filter (logs go to stderr) |

## Scan budgets

| Key | Default | Notes |
|---|---|---|
| `scan.mode` | safe | passive / safe / full / api |
| `scan.rate` | 5 | requests per second |
| `scan.concurrency` | 10 | |
| `scan.depth` | 5 | max crawl depth |
| `scan.timeout_seconds` | 15 | |
| `scan.max_response_bytes` | 2000000 | |
| `scan.max_redirects` | 8 | |
| `scan.max_pages` | 250 | crawler page budget |
| `scan.max_requests` | 500 | crawler request budget |
| `scan.max_queue` | 1000 | |
| `scan.max_children_per_parent` | 80 | per-directory fan-out |

When a budget is hit, Sherlock emits a `[GUARD]` warning and continues analysis on evidence already collected.

Invalid TOML produces a configuration error (non-zero exit), not a panic.
