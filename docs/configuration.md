# Configuration reference

Config file: platform data directory `sherlock.toml` (`sherlock config path`).

| Key | Default | Notes |
|-----|---------|-------|
| ui.mode | classic | minimal / classic / cinematic |
| ui.animations | true | disabled automatically for `--format json` |
| scan.mode | safe | passive / safe / full / api |
| scan.rate | 5 | requests per second |
| scan.concurrency | 10 | semaphore bound |
| scan.depth | 5 | crawl depth |
| scan.timeout_seconds | 15 | per request |
| reports.default_formats | pdf,html,json | |
| engines.* | auto | skip if binary missing |

Environment: `NO_COLOR` disables color. Tracing via `RUST_LOG`.
