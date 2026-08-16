# Changelog

All notable changes to Sherlock Homes are documented here. Versioning follows [Semantic Versioning](https://semver.org/):

- `1.0.x` — bug fixes and hardening that do not break CLI/schema
- `1.x.0` — backward-compatible features
- `2.0.0` — breaking CLI, machine-output, or vault schema changes

## Unreleased

- Crawler request/page/queue budgets and generated-artifact path guards
- JavaScript string literals are clues, not automatic same-origin crawl targets
- Clue UI uses a single HTTP method (no `GET GET /path`)
- Host-level findings sample endpoints in CLI/PDF/HTML; full list stays in the vault
- Header detectors apply to successful document-like responses, not 4xx/binary assets
- Local detector lab + `target/detector-benchmark.json`
- `sherlock findings --format pdf` rejected with guidance to `sherlock report`
- Open-source docs, issue templates, and release packaging notes

## 1.0.0

- Initial public-intended engine: CLI, vault schema 001→002, reports, optional engine stubs
