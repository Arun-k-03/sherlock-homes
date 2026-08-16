## Unreleased

No unreleased changes yet.

## 1.0.1 - 2026-08-16

### Security

- Upgraded the PDF reporting engine from `printpdf 0.7.0` to `printpdf 0.11.2`.
- Upgraded transitive `lopdf` from vulnerable `0.31.0` to `0.44.0`.
- Resolved `RUSTSEC-2026-0187`.
- Preserved PDF report generation using the new operation-based printpdf API.
- Evidence and secret redaction hardening for credential-like material.

### Fixed

- Minified JavaScript API-key aliases no longer generate high-confidence secret false positives.
- JavaScript string literals are no longer automatically treated as same-origin crawl targets.
- RPC-style API paths are not blindly crawled.
- Fixed duplicated HTTP method output such as `GET GET /path`.
- Fixed finding identity collisions across independent cases.
- Fixed Cargo packaging so all report modules are included.

### Hardened

- Added crawler request, page, depth, queue, and child budgets.
- Added generated-artifact and unsafe-path crawl guards.
- Added status-code and content-type-aware detector behavior.
- Improved host-level finding correlation and endpoint evidence sampling.
- Added migration upgrade, idempotence, and legacy-schema regression coverage.
- Added detector accuracy ground-truth tests.

### Reports

- Added PDF, HTML, JSON, JSONL, SARIF, Markdown, and CSV report support.
- Added public finding IDs and affected-endpoint reporting.
- Corrected SARIF repository metadata.

### Project

- Added Windows, Linux, and macOS CI.
- Added RustSec dependency auditing.
- Added GitHub release packaging.
- Added contribution, security, code-of-conduct, development, configuration, migration, and Termux documentation.
- Added issue and pull-request templates.

### Validation

- Windows local GNU validation passed.
- Ubuntu GitHub Actions passed.
- Windows GitHub Actions passed.
- macOS GitHub Actions passed.
- RustSec blocking vulnerability audit passed.
- 90 automated tests passed.