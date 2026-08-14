# Report schema (machine output)

Identifier: `schema` = `sherlock-homes.report.v1`

Additive fields may appear in later 1.x releases. Do not assume field removal without a major version.

```json
{
  "schema": "sherlock-homes.report.v1",
  "case_id": "SH-260814-A7F2",
  "target": "https://example.com",
  "generated": "RFC3339",
  "mode": "safe",
  "findings": []
}
```

Each finding includes: `id`, `internal_id`, `display_id`, `case_id`, `title`, `severity`, `confidence`, `cwe`, `owasp`, `cvss`, `method`, `endpoint`, `parameter`, `detector`, `source_engine`, `description`, `evidence_summary`, `remediation`, `fingerprint`, `status`, `host`, `affected_endpoints`.

CLI/PDF/HTML may **sample** affected endpoints. The JSON array is the full list.

Secrets in evidence fields are redacted.

When `--format json` / `jsonl` / `sarif` is requested for commands that support machine stdout, banners and animations must not appear on stdout. Diagnostics go to stderr.
