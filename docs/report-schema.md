# Report schema (JSON)

Root object:

```json
{
  "schema": "https://sherlock-homes.dev/schema/report-1.0.json",
  "case_id": "SH-260814-A7F2",
  "target": "https://example.com",
  "generated": "RFC3339",
  "mode": "safe",
  "findings": []
}
```

Each finding includes: `id`, `case_id`, `title`, `severity`, `confidence`, `cwe`, `owasp`, `cvss`, `method`, `endpoint`, `parameter`, `detector`, `source_engine`, `description`, `evidence_summary`, `remediation`, `fingerprint`, `status`.

Secrets in evidence fields are redacted.
