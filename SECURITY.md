# Security policy

Sherlock Homes is a security testing tool. Defects in Sherlock itself can cause false confidence, missed findings, or unsafe crawl behavior.

## How to report a vulnerability in Sherlock Homes

Prefer **GitHub private vulnerability reporting** on this repository (Security → Report a vulnerability) once the project is hosted.

If that feature is not enabled yet, open a **private** maintainer channel. **TODO (maintainer):** enable GitHub private vulnerability reporting. Do not invent a public security email.

Include:

- Sherlock version (`sherlock version`)
- OS / architecture
- Whether the issue is in the scanner, vault/migrations, reports, or CLI
- Minimal **localhost** reproduction (no third-party production targets)
- Impact (false positive HIGH/CONFIRMED, crawl explosion, secret leakage in reports, etc.)

## Please do not

- Publish a full exploit for a Sherlock defect before we can ship a fix
- Attach real credentials or production dumps
- Ask us to attack systems you do not own

## Scope

In scope: Sherlock Homes source, CLI, vault, reports, detectors, crawler.

Out of scope: vulnerabilities in optional third-party engines (Nuclei, ZAP, …) — report those upstream.
