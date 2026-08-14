# Examples

```bash
sherlock scan https://127.0.0.1:3000 --mode safe --depth 3 --rate 2 --concurrency 4
sherlock hunt https://127.0.0.1:3000/api/health
sherlock crawl https://127.0.0.1:3000 --exclude "/logout"
sherlock inspect https://127.0.0.1:3000
sherlock case resume SH-260814-A7F2
sherlock report SH-260814-A7F2 --format pdf,html,json,sarif,markdown,csv --output ./reports
sherlock completion powershell
```
