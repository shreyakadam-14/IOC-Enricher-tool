# ioc-enricher

Enrich IP indicators of compromise (IOCs) with [AbuseIPDB](https://www.abuseipdb.com) threat intelligence.
Works as a **CLI** and as a **Streamlit web app**. Accepts a clean IP list *or* raw log text and extracts the IPs for you.

## Features
- Extracts and validates IPv4s from any text (SSH/Apache logs, alerts); dedupes; optional skip of private ranges
- Score, verdict (`clean` / `suspicious` / `malicious`), country, report count, ISP, usage type, last reported
- CSV or JSON output (JSON is ready to feed a SIEM / ticketing automation)
- Handles timeouts, HTTP errors and the free-tier rate limit (stops cleanly)
- Tested with `pytest` (API mocked, no key needed) and CI on every push
- Secret hygiene: key in `.env` (git-ignored) plus `gitleaks` scanning in CI

## Setup
```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt -r requirements-app.txt -r requirements-dev.txt
copy .env.example .env          # then paste your AbuseIPDB key
```

## Usage
```bash
python enrich_iocs.py ips.txt -o results.csv
python enrich_iocs.py auth.log --skip-private --min-score 25 -o results.json
streamlit run app.py
pytest
```

## Verdict thresholds
| Score | Verdict |
|-------|---------|
| 75-100 | malicious |
| 25-74 | suspicious |
| 0-24 | clean |

A score of 0 with many reports can still be legitimate (e.g. 8.8.8.8, Google DNS). Treat verdicts as triage hints, not final answers.

## Project layout
- `enricher.py` core logic (parsing, API calls, verdicts, output)
- `enrich_iocs.py` CLI
- `app.py` Streamlit UI
- `tests/` pytest suite, `.github/workflows/ci.yml` CI + secret scan

## Roadmap
- SQLite cache to save API quota, VirusTotal as a second source, domain/hash support, IPv6
