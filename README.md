# ioc-enricher

Small Python tool that checks a list of IP addresses against AbuseIPDB and outputs a CSV with abuse confidence score, country and report count.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then paste your free AbuseIPDB API key
```

## Run
```bash
python enrich_iocs.py ips.txt > results.csv
```

## Security notes
- API key is loaded from `.env` and `.env` is in `.gitignore`, so it is never committed.
- Input IPs are validated and deduplicated; timeouts and rate limits (HTTP 429) are handled.

## Ideas to extend
- Sort/flag IPs with score >= 50
- Add VirusTotal as a second source
- Read IPs from a log file with regex
