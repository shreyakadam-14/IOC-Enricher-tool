"""enrich_iocs.py: check a list of IPs against AbuseIPDB.

Usage:
    python enrich_iocs.py ips.txt > results.csv
"""
import csv
import ipaddress
import os
import sys
import time

import requests
from dotenv import load_dotenv

load_dotenv()  # key lives in .env, never in the repo
API_KEY = os.environ.get("ABUSEIPDB_KEY")
URL = "https://api.abuseipdb.com/api/v2/check"


def check(ip):
    r = requests.get(
        URL,
        headers={"Key": API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    r.raise_for_status()
    d = r.json()["data"]
    return d["abuseConfidenceScore"], d["countryCode"], d["totalReports"]


def read_ips(path):
    """Read one IP per line; skip blanks, comments, invalid and duplicate IPs."""
    seen, ips = set(), []
    with open(path) as f:
        for line in f:
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"skipping invalid IP: {ip}", file=sys.stderr)
                continue
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


def main():
    if not API_KEY:
        sys.exit("ABUSEIPDB_KEY not set. Copy .env.example to .env and add your key.")
    if len(sys.argv) != 2:
        sys.exit("usage: python enrich_iocs.py ips.txt > results.csv")

    writer = csv.writer(sys.stdout)
    writer.writerow(["ip", "score", "country", "reports"])

    for ip in read_ips(sys.argv[1]):
        try:
            score, country, reports = check(ip)
            writer.writerow([ip, score, country, reports])
        except requests.HTTPError as e:
            if e.response.status_code == 429:
                sys.exit("Rate limit hit (free tier is 1,000 checks/day). Stopping.")
            print(f"{ip}: HTTP error {e.response.status_code}", file=sys.stderr)
        except requests.RequestException as e:
            print(f"{ip}: request failed ({e})", file=sys.stderr)
        time.sleep(0.2)  # be polite to the API


if __name__ == "__main__":
    main()
