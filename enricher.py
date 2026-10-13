"""Core logic for ioc-enricher: IP extraction, AbuseIPDB lookups, verdicts, output."""
import csv
import ipaddress
import json
import re
import time

import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FIELDS = ["ip", "score", "verdict", "country", "reports", "isp", "usage_type", "last_reported"]


class RateLimitError(Exception):
    """Raised when AbuseIPDB answers HTTP 429 (daily quota used up)."""


def verdict(score):
    """Map an abuse confidence score (0-100) to a simple label."""
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def decode_bytes(raw):
    """Decode bytes from UTF-8 or UTF-16 (PowerShell/Notepad often save UTF-16)."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8-sig", errors="ignore")


def read_text(path):
    with open(path, "rb") as f:
        return decode_bytes(f.read())


def parse_ips(text, skip_private=False):
    """Extract unique, valid IPv4 addresses from any text (a list or a raw log)."""
    seen, ips = set(), []
    for candidate in IPV4_RE.findall(text):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue  # e.g. 999.1.1.1
        if skip_private and not ip.is_global:
            continue
        if candidate not in seen:
            seen.add(candidate)
            ips.append(candidate)
    return ips


def check(ip, api_key, max_age_days=90, timeout=10):
    """Look up one IP and return a flat dict (see FIELDS)."""
    r = requests.get(
        API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=timeout,
    )
    if r.status_code == 429:
        raise RateLimitError("AbuseIPDB rate limit reached")
    r.raise_for_status()
    d = r.json()["data"]
    score = d["abuseConfidenceScore"]
    return {
        "ip": ip,
        "score": score,
        "verdict": verdict(score),
        "country": d.get("countryCode") or "",
        "reports": d["totalReports"],
        "isp": d.get("isp") or "",
        "usage_type": d.get("usageType") or "",
        "last_reported": d.get("lastReportedAt") or "",
    }


def enrich_many(ips, api_key, delay=0.2, on_progress=None):
    """Check many IPs. Returns (results, errors); stops early on rate limit."""
    results, errors = [], []
    for i, ip in enumerate(ips, 1):
        try:
            results.append(check(ip, api_key))
        except RateLimitError:
            errors.append((ip, "rate limit reached, stopped"))
            break
        except requests.HTTPError as e:
            errors.append((ip, f"HTTP {e.response.status_code}"))
        except requests.RequestException as e:
            errors.append((ip, f"request failed: {e}"))
        if on_progress:
            on_progress(i, len(ips), ip)
        if delay:
            time.sleep(delay)
    return results, errors


def write_csv(results, fileobj):
    """fileobj must be opened with newline='' (avoids blank lines on Windows)."""
    writer = csv.DictWriter(fileobj, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(results)


def write_json(results, fileobj):
    json.dump(results, fileobj, indent=2)
