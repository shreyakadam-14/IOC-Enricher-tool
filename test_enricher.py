import io

import pytest
import responses

import enricher


def api_body(score=90, country="RU", reports=40):
    return {"data": {"abuseConfidenceScore": score, "countryCode": country,
                     "totalReports": reports, "isp": "ExampleISP",
                     "usageType": "Data Center/Web Hosting/Transit",
                     "lastReportedAt": "2026-10-01T10:00:00+00:00"}}


@pytest.mark.parametrize("score,expected", [
    (0, "clean"), (24, "clean"), (25, "suspicious"), (74, "suspicious"),
    (75, "malicious"), (100, "malicious"),
])
def test_verdict_boundaries(score, expected):
    assert enricher.verdict(score) == expected


def test_parse_ips_from_log_dedupes_and_validates():
    log = ("Failed password for root from 185.220.101.4 port 22\n"
           "bad address 999.1.1.1\n"
           "Failed password from 185.220.101.4 port 22\n"
           "ok 8.8.8.8\n")
    assert enricher.parse_ips(log) == ["185.220.101.4", "8.8.8.8"]


def test_parse_ips_skip_private():
    assert enricher.parse_ips("10.0.0.5 192.168.1.1 8.8.8.8", skip_private=True) == ["8.8.8.8"]


def test_decode_bytes_handles_utf16():
    raw = "8.8.8.8\n1.1.1.1\n".encode("utf-16")
    assert enricher.parse_ips(enricher.decode_bytes(raw)) == ["8.8.8.8", "1.1.1.1"]


@responses.activate
def test_check_parses_response_and_sends_key():
    responses.add(responses.GET, enricher.API_URL, json=api_body(), status=200)
    r = enricher.check("1.2.3.4", "secret-key")
    assert r["score"] == 90 and r["verdict"] == "malicious" and r["country"] == "RU"
    assert responses.calls[0].request.headers["Key"] == "secret-key"


@responses.activate
def test_check_handles_missing_country():
    responses.add(responses.GET, enricher.API_URL, json=api_body(country=None), status=200)
    assert enricher.check("1.2.3.4", "k")["country"] == ""


@responses.activate
def test_check_rate_limit_raises():
    responses.add(responses.GET, enricher.API_URL, status=429)
    with pytest.raises(enricher.RateLimitError):
        enricher.check("1.2.3.4", "k")


@responses.activate
def test_enrich_many_collects_errors_and_continues():
    responses.add(responses.GET, enricher.API_URL, json=api_body(), status=200)
    responses.add(responses.GET, enricher.API_URL, status=500)
    results, errors = enricher.enrich_many(["1.1.1.1", "2.2.2.2"], "k", delay=0)
    assert len(results) == 1 and errors == [("2.2.2.2", "HTTP 500")]


@responses.activate
def test_enrich_many_stops_on_rate_limit():
    responses.add(responses.GET, enricher.API_URL, json=api_body(), status=200)
    responses.add(responses.GET, enricher.API_URL, status=429)
    results, errors = enricher.enrich_many(["1.1.1.1", "2.2.2.2", "3.3.3.3"], "k", delay=0)
    assert len(results) == 1 and len(errors) == 1
    assert len(responses.calls) == 2  # third IP never requested


def test_write_csv_has_no_blank_lines():
    rows = [{f: "x" for f in enricher.FIELDS}] * 2
    buf = io.StringIO(newline="")
    enricher.write_csv(rows, buf)
    lines = buf.getvalue().splitlines()
    assert len(lines) == 3 and all(lines)
