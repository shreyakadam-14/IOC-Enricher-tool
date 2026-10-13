"""enrich_iocs.py: check IPs (from a list or a raw log) against AbuseIPDB.

Usage:
    python enrich_iocs.py ips.txt -o results.csv
    python enrich_iocs.py auth.log --skip-private --min-score 25 -o results.json
"""
import argparse
import os
import sys

from dotenv import load_dotenv

import enricher


def main():
    p = argparse.ArgumentParser(description="Enrich IPs with AbuseIPDB")
    p.add_argument("input", help="text/log file containing IPs")
    p.add_argument("-o", "--output", default="results.csv", help="output file (.csv or .json)")
    p.add_argument("--skip-private", action="store_true", help="ignore private/reserved IPs")
    p.add_argument("--min-score", type=int, default=0, help="only keep score >= N")
    args = p.parse_args()

    load_dotenv()  # key lives in .env, never in the repo
    api_key = os.environ.get("ABUSEIPDB_KEY")
    if not api_key:
        sys.exit("ABUSEIPDB_KEY not set. Copy .env.example to .env and add your key.")

    ips = enricher.parse_ips(enricher.read_text(args.input), args.skip_private)
    if not ips:
        sys.exit("No valid IPs found in input.")

    results, errors = enricher.enrich_many(
        ips, api_key,
        on_progress=lambda i, n, ip: print(f"[{i}/{n}] {ip}", file=sys.stderr),
    )
    results = sorted((r for r in results if r["score"] >= args.min_score),
                     key=lambda r: r["score"], reverse=True)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        (enricher.write_json if args.output.lower().endswith(".json") else enricher.write_csv)(results, f)

    flagged = sum(r["verdict"] != "clean" for r in results)
    print(f"\nChecked {len(ips)} IPs, {flagged} flagged. Saved to {args.output}", file=sys.stderr)
    for ip, msg in errors:
        print(f"  {ip}: {msg}", file=sys.stderr)


if __name__ == "__main__":
    main()
