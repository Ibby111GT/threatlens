#!/usr/bin/env python3
"""
threat_intel.py -- ThreatLens CLI entry point.

Parses one or more IOC values (IPs, domains, hashes, CVEs, emails),
classifies them, and optionally enriches with MITRE ATT&CK context.

Usage:
    python threat_intel.py --demo
    python threat_intel.py --ioc 8.8.8.8
    python threat_intel.py --ioc malicious-domain.com --resolve
    python threat_intel.py --file iocs.txt
    python threat_intel.py --file iocs.txt --json
"""

import argparse
import json
import sys
from pathlib import Path

from lib.enricher import enrich_batch
from lib.ioc import parse_ioc


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"

# Sample IOCs used by --demo so the tool runs with zero setup and no API keys.
_DEMO_IOCS = [
    "8.8.8.8",
    "185.220.101.34",
    "kq3v9z7x1p0m4w.tk",
    "44d88612fea8a8f36de82e1278abb02f",
    "cve-2021-44228",
    "phish@secure-login-update.ml",
]

_TYPE_COLOUR = {
    "ip":     _RED,
    "domain": _YELLOW,
    "url":    _YELLOW,
    "sha256": _CYAN,
    "sha1":   _CYAN,
    "md5":    _CYAN,
    "email":  _GREEN,
    "cve":    _RED,
}


def _colour(ioc_type: str, text: str) -> str:
    c = _TYPE_COLOUR.get(ioc_type, "")
    return f"{c}{text}{_RESET}" if c else text


_SEVERITY_COLOUR = {
    "CRITICAL": _RED,
    "HIGH":     _RED,
    "MEDIUM":   _YELLOW,
    "LOW":      _GREEN,
    "INFO":     _CYAN,
}


def _record(enriched) -> dict:
    ioc = enriched.ioc
    return {
        "value":    ioc.value,
        "type":     ioc.ioc_type,
        "score":    enriched.score,
        "severity": enriched.severity,
        "resolved": enriched.resolved_host,
        "techniques": [
            {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
            for t in enriched.techniques
        ],
        "notes": enriched.notes,
    }


def print_result(enriched, use_json: bool = False) -> None:
    ioc = enriched.ioc
    if use_json:
        print(json.dumps(_record(enriched)))
        return

    label = _colour(ioc.ioc_type, ioc.value)
    sev_c = _SEVERITY_COLOUR.get(enriched.severity, "")
    print(f"{_BOLD}[{ioc.ioc_type.upper()}]{_RESET} {label}")
    print(f"  score    : {sev_c}{enriched.score}/100  {enriched.severity}{_RESET}")
    if enriched.resolved_host:
        print(f"  resolved : {enriched.resolved_host}")
    if enriched.techniques:
        print(f"  ATT&CK   :")
        for t in enriched.techniques[:3]:  # cap at 3 for readability
            print(f"    {t.technique_id}  {t.name}  [{t.tactic}]")
    for note in enriched.notes:
        print(f"  note     : {note}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatLens -- IOC classification and MITRE enrichment",
    )
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--ioc",  metavar="VALUE", help="Single IOC to analyse")
    src.add_argument("--file", metavar="PATH",  help="File with one IOC per line")
    parser.add_argument("--demo", action="store_true",
                        help="Analyse a built-in set of sample IOCs (no input needed)")
    parser.add_argument("--resolve", action="store_true",
                        help="Attempt DNS resolution for IPs and domains")
    parser.add_argument("--vt-key", dest="vt_key", metavar="KEY", default=None,
                        help="VirusTotal API key for live reputation (optional)")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="Write all results to a JSON file (SIEM-friendly)")
    parser.add_argument("--json", dest="use_json", action="store_true",
                        help="Output each result as a JSON object")
    args = parser.parse_args()

    if args.demo:
        values = list(_DEMO_IOCS)
    elif args.ioc:
        values = [args.ioc]
    elif args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"error: {args.file} not found", file=sys.stderr)
            sys.exit(1)
        values = p.read_text().splitlines()
    else:
        parser.error("one of --demo, --ioc, or --file is required")

    results = enrich_batch(values, resolve=args.resolve, vt_key=args.vt_key)
    if not results:
        print("No valid IOCs found.", file=sys.stderr)
        sys.exit(1)

    for r in results:
        print_result(r, use_json=args.use_json)

    if args.output:
        Path(args.output).write_text(
            json.dumps([_record(r) for r in results], indent=2)
        )
        print(f"[+] Wrote {len(results)} record(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
