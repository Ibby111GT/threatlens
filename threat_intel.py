#!/usr/bin/env python3
"""
ThreatLens - Threat Intelligence & IOC Enrichment Platform
-----------------------------------------------------------
Enriches indicators of compromise (IPs, domains, file hashes) using
VirusTotal, AbuseIPDB, and MITRE ATT&CK mappings. Works offline in demo mode.

Usage:
    python threat_intel.py --ioc 8.8.8.8
    python threat_intel.py --ioc malicious-domain.com
    python threat_intel.py --file iocs.txt
    python threat_intel.py --demo
"""

import re
import sys
import json
import time
import hashlib
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"


MITRE_ATTACK_MAP = {
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "phishing": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    "c2": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "scanning": {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    "malware": {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "webshell": {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
}

THREAT_CATEGORIES = {
    "malware": ["trojan", "ransomware", "backdoor", "rat", "banker", "stealer"],
    "c2": ["cobalt strike", "metasploit", "empire", "havoc", "sliver", "c2", "command"],
    "phishing": ["phish", "credential", "login", "bank", "paypal", "verify"],
    "scanning": ["scan", "probe", "masscan", "shodan", "recon", "nmap"],
    "brute_force": ["brute", "dictionary", "spray", "credential stuffing"],
}

MALICIOUS_TLD = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}

DEMO_IOC_DATA = {
    "192.168.1.100": {
        "type": "ip", "threat_score": 85, "country": "RU",
        "reports": 47, "categories": ["brute_force", "scanning"],
        "tags": ["ssh-brute-force", "port-scanner"],
        "last_seen": "2024-12-09",
    },
    "malware-c2.example.com": {
        "type": "domain", "threat_score": 95, "registrar": "NameSilo",
        "reports": 128, "categories": ["c2", "malware"],
        "tags": ["cobalt-strike", "c2-server", "malware-distribution"],
        "last_seen": "2024-12-10",
    },
    "d41d8cd98f00b204e9800998ecf8427e": {
        "type": "hash", "threat_score": 72, "file_type": "PE32",
        "reports": 23, "categories": ["malware"],
        "tags": ["trojan", "infostealer"],
        "last_seen": "2024-11-28",
    },
}


@dataclass
class IOCResult:
    ioc: str
    ioc_type: IOCType
    threat_score: int
    risk_level: str
    categories: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    geo_country: Optional[str] = None
    reports: int = 0
    last_seen: Optional[str] = None
    source: str = "offline"
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "ioc": self.ioc, "type": self.ioc_type.value,
            "threat_score": self.threat_score, "risk_level": self.risk_level,
            "categories": self.categories, "tags": self.tags,
            "mitre": self.mitre_techniques, "country": self.geo_country,
            "reports": self.reports, "last_seen": self.last_seen,
        }


def detect_ioc_type(ioc: str) -> IOCType:
    ioc = ioc.strip()
    ip_pattern = re.compile(r"^(d{1,3}\.){3}d{1,3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
    domain_pattern = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$")
    if ip_pattern.match(ioc): return IOCType.IP
    if hash_pattern.match(ioc): return IOCType.HASH
    if domain_pattern.match(ioc): return IOCType.DOMAIN
    return IOCType.UNKNOWN


def score_to_risk(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def map_mitre_techniques(categories: list) -> list:
    techniques = []
    for cat in categories:
        if cat in MITRE_ATTACK_MAP:
            techniques.append(MITRE_ATTACK_MAP[cat])
    return techniques


def heuristic_score(ioc: str, ioc_type: IOCType) -> tuple:
    """Offline heuristic scoring when no API keys are available."""
    score = 0
    categories = []
    tags = []

    if ioc_type == IOCType.IP:
        octets = list(map(int, ioc.split(".")))
        private = (
            (octets[0] == 10) or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)
        )
        if private:
            tags.append("private-ip")
        else:
            score += 20
            tags.append("public-ip")

    elif ioc_type == IOCType.DOMAIN:
        tld = "." + ioc.rsplit(".", 1)[-1].lower()
        if tld in MALICIOUS_TLD:
            score += 40
            tags.append(f"suspicious-tld:{tld}")
            categories.append("malware")
        if len(ioc) > 30:
            score += 15
            tags.append("long-domain")
        digit_ratio = sum(c.isdigit() for c in ioc.split(".")[0]) / max(len(ioc.split(".")[0]), 1)
        if digit_ratio > 0.4:
            score += 20
            tags.append("high-digit-ratio")
        if re.search(r"[0-9a-f]{8,}", ioc.split(".")[0]):
            score += 25
            tags.append("dga-like")
            categories.append("c2")

    elif ioc_type == IOCType.HASH:
        score += 30
        tags.append("file-hash")

    return min(score, 100), categories, tags


def enrich_offline(ioc: str, ioc_type: IOCType) -> IOCResult:
    """Enrich IOC using offline heuristics and demo data."""
    if ioc in DEMO_IOC_DATA:
        data = DEMO_IOC_DATA[ioc]
        score = data["threat_score"]
        categories = data["categories"]
        tags = data["tags"]
    else:
        score, categories, tags = heuristic_score(ioc, ioc_type)

    mitre = map_mitre_techniques(categories)
    return IOCResult(
        ioc=ioc, ioc_type=ioc_type,
        threat_score=score, risk_level=score_to_risk(score),
        categories=categories, tags=tags,
        mitre_techniques=mitre,
        source="offline_heuristic",
    )


def enrich_virustotal(ioc: str, ioc_type: IOCType, api_key: str) -> Optional[IOCResult]:
    """Query VirusTotal API v3."""
    endpoints = {
        IOCType.IP: f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        IOCType.DOMAIN: f"https://www.virustotal.com/api/v3/domains/{ioc}",
        IOCType.HASH: f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = endpoints.get(ioc_type)
    if not url: return None
    try:
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        score = min(100, int((malicious / total) * 100) + malicious * 2)
        categories = list(attrs.get("categories", {}).values())[:3]
        tags = attrs.get("tags", [])[:5]
        mitre = map_mitre_techniques(categories)
        return IOCResult(
            ioc=ioc, ioc_type=ioc_type,
            threat_score=score, risk_level=score_to_risk(score),
            categories=categories, tags=tags,
            mitre_techniques=mitre,
            reports=malicious,
            source="virustotal",
            raw=attrs,
        )
    except Exception as e:
        print(f"  [!] VirusTotal error: {e}")
        return None


def enrich_ioc(ioc: str, vt_key: Optional[str] = None) -> IOCResult:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == IOCType.UNKNOWN:
        print(f"[!] Cannot determine IOC type for: {ioc}")
        return IOCResult(ioc=ioc, ioc_type=IOCType.UNKNOWN,
                        threat_score=0, risk_level="INFO")
    if vt_key:
        result = enrich_virustotal(ioc, ioc_type, vt_key)
        if result:
            return result
    return enrich_offline(ioc, ioc_type)


def print_result(result: IOCResult):
    risk_icons = {"CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]",
                 "LOW": "[.  ]", "INFO": "[   ]"}
    icon = risk_icons.get(result.risk_level, "[?]")
    sep = "-" * 55
    print(f"\n{sep}")
    print(f"  IOC       : {result.ioc}")
    print(f"  Type      : {result.ioc_type.value.upper()}")
    print(f"  Risk      : {icon} {result.risk_level}  (score: {result.threat_score}/100)")
    print(f"  Source    : {result.source}")
    if result.reports:
        print(f"  Reports   : {result.reports} malicious detections")
    if result.geo_country:
        print(f"  Country   : {result.geo_country}")
    if result.categories:
        print(f"  Categories: {", ".join(result.categories)}")
    if result.tags:
        print(f"  Tags      : {" | ".join(result.tags[:5])}")
    if result.mitre_techniques:
        print("  MITRE ATT&CK:")
        for t in result.mitre_techniques:
            print(f"    {t["id"]:<12} {t["tactic"]:<25} {t["name"]}")
    print(sep)


def run_demo():
    demo_iocs = [
        "192.168.1.100",
        "malware-c2.example.com",
        "d41d8cd98f00b204e9800998ecf8427e",
        "8.8.8.8",
        "ab3f9x12cd78ef.xyz",
    ]
    print("\n  ThreatLens Demo - IOC Enrichment")
    print("  " + "=" * 52)
    for ioc in demo_iocs:
        result = enrich_ioc(ioc)
        print_result(result)
    print()


def main():
    parser = argparse.ArgumentParser(description="ThreatLens - IOC enrichment and threat intelligence")
    parser.add_argument("--ioc", help="Single IOC to enrich (IP, domain, or hash)")
    parser.add_argument("--file", help="File with one IOC per line")
    parser.add_argument("--demo", action="store_true", help="Run with demo IOC data")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--output", help="Save results to JSON file")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    iocs = []
    if args.ioc:
        iocs = [args.ioc]
    elif args.file:
        try:
            with open(args.file) as f:
                iocs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
    else:
        parser.print_help()
        return

    results = []
    for ioc in iocs:
        print(f"[*] Enriching: {ioc}")
        result = enrich_ioc(ioc, vt_key=args.vt_key)
        print_result(result)
        results.append(result.to_dict())
        time.sleep(0.5)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"timestamp": datetime.now().isoformat(), "results": results}, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
