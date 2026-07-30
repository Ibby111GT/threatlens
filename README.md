# ThreatLens — IOC Enrichment & Triage

A threat-intelligence tool that classifies indicators of compromise (IOCs),
scores them with offline heuristics, maps them to MITRE ATT&CK techniques, and
can optionally enrich them with live VirusTotal reputation. Runs fully offline
with **no API keys required** — pure Python standard library, zero dependencies.

## Features

- IOC type auto-detection: IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256 hashes, emails, CVEs
- Offline heuristic threat scoring (0–100) with CRITICAL / HIGH / MEDIUM / LOW / INFO bands
- DGA (domain generation algorithm) detection via entropy + consonant-run + vowel-ratio analysis
- Suspicious TLD flagging (`.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, `.top`, …)
- Private / RFC1918 address recognition (down-weighted as internal)
- MITRE ATT&CK technique and tactic mapping
- Optional VirusTotal API v3 reputation lookups (`--vt-key`) folded into the score
- Best-effort DNS resolution (`--resolve`)
- JSON output per line (`--json`) and batch JSON export to file (`--output`) for SIEM ingestion
- Demo mode with a pre-loaded sample IOC set

## Usage

```bash
# Demo mode (no input, no API keys needed)
python threat_intel.py --demo

# Analyse a single IOC
python threat_intel.py --ioc 8.8.8.8
python threat_intel.py --ioc kq3v9z7x1p0m4w.tk        # flagged: DGA + suspicious TLD
python threat_intel.py --ioc 44d88612fea8a8f36de82e1278abb02f

# Resolve DNS while enriching
python threat_intel.py --ioc example.com --resolve

# Batch enrich from a file (one IOC per line; blank/# lines skipped)
python threat_intel.py --file iocs.txt

# Export results to a JSON file
python threat_intel.py --demo --output results.json

# Add live VirusTotal reputation (optional, free key)
python threat_intel.py --ioc 1.2.3.4 --vt-key YOUR_VT_API_KEY
```

## Scoring

Each IOC starts from a type-based base score, adjusted by heuristics:

| Signal | Effect |
|--------|--------|
| Suspicious TLD | +20 |
| DGA-like domain | +25 |
| Private / internal IP | forced low (10) |
| VirusTotal malicious hits | raises to ≥ 70 |
| VirusTotal suspicious hits | raises to ≥ 45 |

Bands: `>=80 CRITICAL`, `>=60 HIGH`, `>=35 MEDIUM`, `>=15 LOW`, else `INFO`.

## MITRE ATT&CK Coverage

The bundled offline table includes techniques across Execution, Defense Evasion,
Credential Access, Discovery, Initial Access, Command and Control, Exfiltration,
Reconnaissance, Persistence, and Impact — e.g. T1071 (C2), T1566 (Phishing),
T1110 (Brute Force), T1595 (Active Scanning), T1505.003 (Web Shell), T1486
(Ransomware). IOCs are mapped to techniques via their most likely tactic.

## VirusTotal (Optional)

ThreatLens works fully offline. To enable live lookups, get a free key at
virustotal.com (free tier: 500 requests/day) and pass `--vt-key`. Any lookup
failure (rate limit, network, unknown IOC) degrades gracefully back to the
offline heuristic score.

VirusTotal enrichment covers **IPs, domains, and file hashes (MD5/SHA-1/SHA-256)
only** — the VT v3 collections ThreatLens queries. URL and email IOCs are not
looked up; for those the tool notes that VT is not implemented for the type and
keeps the offline heuristic score.

## Testing

```bash
python -m unittest discover -s tests -v
```

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)
- VirusTotal API key optional
