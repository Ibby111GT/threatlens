# ThreatLens — Threat Intelligence Platform

An IOC enrichment and correlation tool that integrates with VirusTotal and maps findings
to MITRE ATT&CK techniques. Works in fully offline demo mode — no API keys required.

## Features

- IOC type auto-detection: IPv4 addresses, domains, MD5/SHA1/SHA256 hashes
- VirusTotal API v3 integration (optional — requires free API key)
- Offline heuristic scoring when no API keys are provided
- MITRE ATT&CK technique and tactic mapping
- Threat scoring 0-100 with CRITICAL / HIGH / MEDIUM / LOW / INFO classification
- DGA (domain generation algorithm) detection heuristics
- Suspicious TLD flagging (.tk, .ml, .xyz, .top, etc.)
- Batch IOC enrichment from file
- JSON export for SIEM ingestion
- Demo mode with pre-loaded malicious IOCs

## Usage

```bash
# Demo mode (no API keys needed)
python threat_intel.py --demo

# Enrich a single IP
python threat_intel.py --ioc 192.168.1.100

# Enrich a domain
python threat_intel.py --ioc malicious-domain.com

# Enrich a file hash
python threat_intel.py --ioc d41d8cd98f00b204e9800998ecf8427e

# Batch enrich from file (one IOC per line)
python threat_intel.py --file iocs.txt

# With VirusTotal API key
python threat_intel.py --ioc 8.8.8.8 --vt-key YOUR_API_KEY

# Export to JSON
python threat_intel.py --demo --output results.json
```

## MITRE ATT&CK Coverage

| Category | Technique ID | Tactic |
|----------|-------------|--------|
| brute_force | T1110 | Credential Access |
| phishing | T1566 | Initial Access |
| c2 | T1071 | Command and Control |
| exfiltration | T1041 | Exfiltration |
| scanning | T1595 | Reconnaissance |
| malware | T1204 | Execution |
| ransomware | T1486 | Impact |
| webshell | T1505.003 | Persistence |

## API Keys (Optional)

ThreatLens works fully offline without any API keys.
To enable live VirusTotal lookups, get a free API key at virustotal.com:

```bash
python threat_intel.py --ioc 1.2.3.4 --vt-key YOUR_VT_API_KEY
```

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)
- VirusTotal API key optional (free tier: 500 requests/day)
