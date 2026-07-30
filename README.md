# ThreatLens — IOC Enrichment & Triage

[![CI](https://github.com/Ibby111GT/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/Ibby111GT/threatlens/actions/workflows/ci.yml)

A threat-intelligence tool that classifies indicators of compromise (IOCs),
scores them with offline heuristics, maps them to MITRE ATT&CK techniques, and
can optionally enrich them with live VirusTotal reputation. Runs fully offline
with **no API keys required** — pure Python standard library, zero dependencies.

## Features

- IOC type auto-detection: IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256 hashes, emails, CVEs
- Offline heuristic threat scoring (0–100) with CRITICAL / HIGH / MEDIUM / LOW / INFO bands
- DGA (domain generation algorithm) detection via entropy + consonant-run + vowel-ratio analysis
- Suspicious TLD flagging (`.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, `.top`, …)
- Internal-address recognition for IPv4 **and** IPv6 — private, loopback, and link-local addresses down-weighted
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

## How it works (plain English)

*For readers who don't work in security.*

**What an IOC is.** An *indicator of compromise* is a concrete artefact left
behind when something bad happens — an IP address malware phoned home to, a
domain in a phishing link, the fingerprint (hash) of a malicious file, an
attacker's email address, or a vulnerability ID (CVE). ThreatLens takes a pile
of these, works out what kind each one is, and gives each a rough risk score so
a human knows what to look at first.

**Where the score comes from.** By default everything runs on your own machine
with no lookups at all. The score starts from how dangerous that *type* of
indicator tends to be, then simple local rules nudge it: a domain on a
throwaway TLD like `.tk` gets bumped up; a domain whose name looks
machine-generated — long, random-looking, few vowels — gets bumped up more; an
address that is clearly internal (a private range, or a loopback like
`127.0.0.1` / `::1`) is pushed right down, because it is not an external threat.

**The score is a triage hint, not a verdict.** A high number means "look at
this first", *not* "this is confirmed malicious". A low number means "probably
not worth your time", *not* "provably safe". The heuristics are deliberately
simple: they will both miss real threats and flag harmless things. Treat the
output as a prioritised worklist for an analyst, never as a final answer.

**An optional second opinion.** If you have a free VirusTotal key you can pass
`--vt-key` to fold in how many antivirus engines currently flag an indicator.
That step is optional, needs a network connection, and only covers IPs,
domains, and file hashes — URLs and email addresses keep their offline score.

**Try it.** Run `python threat_intel.py --demo`. It scores a built-in set of
example indicators — from a clean public DNS server to a DGA-style phishing
domain — so you can see the output with no input, no key, and no network.

## Limitations

- **Scores are triage hints, not verdicts.** They rank indicators for human
  review. A high score is "check this first", not proof of malice; a low score
  is not a clean bill of health.
- **The heuristics are offline and coarse.** DGA detection is entropy /
  consonant-run / vowel-ratio based, so it will misjudge short, foreign-language,
  or deliberately word-like malicious domains, and can flag legitimate
  high-entropy hostnames (CDNs, hashed subdomains). The suspicious-TLD list is a
  small fixed sample, not an exhaustive reputation feed.
- **IPv6 classification is best-effort.** Internal-address detection leans on
  Python's `ipaddress` module; unusual or transitional address forms may not be
  recognised as internal.
- **VirusTotal is optional and partial.** It covers IPs, domains, and file
  hashes only, requires a key and network access, and its engine counts are
  themselves noisy — treat them as one more signal, not ground truth.
- **No sandboxing, no live intel.** ThreatLens does not detonate files, attribute
  threat actors, or consult live feeds. The MITRE mapping is a small static table
  hinting at likely tactics per IOC *type*, not a per-indicator determination.

## Tests

```bash
python3 -m unittest discover -v
```

30 tests, all offline — the VirusTotal HTTP calls are mocked with
`unittest.mock`, so the suite never opens a network connection. They cover IOC
classification (including IPv6 validation), hostname extraction with ports and
userinfo, offline scoring and severity bands, private / loopback / link-local
down-weighting, DGA and suspicious-TLD flags, VirusTotal parsing and graceful
failure, and the MITRE lookup table.

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)
- VirusTotal API key optional

## Ethical use

For authorised triage of indicators from your own environment, or an engagement
you are permitted to work. Note that `--resolve` sends the indicator to DNS and
`--vt-key` sends it to VirusTotal, so do not submit indicators you are not
allowed to disclose to third parties. Nothing here confirms an indicator is
malicious — act on the output only after human review.
