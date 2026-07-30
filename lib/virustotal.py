"""
lib/virustotal.py -- optional VirusTotal API v3 lookups.

Pure stdlib (urllib). Used only when the caller supplies an API key;
every failure degrades gracefully to None so ThreatLens keeps working
fully offline. Free VT keys allow 500 lookups/day at 4/min.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

_BASE = "https://www.virustotal.com/api/v3"

# Map ThreatLens IOC types to VT v3 collection paths.
_ENDPOINTS = {
    "ip":     "ip_addresses",
    "domain": "domains",
    "md5":    "files",
    "sha1":   "files",
    "sha256": "files",
}


def supports(ioc_type: str) -> bool:
    """
    True when VirusTotal enrichment is implemented for this IOC type.

    VT v3 collections cover IP addresses, domains, and file hashes
    (md5/sha1/sha256); url and email IOCs are not looked up.
    """
    return ioc_type in _ENDPOINTS


@dataclass
class VTResult:
    malicious:  int
    suspicious: int
    harmless:   int
    undetected: int

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected


def lookup(ioc_type: str, value: str, api_key: str, timeout: float = 10.0) -> Optional[VTResult]:
    """
    Query VirusTotal for an IOC and return engine verdict counts.

    Returns None if the type is unsupported, the key is missing, or the
    request fails for any reason (network, rate limit, unknown IOC).
    """
    endpoint = _ENDPOINTS.get(ioc_type)
    if not endpoint or not api_key:
        return None

    url = f"{_BASE}/{endpoint}/{value}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, OSError):
        return None

    stats = (
        data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
    )
    if not stats:
        return None

    return VTResult(
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
    )
