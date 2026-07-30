"""
lib/scoring.py -- offline heuristic threat scoring for IOCs.

Produces a 0-100 threat score and a severity band (CRITICAL / HIGH /
MEDIUM / LOW / INFO) using only local heuristics, so ThreatLens is
useful with no API keys. External signals (e.g. VirusTotal) can be
layered on top by callers via `apply_reputation`.
"""

import math
from typing import List, Tuple
from urllib.parse import urlsplit

# Free / abused TLDs frequently seen in phishing and malware campaigns.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "gdn", "work", "click",
    "link", "loan", "download", "zip", "mov", "country", "kim", "science",
}

# RFC1918 / loopback / link-local prefixes treated as internal (low risk).
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")


def _is_private_ip(value: str) -> bool:
    if value.startswith(_PRIVATE_PREFIXES):
        return True
    if value.startswith("172."):
        try:
            second = int(value.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_dga(domain: str) -> bool:
    """
    Heuristic domain-generation-algorithm detector.

    Flags the registrable label when it is long, high-entropy, and
    light on vowels -- the signature of algorithmically generated names.
    """
    label = domain.split(".")[0].lower()
    if len(label) < 10:
        return False
    entropy = shannon_entropy(label)
    vowels = sum(label.count(v) for v in "aeiou")
    vowel_ratio = vowels / len(label)
    longest_consonant_run = 0
    run = 0
    for ch in label:
        if ch.isalpha() and ch not in "aeiou":
            run += 1
            longest_consonant_run = max(longest_consonant_run, run)
        else:
            run = 0
    digit_ratio = sum(ch.isdigit() for ch in label) / len(label)
    return (entropy >= 3.5 and vowel_ratio < 0.30) or longest_consonant_run >= 5 or digit_ratio >= 0.4


def hostname_of(value: str) -> str:
    """
    Extract the bare hostname from a domain or URL value.

    Strips scheme, userinfo, port, and path so downstream heuristics see
    only the host (e.g. ``http://user@evil.tk:8080/x`` -> ``evil.tk``).
    Schemeless values are parsed as ``//value`` so urlsplit still yields a
    hostname. Returns a lowercased host, falling back to the lowercased
    input when no host can be parsed.
    """
    v = (value or "").strip()
    if not v:
        return ""
    parsed = urlsplit(v if "://" in v else "//" + v)
    host = parsed.hostname
    return host.lower() if host else v.lower()


def suspicious_tld(domain: str) -> str:
    """Return the TLD if it is on the suspicious list, else ''."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld if tld in SUSPICIOUS_TLDS else ""


def severity_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def score_ioc(ioc_type: str, value: str) -> Tuple[int, str, List[str]]:
    """
    Return (score 0-100, severity, notes) from offline heuristics.

    The base score reflects how inherently risky the indicator type is;
    domain heuristics (DGA, suspicious TLD) add weight on top.
    """
    notes: List[str] = []
    base = {
        "ip": 40, "domain": 40, "url": 55, "email": 45,
        "md5": 50, "sha1": 50, "sha256": 50, "cve": 60,
    }.get(ioc_type, 20)
    score = base

    if ioc_type == "ip" and _is_private_ip(value):
        score = 10
        notes.append("Private / internal address (RFC1918) -- low external risk.")

    if ioc_type in ("domain", "url"):
        host = hostname_of(value)
        tld = suspicious_tld(host)
        if tld:
            score += 20
            notes.append(f"Suspicious TLD .{tld} commonly abused for phishing/malware.")
        if looks_like_dga(host):
            score += 25
            notes.append("Domain resembles algorithmically generated (DGA) name.")

    if ioc_type == "cve":
        notes.append("Check NVD / CISA KEV for CVSS severity and exploitation status.")

    score = max(0, min(100, score))
    return score, severity_for(score), notes


def apply_reputation(score: int, malicious: int, suspicious: int) -> Tuple[int, str]:
    """
    Fold an external reputation verdict (e.g. VirusTotal engine counts)
    into an existing heuristic score and return (score, severity).
    """
    if malicious > 0:
        score = max(score, min(100, 70 + malicious * 3))
    elif suspicious > 0:
        score = max(score, min(100, 45 + suspicious * 2))
    return score, severity_for(score)
