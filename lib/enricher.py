"""
lib/enricher.py -- IOC enrichment: attach MITRE context, heuristic
threat scoring, and (optionally) VirusTotal reputation.
"""

import socket
from dataclasses import dataclass, field
from typing import List, Optional

from .ioc import IOC, parse_ioc_list
from .mitre import Technique, techniques_for_tactic
from .scoring import score_ioc, apply_reputation
from . import virustotal


@dataclass
class EnrichedIOC:
    ioc:           IOC
    resolved_host: Optional[str]      = None
    techniques:    List[Technique]    = field(default_factory=list)
    notes:         List[str]          = field(default_factory=list)
    score:         int                = 0
    severity:      str                = "INFO"
    vt:            Optional[object]   = None   # virustotal.VTResult when available


def _try_resolve(value: str) -> Optional[str]:
    """Best-effort reverse DNS for IPs, forward lookup for domains."""
    try:
        if value.count(".") == 3 and all(p.isdigit() for p in value.split(".")):
            return socket.gethostbyaddr(value)[0]
        return socket.gethostbyname(value)
    except (socket.herror, socket.gaierror, OSError):
        return None


def enrich(ioc: IOC, resolve: bool = False, vt_key: Optional[str] = None) -> EnrichedIOC:
    """
    Attach enrichment to a single IOC: MITRE ATT&CK tactic coverage, a
    0-100 heuristic threat score with severity band, and optional
    VirusTotal reputation when `vt_key` is supplied.

    resolve=True attempts a DNS lookup (slow; disable in large batches).
    """
    enriched = EnrichedIOC(ioc=ioc)

    if resolve and ioc.ioc_type in ("ip", "domain"):
        enriched.resolved_host = _try_resolve(ioc.value)

    # Tag common IOC types with likely ATT&CK coverage.
    tactic_hints = {
        "ip":     "Command and Control",
        "domain": "Command and Control",
        "url":    "Command and Control",
        "sha256": "Defense Evasion",
        "sha1":   "Defense Evasion",
        "md5":    "Defense Evasion",
        "email":  "Initial Access",
        "cve":    "Initial Access",
    }
    tactic = tactic_hints.get(ioc.ioc_type)
    if tactic:
        enriched.techniques = techniques_for_tactic(tactic)

    # Offline heuristic scoring.
    score, severity, notes = score_ioc(ioc.ioc_type, ioc.value)
    enriched.score = score
    enriched.severity = severity
    enriched.notes.extend(notes)

    # Optional live VirusTotal reputation, folded into the score.
    if vt_key:
        if not virustotal.supports(ioc.ioc_type):
            enriched.notes.append(
                f"VirusTotal lookup not implemented for {ioc.ioc_type} IOCs; "
                f"offline heuristics used."
            )
        else:
            vt = virustotal.lookup(ioc.ioc_type, ioc.value, vt_key)
            if vt is not None:
                enriched.vt = vt
                enriched.score, enriched.severity = apply_reputation(
                    enriched.score, vt.malicious, vt.suspicious
                )
                enriched.notes.append(
                    f"VirusTotal: {vt.malicious} malicious / {vt.suspicious} suspicious "
                    f"of {vt.total} engines."
                )
            else:
                enriched.notes.append("VirusTotal lookup unavailable; offline heuristics used.")

    return enriched


def enrich_batch(values: List[str], resolve: bool = False,
                 vt_key: Optional[str] = None) -> List[EnrichedIOC]:
    """Parse a list of raw IOC strings and return enriched results."""
    iocs = parse_ioc_list(values)
    return [enrich(ioc, resolve=resolve, vt_key=vt_key) for ioc in iocs]
