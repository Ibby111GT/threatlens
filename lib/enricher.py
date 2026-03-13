"""
lib/enricher.py -- IOC enrichment: attach MITRE context and basic metadata.
"""

import socket
from dataclasses import dataclass, field
from typing import List, Optional

from .ioc import IOC, parse_ioc_list
from .mitre import Technique, lookup as mitre_lookup, techniques_for_tactic


@dataclass
class EnrichedIOC:
    ioc:           IOC
    resolved_host: Optional[str]      = None
    techniques:    List[Technique]    = field(default_factory=list)
    notes:         List[str]          = field(default_factory=list)


def _try_resolve(value: str) -> Optional[str]:
    """Best-effort reverse DNS for IPs, forward lookup for domains."""
    try:
        if value.count(".") == 3 and all(p.isdigit() for p in value.split(".")):
            return socket.gethostbyaddr(value)[0]
        return socket.gethostbyname(value)
    except (socket.herror, socket.gaierror, OSError):
        return None


def enrich(ioc: IOC, resolve: bool = False) -> EnrichedIOC:
    """
    Attach basic enrichment data to a single IOC.

    resolve=True will attempt a DNS lookup (slow; disable in batch jobs).
    """
    enriched = EnrichedIOC(ioc=ioc)

    if resolve and ioc.ioc_type in ("ip", "domain"):
        enriched.resolved_host = _try_resolve(ioc.value)

    # Tag common IOC types with likely ATT&CK coverage
    tactic_hints = {
        "ip":     "Command and Control",
        "domain": "Command and Control",
        "url":    "Command and Control",
        "sha256": "Defense Evasion",
        "sha1":   "Defense Evasion",
        "md5":    "Defense Evasion",
        "email":  "Initial Access",
    }
    tactic = tactic_hints.get(ioc.ioc_type)
    if tactic:
        enriched.techniques = techniques_for_tactic(tactic)

    if ioc.ioc_type == "cve":
        enriched.notes.append("Check NVD / CISA KEV for severity and patch status.")

    return enriched


def enrich_batch(values: List[str], resolve: bool = False) -> List[EnrichedIOC]:
    """Parse a list of raw IOC strings and return enriched results."""
    iocs = parse_ioc_list(values)
    return [enrich(ioc, resolve=resolve) for ioc in iocs]
