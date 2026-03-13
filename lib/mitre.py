"""
lib/mitre.py -- Lightweight MITRE ATT&CK tactic/technique mapping.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Technique:
    technique_id: str
    name:         str
    tactic:       str
    description:  str = ''
    subtechniques: List[str] = field(default_factory=list)


# Subset of ATT&CK Enterprise techniques (v14) for quick offline lookup.
# Keys are technique IDs (Txxxx or Txxxx.xxx).
_TECHNIQUES: Dict[str, Technique] = {
    "T1059": Technique("T1059", "Command and Scripting Interpreter", "Execution",
             "Adversaries abuse command/script interpreters to execute commands."),
    "T1059.001": Technique("T1059.001", "PowerShell", "Execution",
             "Adversaries abuse PowerShell commands and scripts."),
    "T1059.003": Technique("T1059.003", "Windows Command Shell", "Execution",
             "Adversaries abuse cmd.exe to execute commands."),
    "T1055": Technique("T1055", "Process Injection", "Defense Evasion",
             "Adversaries inject code into processes."),
    "T1078": Technique("T1078", "Valid Accounts", "Defense Evasion",
             "Adversaries obtain and abuse existing credentials."),
    "T1110": Technique("T1110", "Brute Force", "Credential Access",
             "Adversaries use brute-force to gain access."),
    "T1110.001": Technique("T1110.001", "Password Guessing", "Credential Access",
             "Adversaries guess passwords without prior knowledge of the scheme."),
    "T1110.003": Technique("T1110.003", "Password Spraying", "Credential Access",
             "Adversaries use one or few passwords against many accounts."),
    "T1046": Technique("T1046", "Network Service Discovery", "Discovery",
             "Adversaries may attempt to get a listing of services running on remote hosts."),
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "Initial Access",
             "Adversaries exploit vulnerabilities in internet-facing applications."),
    "T1566": Technique("T1566", "Phishing", "Initial Access",
             "Adversaries send malicious messages to gain access."),
    "T1071": Technique("T1071", "Application Layer Protocol", "Command and Control",
             "Adversaries communicate over application-layer protocols."),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
             "Adversaries steal data by exfiltrating it over the C2 channel."),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "Impact",
             "Adversaries encrypt data to interrupt availability."),
}


def lookup(technique_id: str) -> Optional[Technique]:
    """Return a Technique for the given ID, or None if unknown."""
    return _TECHNIQUES.get(technique_id.upper().strip())


def techniques_for_tactic(tactic: str) -> List[Technique]:
    """Return all techniques that belong to the given tactic."""
    tactic_lower = tactic.lower()
    return [t for t in _TECHNIQUES.values() if t.tactic.lower() == tactic_lower]


def all_tactics() -> List[str]:
    """Return a deduplicated, sorted list of tactics present in the local table."""
    return sorted({t.tactic for t in _TECHNIQUES.values()})
