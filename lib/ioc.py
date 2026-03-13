"""
lib/ioc.py -- Indicator of Compromise (IOC) parsing and classification.
"""

import re
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# IOC type patterns
# ---------------------------------------------------------------------------

_IPV4_RE   = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')
_IPV6_RE   = re.compile(r'^[0-9a-fA-F:]+:[0-9a-fA-F]+$')
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
_URL_RE    = re.compile(r'^https?://')
_MD5_RE    = re.compile(r'^[0-9a-fA-F]{32}$')
_SHA1_RE   = re.compile(r'^[0-9a-fA-F]{40}$')
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_EMAIL_RE  = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
_CVE_RE    = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


@dataclass
class IOC:
    value:    str
    ioc_type: str   # ip, domain, url, md5, sha1, sha256, email, cve, unknown
    raw:      str   = ''
    tags:     list  = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if not self.raw:
            self.raw = self.value


def classify(value: str) -> str:
    v = value.strip()
    if _CVE_RE.match(v):    return 'cve'
    if _SHA256_RE.match(v): return 'sha256'
    if _SHA1_RE.match(v):   return 'sha1'
    if _MD5_RE.match(v):    return 'md5'
    if _IPV4_RE.match(v):   return 'ip'
    if _IPV6_RE.match(v):   return 'ip'
    if _URL_RE.match(v):    return 'url'
    if _EMAIL_RE.match(v):  return 'email'
    if _DOMAIN_RE.match(v): return 'domain'
    return 'unknown'


def parse_ioc(value: str) -> IOC:
    """Parse a single IOC string and return a typed IOC object."""
    v = value.strip()
    return IOC(value=v, ioc_type=classify(v))


def parse_ioc_list(values: List[str]) -> List[IOC]:
    """Parse a list of IOC strings, skipping blanks and comment lines."""
    result = []
    for line in values:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        result.append(parse_ioc(line))
    return result
