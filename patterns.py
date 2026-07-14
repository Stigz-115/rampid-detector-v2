"""
RampID pattern matching utilities.

Detects LiveRamp RampID signals in network traffic, cookies, and page content.

RampID identifiers follow these formats:
  - XY<4-digit-number><random hash>   (49 or 70 characters total)
  - Xi<4-digit-number><random hash>   (49 or 70 characters total)

The rlcdn.com domain is LiveRamp's cookie-matching / ID sync endpoint.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Domain / URL patterns
# ---------------------------------------------------------------------------

# LiveRamp's primary delivery domain for ID syncs and cookie matching
RLCDN_PATTERN = re.compile(r"rlcdn\.com", re.IGNORECASE)

# Additional LiveRamp / RampID related domains and endpoints
LIVERAMP_DOMAINS = [
    "rlcdn.com",
    "liveramp.com",
    "idsync.rlcdn.com",
    "tags.rlcdn.com",
    "pippio.com",          # Legacy LiveRamp domain
    "live.ramp.com",
    "ramp.com",
]

# Keywords that may appear in script URLs or inline JS referencing RampID
RAMPID_KEYWORDS = [
    "rampid",
    "ramp_id",
    "ramp-id",
    "liveramp",
    "live_ramp",
    "live-ramp",
    "idsync",
    "id_sync",
    "ats.js",              # LiveRamp's Authenticated Traffic Solution script
    "enabler.js",          # Legacy LiveRamp enabler
    "pippio",
    "rlcdn",
]


# ---------------------------------------------------------------------------
# RampID identifier regex
# ---------------------------------------------------------------------------

# XY or Xi prefix, followed by 4 digits, then a base64-ish hash.
# The hash portion is alphanumeric with possible - and _ characters.
# Total length is either 49 (hash=43) or 70 (hash=64).

_HASH_CHARS = r"[A-Za-z0-9_\-]"

# XY<4 digits><43 hash chars> = 2 + 4 + 43 = 49
_RAMPID_49 = re.compile(rf"\b(XY|Xi)\d{{4}}{_HASH_CHARS}{{43}}\b")

# XY<4 digits><64 hash chars> = 2 + 4 + 64 = 70
_RAMPID_70 = re.compile(rf"\b(XY|Xi)\d{{4}}{_HASH_CHARS}{{64}}\b")

# Combined pattern for any valid RampID
RAMPID_PATTERN = re.compile(
    rf"\b(XY|Xi)\d{{4}}{_HASH_CHARS}{{43}}\b"   # 49-char variant
    rf"|"
    rf"\b(XY|Xi)\d{{4}}{_HASH_CHARS}{{64}}\b",   # 70-char variant
)

# Broader fallback: XY/Xi + 4 digits + at least 20 hash chars (catches truncated IDs)
RAMPID_BROAD = re.compile(rf"\b(XY|Xi)\d{{4}}{_HASH_CHARS}{{20,}}\b")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RampIDMatch:
    """A single RampID identifier found in content."""
    value: str
    source: str          # Where it was found: "cookie", "network", "script", "html"
    length: int
    variant: str         # "49-char" or "70-char" or "broad"


@dataclass
class ScanResult:
    """Aggregated results from a website scan."""
    url: str = ""
    scan_mode: str = ""                              # "playwright" or "requests"

    # Network-level findings
    rlcdn_requests: list[dict] = field(default_factory=list)     # URLs containing rlcdn
    liveramp_requests: list[dict] = field(default_factory=list)  # Other LiveRamp domains
    all_network_requests: list[dict] = field(default_factory=list)

    # Content findings
    rampid_matches: list[RampIDMatch] = field(default_factory=list)
    script_references: list[str] = field(default_factory=list)   # Script URLs referencing LiveRamp
    cookie_matches: list[dict] = field(default_factory=list)

    # Metadata
    page_title: str = ""
    error: Optional[str] = None

    @property
    def has_rampid(self) -> bool:
        """True if any RampID signal was detected."""
        return bool(self.rlcdn_requests or self.rampid_matches or self.script_references)

    @property
    def confidence(self) -> str:
        """Confidence level of the detection."""
        signals = sum([
            bool(self.rlcdn_requests),
            bool(self.rampid_matches),
            bool(self.script_references),
            bool(self.cookie_matches),
        ])
        if signals >= 3:
            return "High"
        elif signals >= 2:
            return "Medium"
        elif signals >= 1:
            return "Low"
        return "None"

    @property
    def summary(self) -> str:
        """Human-readable summary."""
        if self.error:
            return f"Error: {self.error}"
        if not self.has_rampid:
            return "No RampID / LiveRamp signals detected."
        parts = []
        if self.rlcdn_requests:
            parts.append(f"{len(self.rlcdn_requests)} rlcdn.com network call(s)")
        if self.rampid_matches:
            parts.append(f"{len(self.rampid_matches)} RampID identifier(s)")
        if self.script_references:
            parts.append(f"{len(self.script_references)} LiveRamp script reference(s)")
        if self.cookie_matches:
            parts.append(f"{len(self.cookie_matches)} cookie match(es)")
        return "Detected: " + ", ".join(parts) + f" (Confidence: {self.confidence})"


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def find_rampids(text: str, source: str = "unknown") -> list[RampIDMatch]:
    """
    Find all RampID identifiers in a text string.

    Args:
        text: The text to search (cookie value, URL, script content, HTML).
        source: Where this text came from (for reporting).

    Returns:
        List of RampIDMatch objects.
    """
    matches = []
    seen = set()

    # Exact 49-char matches
    for m in _RAMPID_49.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            matches.append(RampIDMatch(
                value=val, source=source, length=49, variant="49-char"
            ))

    # Exact 70-char matches
    for m in _RAMPID_70.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            matches.append(RampIDMatch(
                value=val, source=source, length=70, variant="70-char"
            ))

    # Broad fallback for partial/truncated IDs (only if no exact match for same value)
    for m in RAMPID_BROAD.finditer(text):
        val = m.group()
        if val not in seen:
            # Check if an exact match already captured a superset
            already_found = any(
                existing.value in val or val in existing.value
                for existing in matches
            )
            if not already_found:
                seen.add(val)
                matches.append(RampIDMatch(
                    value=val, source=source, length=len(val), variant="broad"
                ))

    return matches


def is_rlcdn_url(url: str) -> bool:
    """Check if a URL references rlcdn.com."""
    return bool(RLCDN_PATTERN.search(url))


def is_liveramp_url(url: str) -> bool:
    """Check if a URL references any known LiveRamp domain."""
    url_lower = url.lower()
    return any(domain in url_lower for domain in LIVERAMP_DOMAINS)


def find_script_references(html: str) -> list[str]:
    """
    Find <script> tags whose src attribute references LiveRamp/RampID.

    Returns a list of script src URLs.
    """
    refs = []
    # Match script tags with src attributes
    script_pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in script_pattern.finditer(html):
        src = m.group(1)
        src_lower = src.lower()
        if is_liveramp_url(src) or any(kw in src_lower for kw in RAMPID_KEYWORDS):
            refs.append(src)

    # Also check inline scripts for LiveRamp keywords
    inline_pattern = re.compile(
        r'<script[^>]*>(.*?)</script>',
        re.IGNORECASE | re.DOTALL,
    )
    for m in inline_pattern.finditer(html):
        content = m.group(1)
        content_lower = content.lower()
        if any(kw in content_lower for kw in ["rlcdn", "liveramp", "rampid", "pippio", "ats.js"]):
            # Try to extract a URL if one is referenced
            url_match = re.search(r'https?://[^\s"\'<>]+rlcdn[^\s"\'<>]*', content, re.IGNORECASE)
            if url_match:
                refs.append(url_match.group())
            else:
                refs.append("inline script referencing LiveRamp/RampID")

    return list(dict.fromkeys(refs))  # dedupe preserving order
