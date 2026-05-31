"""
PhishGuard – DNS / WHOIS Forensics
Passive analysis: domain age, DNS records, typosquatting detection.
"""

import asyncio
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Optional imports – graceful degradation if not installed
try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ── Typosquatting ──────────────────────────────────────────────────────────────
KNOWN_BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "yahoo", "ebay", "chase", "wellsfargo", "bankofamerica", "citibank",
    "irs", "usps", "fedex", "ups", "dhl", "steam", "roblox", "binance",
    "coinbase", "blockchain",
]

def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _detect_typosquat(hostname: str) -> Optional[str]:
    """Return brand name if hostname is a typosquat, else None."""
    # Remove TLD
    parts = hostname.split(".")
    sld = parts[-2] if len(parts) >= 2 else hostname
    # Strip numeric prefixes / suffixes
    sld_lower = sld.lower()
    sld_clean = re.sub(r"[^a-z]", "", sld_lower)  # letters only for edit-distance
    for brand in KNOWN_BRANDS:
        if sld_lower == brand:
            return None  # exact match – legit
        # Raw edit distance on the original SLD (preserving digits/hyphens)
        dist = _levenshtein(sld_lower.replace("-", ""), brand)
        threshold = 2 if len(brand) > 6 else 1
        if 0 < dist <= threshold:
            return brand
        # Homoglyph heuristic
        homoglyphs = str.maketrans("0oO1lI", "oooo1l")
        if sld_clean.translate(homoglyphs) == brand:
            return brand
        # Brand embedded in longer string (e.g. "paypal-secure")
        if brand in sld_clean and sld_clean != brand:
            return brand
    return None


class DNSWHOISForensics:

    async def analyze(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.hostname or ""
        domain = ".".join(hostname.split(".")[-2:]) if hostname else ""

        # Run sync I/O in thread pool
        loop = asyncio.get_event_loop()
        whois_data, dns_data = await asyncio.gather(
            loop.run_in_executor(None, self._whois, domain),
            loop.run_in_executor(None, self._dns,   hostname),
        )

        age_days = None
        if whois_data.get("creation_date"):
            try:
                cd = whois_data["creation_date"]
                if isinstance(cd, list): cd = cd[0]
                if cd.tzinfo is None: cd = cd.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - cd).days
            except Exception:
                pass

        typosquat = _detect_typosquat(hostname)

        return {
            "domain":       domain,
            "hostname":     hostname,
            "registrar":    whois_data.get("registrar"),
            "creation_date": str(whois_data.get("creation_date", "")),
            "expiration_date": str(whois_data.get("expiration_date", "")),
            "country":      whois_data.get("country"),
            "domain_age_days": age_days,
            "ip_addresses": dns_data.get("a_records", []),
            "mx_records":   dns_data.get("mx_records", []),
            "ns_records":   dns_data.get("ns_records", []),
            "dns_resolves": dns_data.get("resolves", False),
            "typosquat_target": typosquat,
        }

    def _whois(self, domain: str) -> dict:
        if not HAS_WHOIS or not domain:
            return {}
        try:
            w = python_whois.whois(domain)
            return {
                "registrar":       w.registrar,
                "creation_date":   w.creation_date,
                "expiration_date": w.expiration_date,
                "country":         w.country,
            }
        except Exception:
            return {}

    def _dns(self, hostname: str) -> dict:
        result: dict = {"resolves": False, "a_records": [], "mx_records": [], "ns_records": []}
        if not hostname:
            return result
        # Basic socket resolve
        try:
            info = socket.getaddrinfo(hostname, None)
            result["a_records"] = list({i[4][0] for i in info})
            result["resolves"] = True
        except socket.gaierror:
            pass

        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4
            resolver.lifetime = 4
            for rtype, key in [("MX", "mx_records"), ("NS", "ns_records")]:
                try:
                    answers = resolver.resolve(hostname, rtype)
                    result[key] = [str(r) for r in answers]
                except Exception:
                    pass
        return result
