"""
PhishGuard – URL Feature Extraction
Extracts 30+ statistical and lexical features from a raw URL string.
No network I/O here – pure computational features for the ML model.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict


# ──────────────────────────────────────────────
# Entropy helper
# ──────────────────────────────────────────────
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


# ──────────────────────────────────────────────
# Known brands for typosquat detection
# ──────────────────────────────────────────────
KNOWN_BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "yahoo", "ebay", "chase", "wellsfargo", "bankofamerica", "citibank",
    "irs", "usps", "fedex", "ups", "dhl", "steam", "roblox",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update",
    "banking", "payment", "confirm", "wallet", "password", "credential",
    "suspend", "alert", "urgent", "free", "prize", "winner", "click",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "adf.ly", "is.gd", "clck.ru", "shorte.st",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".club", ".online", ".site", ".info", ".biz",
}


def extract_features(url: str) -> Dict[str, float]:
    """
    Returns a flat dict of numeric features.
    Column order is fixed – must match training order.
    """
    feature_url = re.sub(r"://www\.", "://", url, count=1, flags=re.IGNORECASE)
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme   = parsed.scheme or ""
    hostname = (parsed.hostname or "").lower().strip(".")
    path     = parsed.path or ""
    query    = parsed.query or ""
    fragment = parsed.fragment or ""

    # Treat www. as a presentation prefix, not as a meaningful subdomain.
    full_domain = re.sub(r"^www\.", "", hostname)
    domain_clean = full_domain
    subdomain_part = ""
    parts = full_domain.split(".")
    if len(parts) > 2:
        subdomain_part = ".".join(parts[:-2])

    tld = "." + parts[-1] if parts else ""
    path_query = path + "?" + query if query else path

    # ── Length features ──────────────────────────────
    f = {}
    f["url_length"]        = len(feature_url)
    f["domain_length"]     = len(domain_clean)
    f["path_length"]       = len(path)
    f["query_length"]      = len(query)
    f["subdomain_length"]  = len(subdomain_part)

    # ── Count features ───────────────────────────────
    f["num_dots"]          = feature_url.count(".")
    f["num_hyphens"]       = feature_url.count("-")
    f["num_underscores"]   = feature_url.count("_")
    f["num_slashes"]       = feature_url.count("/")
    f["num_at_signs"]      = feature_url.count("@")
    f["num_equals"]        = feature_url.count("=")
    f["num_ampersands"]    = feature_url.count("&")
    f["num_exclamations"]  = feature_url.count("!")
    f["num_tildes"]        = feature_url.count("~")
    f["num_commas"]        = feature_url.count(",")
    f["num_plus"]          = feature_url.count("+")
    f["num_asterisks"]     = feature_url.count("*")
    f["num_hash"]          = feature_url.count("#")
    f["num_dollar"]        = feature_url.count("$")
    f["num_percent"]       = feature_url.count("%")
    f["num_digits_domain"] = sum(c.isdigit() for c in domain_clean)
    f["digit_ratio_domain"]= f["num_digits_domain"] / max(len(domain_clean), 1)

    # ── Entropy ──────────────────────────────────────
    f["entropy_url"]    = _shannon_entropy(feature_url)
    f["entropy_domain"] = _shannon_entropy(domain_clean)
    f["entropy_path"]   = _shannon_entropy(path)

    # ── Boolean / categorical ─────────────────────────
    f["has_ip"]            = 1.0 if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0.0
    f["has_https"]         = 1.0 if scheme == "https" else 0.0
    f["has_http"]          = 1.0 if scheme == "http"  else 0.0
    f["has_at_sign"]       = 1.0 if "@" in feature_url else 0.0
    f["has_double_slash"]  = 1.0 if "//" in path else 0.0
    f["has_hex_encoding"]  = 1.0 if "%" in feature_url else 0.0
    f["is_shortened"]      = 1.0 if domain_clean in SHORTENER_DOMAINS else 0.0
    f["suspicious_tld"]    = 1.0 if tld.lower() in SUSPICIOUS_TLDS else 0.0

    # Subdomain count (proxy for deep nesting)
    f["subdomain_count"]   = len(subdomain_part.split(".")) if subdomain_part else 0.0

    # ── Keyword features ─────────────────────────────
    url_lower = feature_url.lower()
    f["suspicious_keyword_count"] = sum(
        kw in url_lower for kw in SUSPICIOUS_KEYWORDS)
    f["brand_in_subdomain"] = float(any(
        brand in subdomain_part.lower() for brand in KNOWN_BRANDS))
    f["brand_in_path"] = float(any(
        brand in path.lower() for brand in KNOWN_BRANDS))

    # ── Special obfuscation signals ───────────────────
    f["has_punycode"]   = 1.0 if "xn--" in hostname else 0.0
    f["has_redirect"]   = 1.0 if "redirect" in url_lower or "url=" in url_lower else 0.0
    f["has_data_uri"]   = 1.0 if url_lower.startswith("data:") else 0.0
    f["num_subdomains"] = max(len(parts) - 2, 0)

    return f


FEATURE_NAMES = list(extract_features("http://example.com").keys())
NUM_FEATURES   = len(FEATURE_NAMES)
