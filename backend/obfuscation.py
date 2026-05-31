"""
PhishGuard – URL Obfuscation Decoder
Handles common obfuscation techniques used by phishing actors.
"""

import base64
import re
import urllib.parse
from typing import Optional


def decode_url(url: str) -> str:
    """
    Iteratively decode a URL through common obfuscation layers.
    Returns the final decoded URL.
    """
    original = url
    url = url.strip()

    # Pass 1 – percent-decoding
    try:
        decoded = urllib.parse.unquote(url)
        if decoded != url:
            url = decoded
    except Exception:
        pass

    # Pass 2 – double percent-encoding (e.g. %2540 → %40 → @)
    try:
        decoded2 = urllib.parse.unquote(url)
        if decoded2 != url:
            url = decoded2
    except Exception:
        pass

    # Pass 3 – data: URI
    if url.lower().startswith("data:text/html"):
        m = re.search(r"base64,(.+)$", url, re.IGNORECASE)
        if m:
            try:
                inner = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="ignore")
                # Extract embedded href/src URL
                href = re.search(r'(?:href|src|url)[=:]\s*["\']?([^\s"\'<>]+)', inner, re.IGNORECASE)
                if href:
                    url = href.group(1)
            except Exception:
                pass

    # Pass 4 – redirect wrappers (e.g. ?url=, ?redirect=, ?next=)
    redirect_params = ["url", "redirect", "next", "goto", "link", "target", "r"]
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in redirect_params:
        if param in qs:
            candidate = qs[param][0]
            if candidate.startswith("http"):
                url = candidate
                break

    # Pass 5 – Unicode / punycode homoglyphs (normalize to ASCII)
    try:
        p = urllib.parse.urlparse(url)
        ascii_host = p.hostname.encode("idna").decode("ascii") if p.hostname else ""
        if ascii_host and ascii_host != p.hostname:
            url = p._replace(netloc=ascii_host).geturl()
    except Exception:
        pass

    # Pass 6 – IP address variants (hex, octal, dword)
    url = _normalize_ip(url)

    return url


_DWORD_RE  = re.compile(r"https?://(\d{8,10})")
_HEX_IP_RE = re.compile(r"https?://0x([0-9a-fA-F]{8})")
_OCTAL_RE  = re.compile(r"https?://(0\d+\.0\d+\.0\d+\.0\d+)")


def _normalize_ip(url: str) -> str:
    # Dword: http://3232235521 → 192.168.0.1
    m = _DWORD_RE.search(url)
    if m:
        dword = int(m.group(1))
        ip = ".".join(str((dword >> (8 * i)) & 0xFF) for i in reversed(range(4)))
        url = url.replace(m.group(1), ip)

    # Hex: http://0xC0A80001 → 192.168.0.1
    m = _HEX_IP_RE.search(url)
    if m:
        val = int(m.group(1), 16)
        ip  = ".".join(str((val >> (8 * i)) & 0xFF) for i in reversed(range(4)))
        url = url.replace("0x" + m.group(1), ip)

    # Octal IP (basic): 0300.0250.00.01 → 192.168.0.1
    m = _OCTAL_RE.search(url)
    if m:
        try:
            ip = ".".join(str(int(o, 8)) for o in m.group(1).split("."))
            url = url.replace(m.group(1), ip)
        except Exception:
            pass

    return url
