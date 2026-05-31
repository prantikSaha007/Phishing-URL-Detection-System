"""
PhishGuard - Cyber Threat Intelligence Orchestrator
Queries VirusTotal, URLhaus, and PhishTank asynchronously.
"""

import asyncio
import base64
import hashlib
import os
from typing import Any, Dict
from urllib.parse import urlparse

import aiohttp

VT_API_KEY   = os.getenv("VT_API_KEY", "")
URLHAUS_API  = "https://urlhaus-api.abuse.ch/v1/url/"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


class CTIOrchestrator:

    async def query(self, url: str) -> Dict[str, Any]:
        results = await asyncio.gather(
            self._virustotal(url),
            self._urlhaus(url),
            return_exceptions=True,
        )
        vt_res  = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
        uh_res  = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
        return {
            "virustotal": vt_res,
            "urlhaus":    uh_res,
        }

    # ── VirusTotal ────────────────────────────────────────────────────────────
    async def _virustotal(self, url: str) -> Dict[str, Any]:
        if not VT_API_KEY:
            return {"available": False, "reason": "VT_API_KEY not configured"}

        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        headers = {"x-apikey": VT_API_KEY}
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(endpoint, headers=headers) as resp:
                if resp.status == 404:
                    # Submit for analysis
                    return await self._vt_submit(session, url, headers)
                if resp.status != 200:
                    return {"available": False, "status": resp.status}
                data = await resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "available":  True,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "scan_date":  data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
            "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
        }

    async def _vt_submit(self, session, url: str, headers: dict) -> dict:
        async with session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                return {"available": True, "status": "submitted_for_analysis",
                        "malicious": 0, "suspicious": 0}
            return {"available": False, "status": resp.status}

    # ── URLhaus ───────────────────────────────────────────────────────────────
    async def _urlhaus(self, url: str) -> Dict[str, Any]:
        payload = {"url": url}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
            async with session.post(URLHAUS_API, data=payload) as resp:
                if resp.status != 200:
                    return {"available": False, "status": resp.status}
                data = await resp.json(content_type=None)

        if data.get("query_status") == "no_results":
            return {"available": True, "found": False}

        return {
            "available":   True,
            "found":       True,
            "url_status":  data.get("url_status"),
            "threat":      data.get("threat"),
            "tags":        data.get("tags", []),
            "date_added":  data.get("date_added"),
            "reporter":    data.get("reporter"),
        }
