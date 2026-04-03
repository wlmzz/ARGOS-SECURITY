"""
ARGOS — Intelligence Feeds
IP enrichment from public sources: ip-api.com (geo) and AbuseIPDB.
Results are cached in-memory for CACHE_TTL seconds to avoid rate limiting.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

log = logging.getLogger("argos.intelligence")

# Simple in-memory cache: ip → (timestamp, result)
_cache: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 3600  # 1 hour


class IntelligenceFeeds:
    """Async IP enrichment aggregating geolocation and abuse-reputation data."""

    IPAPI_URL = (
        "http://ip-api.com/json/{ip}"
        "?fields=status,country,regionName,city,isp,org,as,hosting"
    )
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, abuseipdb_key: Optional[str] = None) -> None:
        self.abuseipdb_key = abuseipdb_key

    async def enrich_ip(self, ip: str) -> dict:
        """
        Return an enrichment dict for *ip*.  Results are cached for CACHE_TTL
        seconds.  The dict always contains ``ip`` and ``sources`` keys; each
        source is only present when the lookup succeeds.
        """
        # Check cache first
        cached = _cache.get(ip)
        if cached and time.time() - cached[0] < CACHE_TTL:
            return cached[1]

        result: dict = {"ip": ip, "sources": {}}

        # Geolocation — always available, free, no key required
        geo = await self._lookup_geolocation(ip)
        if geo:
            result["sources"]["geolocation"] = geo

        # AbuseIPDB — only when an API key is configured
        if self.abuseipdb_key:
            abuse = await self._lookup_abuseipdb(ip)
            if abuse:
                result["sources"]["abuseipdb"] = abuse

        _cache[ip] = (time.time(), result)
        return result

    # ── Private helpers ──────────────────────────────────────────────────────────

    async def _lookup_geolocation(self, ip: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(self.IPAPI_URL.format(ip=ip))
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country"),
                            "region": data.get("regionName"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "asn": data.get("as"),
                            "hosting": data.get("hosting", False),
                        }
        except Exception as exc:
            log.debug("Geolocation lookup failed for %s: %s", ip, exc)
        return None

    async def _lookup_abuseipdb(self, ip: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    self.ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self.abuseipdb_key,
                        "Accept": "application/json",
                    },
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    return {
                        "abuse_score": data.get("abuseConfidenceScore"),
                        "total_reports": data.get("totalReports"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "is_tor": data.get("isTor", False),
                    }
        except Exception as exc:
            log.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None
