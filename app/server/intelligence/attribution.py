"""
ARGOS — Attribution Engine
WHOIS / RDAP lookups via the ipwhois library.
The synchronous ipwhois call is executed in a thread pool so it never
blocks the async event loop.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

log = logging.getLogger("argos.attribution")


class AttributionEngine:
    """ASN / WHOIS attribution for source IPs."""

    async def full_attribution(self, ip: str) -> dict:
        """
        Return a best-effort attribution dict for *ip*.
        Always returns at least ``{"ip": ip}``.
        """
        result: dict = {"ip": ip}
        try:
            # ipwhois is synchronous — run in thread pool to avoid blocking
            whois_data = await asyncio.to_thread(self._whois_lookup, ip)
            if whois_data:
                result.update(whois_data)
        except Exception as exc:
            log.debug("Attribution failed for %s: %s", ip, exc)
        return result

    # ── Synchronous helpers (run in thread pool) ─────────────────────────────────

    def _whois_lookup(self, ip: str) -> Optional[dict]:
        """
        Perform an RDAP lookup via ipwhois.
        Returns None if ipwhois is not installed or the lookup fails.
        """
        try:
            from ipwhois import IPWhois  # optional dependency

            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)

            # Extract org description from network remarks if available
            network = res.get("network") or {}
            remarks = network.get("remarks") or []
            org_description = ""
            if remarks and isinstance(remarks[0], dict):
                org_description = remarks[0].get("description", "")

            return {
                "asn": res.get("asn"),
                "asn_description": res.get("asn_description"),
                "asn_country": res.get("asn_country_code"),
                "network_name": network.get("name"),
                "org": org_description,
            }
        except ImportError:
            log.debug("ipwhois not installed — attribution unavailable")
            return None
        except Exception as exc:
            log.debug("WHOIS lookup failed for %s: %s", ip, exc)
            return None
