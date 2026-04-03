"""
ARGOS — Intelligence router.
Blocked IP management and IP enrichment via ip-api.com (free, no API key required).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.auth import get_current_device
from server.db import BlockedIP, get_db

log = logging.getLogger("argos.intelligence")
router = APIRouter()

# ip-api.com fields to request (free tier)
_IPAPI_FIELDS = "status,message,country,regionName,city,isp,org,as,hosting,query"
_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=" + _IPAPI_FIELDS


# ─── PYDANTIC MODELS ──────────────────────────────────────────────────────────

class BlockRequest(BaseModel):
    ip: str
    reason: str
    duration_minutes: Optional[int] = None
    community: bool = False


class BlockedIPResponse(BaseModel):
    ip: str
    reason: str
    device_id: Optional[str] = None
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    community: bool

    model_config = {"from_attributes": True}


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("/blocked", response_model=list[BlockedIPResponse])
async def list_blocked(
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> list[BlockedIPResponse]:
    """List all blocked IP addresses."""
    result = await db.execute(select(BlockedIP).order_by(BlockedIP.blocked_at.desc()))
    rows = result.scalars().all()
    return [BlockedIPResponse.model_validate(row) for row in rows]


@router.post("/blocked", response_model=BlockedIPResponse, status_code=status.HTTP_201_CREATED)
async def block_ip(
    body: BlockRequest,
    db: AsyncSession = Depends(get_db),
    current_device: str = Depends(get_current_device),
) -> BlockedIPResponse:
    """Manually block an IP address (DB-only — does not modify firewall rules)."""
    # Check for existing block
    existing = await db.execute(select(BlockedIP).where(BlockedIP.ip == body.ip))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IP {body.ip} is already blocked.",
        )

    now = datetime.utcnow()
    expires_at: Optional[datetime] = None
    if body.duration_minutes is not None and body.duration_minutes > 0:
        expires_at = now + timedelta(minutes=body.duration_minutes)

    blocked = BlockedIP(
        ip=body.ip,
        reason=body.reason,
        device_id=current_device,
        blocked_at=now,
        expires_at=expires_at,
        community=body.community,
    )
    db.add(blocked)
    await db.commit()
    await db.refresh(blocked)
    return BlockedIPResponse.model_validate(blocked)


@router.delete("/blocked/{ip}")
async def unblock_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """Remove a blocked IP address."""
    result = await db.execute(select(BlockedIP).where(BlockedIP.ip == ip))
    blocked: BlockedIP | None = result.scalar_one_or_none()

    if blocked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IP {ip} not found in blocklist.")

    await db.delete(blocked)
    await db.commit()
    return {"status": "unblocked", "ip": ip}


@router.get("/lookup/{ip}")
async def lookup_ip(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """
    Enrich an IP with threat intelligence.
    Uses intelligence_feeds if available, otherwise falls back to ip-api.com (free).
    """
    # Try the intelligence feeds engine if loaded on app state
    intelligence_feeds = getattr(request.app.state, "intelligence_feeds", None)
    if intelligence_feeds is not None:
        try:
            enriched = await intelligence_feeds.enrich_ip(ip)
            if enriched:
                return enriched
        except Exception as exc:
            log.warning("intelligence_feeds.enrich_ip failed for %s: %s", ip, exc)

    # Fallback: ip-api.com (free, no API key, max 45 requests/minute for HTTP)
    geolocation: dict = {}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(_IPAPI_URL.format(ip=ip))
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                geolocation = {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "hosting": data.get("hosting", False),
                }
            else:
                geolocation = {"error": data.get("message", "Unknown error from ip-api.com")}
    except httpx.HTTPError as exc:
        log.warning("ip-api.com lookup failed for %s: %s", ip, exc)
        geolocation = {"error": "Geolocation lookup unavailable."}

    return {
        "ip": ip,
        "sources": {
            "geolocation": geolocation,
        },
    }
