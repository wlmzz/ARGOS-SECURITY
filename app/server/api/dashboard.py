"""
ARGOS — Dashboard router.
Aggregated overview endpoint for the web dashboard and mobile app.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.auth import get_current_device
from server.db import BlockedIP, Device, HoneypotSession, ThreatEvent, get_db

log = logging.getLogger("argos.dashboard")
router = APIRouter()


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("/overview")
async def overview(
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """
    Return complete dashboard data in a single request.
    Includes stats, recent events, threat type breakdown, and hourly chart.
    """
    now = datetime.utcnow()
    today_str = now.strftime("%Y-%m-%d")
    week_ago = now - timedelta(days=7)

    # ── Stats ────────────────────────────────────────────────────────────────

    # Total threats ever
    total_result = await db.execute(select(func.count(ThreatEvent.id)))
    total_threats: int = total_result.scalar_one() or 0

    # Threats today
    today_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            func.date(ThreatEvent.timestamp) == today_str
        )
    )
    threats_today: int = today_result.scalar_one() or 0

    # Threats this week
    week_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.timestamp >= week_ago
        )
    )
    threats_week: int = week_result.scalar_one() or 0

    # Blocked IPs
    blocked_result = await db.execute(select(func.count(BlockedIP.ip)))
    blocked_ips: int = blocked_result.scalar_one() or 0

    # Devices online vs total
    devices_total_result = await db.execute(select(func.count(Device.id)))
    devices_total: int = devices_total_result.scalar_one() or 0

    devices_online_result = await db.execute(
        select(func.count(Device.id)).where(Device.status == "online")
    )
    devices_online: int = devices_online_result.scalar_one() or 0

    # Critical threats today
    critical_today_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.severity == "critical",
            func.date(ThreatEvent.timestamp) == today_str,
        )
    )
    critical_today: int = critical_today_result.scalar_one() or 0

    # Active honeypots (sessions with no ended_at)
    honeypots_result = await db.execute(
        select(func.count(HoneypotSession.id)).where(
            HoneypotSession.ended_at == None  # noqa: E711
        )
    )
    active_honeypots: int = honeypots_result.scalar_one() or 0

    # ── Recent events (last 20) ───────────────────────────────────────────────

    recent_result = await db.execute(
        select(ThreatEvent)
        .order_by(ThreatEvent.timestamp.desc())
        .limit(20)
    )
    recent_events_rows = recent_result.scalars().all()
    recent_events = [
        {
            "id": e.id,
            "device_id": e.device_id,
            "timestamp": e.timestamp.isoformat(),
            "threat_type": e.threat_type,
            "severity": e.severity,
            "source_ip": e.source_ip,
            "source_port": e.source_port,
            "target_port": e.target_port,
            "protocol": e.protocol,
            "description": e.description,
            "action_taken": e.action_taken,
            "ai_analysis": e.ai_analysis,
            "ai_confidence": e.ai_confidence,
            "resolved": e.resolved,
        }
        for e in recent_events_rows
    ]

    # ── Threat types breakdown ────────────────────────────────────────────────

    threat_types_result = await db.execute(
        select(ThreatEvent.threat_type, func.count(ThreatEvent.id).label("count"))
        .group_by(ThreatEvent.threat_type)
        .order_by(func.count(ThreatEvent.id).desc())
    )
    threat_types = [
        {"type": row.threat_type, "count": row.count}
        for row in threat_types_result.all()
    ]

    # ── Hourly chart for today (24 buckets) ───────────────────────────────────

    # Use SQLite strftime to extract the hour from timestamp
    hourly_result = await db.execute(
        select(
            func.strftime("%H", ThreatEvent.timestamp).label("hour"),
            func.count(ThreatEvent.id).label("count"),
        )
        .where(func.date(ThreatEvent.timestamp) == today_str)
        .group_by(func.strftime("%H", ThreatEvent.timestamp))
    )
    hourly_raw = {row.hour: row.count for row in hourly_result.all()}

    # Fill all 24 hours with 0 if no data
    hourly_chart = [
        {
            "hour": f"{h:02d}:00",
            "count": hourly_raw.get(f"{h:02d}", 0),
        }
        for h in range(24)
    ]

    return {
        "stats": {
            "total_threats": total_threats,
            "threats_today": threats_today,
            "threats_week": threats_week,
            "blocked_ips": blocked_ips,
            "devices_online": devices_online,
            "devices_total": devices_total,
            "critical_today": critical_today,
            "active_honeypots": active_honeypots,
        },
        "recent_events": recent_events,
        "threat_types": threat_types,
        "hourly_chart": hourly_chart,
    }
