"""
ARGOS — Events router.
Ingestion, querying, stats, and human decision recording for threat events.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.auth import get_current_device
from server.db import BlockedIP, ThreatEvent, TrainingExample, get_db

log = logging.getLogger("argos.events")
router = APIRouter()


# ─── PYDANTIC MODELS ──────────────────────────────────────────────────────────

class EventIngestRequest(BaseModel):
    device_id: str
    threat_type: str
    severity: str
    source_ip: str
    source_port: Optional[int] = None
    target_port: Optional[int] = None
    protocol: str = "tcp"
    description: str
    raw_data: Optional[Any] = None
    action_taken: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_confidence: Optional[float] = None


class EventResponse(BaseModel):
    id: str
    device_id: str
    timestamp: datetime
    threat_type: str
    severity: str
    source_ip: str
    source_port: Optional[int] = None
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str
    action_taken: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_confidence: Optional[float] = None
    resolved: bool

    model_config = {"from_attributes": True}


class DecideRequest(BaseModel):
    action: str
    reasoning: str
    source: str = "human"


class IngestResponse(BaseModel):
    event_id: str
    ai_decision: dict
    status: str


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _make_event_id(device_id: str, source_ip: str, timestamp: datetime) -> str:
    """Deterministic SHA256-based event ID."""
    raw = f"{device_id}:{source_ip}:{timestamp.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _serialize_raw_data(raw_data: Any) -> Optional[str]:
    if raw_data is None:
        return None
    if isinstance(raw_data, str):
        return raw_data
    try:
        return json.dumps(raw_data)
    except (TypeError, ValueError):
        return str(raw_data)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

# IMPORTANT: /stats/summary must be defined BEFORE /{event_id} to prevent
# FastAPI from matching the literal string "stats" as an event_id parameter.

@router.get("/stats/summary")
async def stats_summary(
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """Return aggregate event statistics."""
    # Total events
    total_result = await db.execute(select(func.count(ThreatEvent.id)))
    total: int = total_result.scalar_one() or 0

    # Critical events
    critical_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.severity == "critical")
    )
    critical: int = critical_result.scalar_one() or 0

    # High events
    high_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.severity == "high")
    )
    high: int = high_result.scalar_one() or 0

    # Blocked IPs
    blocked_result = await db.execute(select(func.count(BlockedIP.ip)))
    blocked_ips: int = blocked_result.scalar_one() or 0

    # Today's events
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    today_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            func.date(ThreatEvent.timestamp) == today_str
        )
    )
    today: int = today_result.scalar_one() or 0

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "blocked_ips": blocked_ips,
        "today": today,
    }


@router.post("", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    body: EventIngestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> IngestResponse:
    """Ingest a threat event from an agent. Runs server-side AI if confidence is low."""
    now = datetime.utcnow()
    event_id = _make_event_id(body.device_id, body.source_ip, now)

    ai_decision: dict = {
        "severity_confirmed": True,
        "action": body.action_taken or "log",
        "reasoning": body.ai_analysis or "Recorded by server.",
        "confidence": body.ai_confidence or 0.0,
        "escalate_to_human": False,
    }

    # Run server-side AI analysis if confidence is missing or low
    needs_ai = body.ai_confidence is None or body.ai_confidence < 0.5
    if needs_ai:
        ai_engine = getattr(request.app.state, "ai_engine", None)
        if ai_engine is not None:
            try:
                event_dict = body.model_dump()
                server_decision = await ai_engine.analyze(event_dict)
                if server_decision:
                    ai_decision = server_decision
            except Exception as exc:
                log.warning("AI engine analysis failed: %s", exc)

    # Persist event
    threat_event = ThreatEvent(
        id=event_id,
        device_id=body.device_id,
        timestamp=now,
        threat_type=body.threat_type,
        severity=body.severity,
        source_ip=body.source_ip,
        source_port=body.source_port,
        target_port=body.target_port,
        protocol=body.protocol,
        description=body.description,
        raw_data=_serialize_raw_data(body.raw_data),
        action_taken=ai_decision.get("action") or body.action_taken,
        ai_analysis=ai_decision.get("reasoning") or body.ai_analysis,
        ai_confidence=ai_decision.get("confidence") or body.ai_confidence,
        evidence_path=None,
        resolved=False,
    )
    db.add(threat_event)
    await db.commit()

    # Broadcast via WebSocket
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager is not None:
        try:
            await ws_manager.broadcast({
                "type": "new_threat",
                "event_id": event_id,
                "device_id": body.device_id,
                "threat_type": body.threat_type,
                "severity": body.severity,
                "source_ip": body.source_ip,
                "description": body.description,
                "action_taken": ai_decision.get("action"),
                "timestamp": now.isoformat(),
                "ai_decision": ai_decision,
            })
        except Exception as exc:
            log.warning("WebSocket broadcast failed: %s", exc)

    return IngestResponse(event_id=event_id, ai_decision=ai_decision, status="accepted")


@router.get("", response_model=list[EventResponse])
async def list_events(
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
    severity: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    threat_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[EventResponse]:
    """List threat events with optional filters and pagination."""
    stmt = select(ThreatEvent).order_by(ThreatEvent.timestamp.desc())

    if severity is not None:
        stmt = stmt.where(ThreatEvent.severity == severity)
    if device_id is not None:
        stmt = stmt.where(ThreatEvent.device_id == device_id)
    if threat_type is not None:
        stmt = stmt.where(ThreatEvent.threat_type == threat_type)

    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    events = result.scalars().all()
    return [EventResponse.model_validate(e) for e in events]


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> EventResponse:
    """Get a single threat event by ID."""
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == event_id))
    event: ThreatEvent | None = result.scalar_one_or_none()

    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

    return EventResponse.model_validate(event)


@router.post("/{event_id}/decide")
async def decide_event(
    event_id: str,
    body: DecideRequest,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """Record a human (or Claude API) decision and save as a training example."""
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == event_id))
    event: ThreatEvent | None = result.scalar_one_or_none()

    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

    # Build training prompt from event data
    prompt = (
        f"Threat Type: {event.threat_type}\n"
        f"Severity: {event.severity}\n"
        f"Source IP: {event.source_ip}\n"
        f"Description: {event.description}\n"
        f"Raw Data: {event.raw_data or 'N/A'}\n"
        f"Prior AI Analysis: {event.ai_analysis or 'N/A'}\n"
        f"Prior AI Confidence: {event.ai_confidence or 'N/A'}"
    )

    response_text = json.dumps({
        "action": body.action,
        "reasoning": body.reasoning,
        "confidence": 1.0,
        "escalate_to_human": False,
    })

    example = TrainingExample(
        event_id=event_id,
        prompt=prompt,
        response=response_text,
        source=body.source,
        created_at=datetime.utcnow(),
        used_in_training=False,
    )
    db.add(example)

    # Mark event as resolved
    event.resolved = True
    event.action_taken = event.action_taken or body.action

    await db.commit()

    return {"status": "decision_recorded", "training_example_saved": True}
