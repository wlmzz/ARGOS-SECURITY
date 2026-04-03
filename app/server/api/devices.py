"""
ARGOS — Devices router.
CRUD for registered agent devices, plus heartbeat and token generation.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.auth import get_current_device
from server.db import APIToken, Device, ThreatEvent, get_db

router = APIRouter()


# ─── PYDANTIC MODELS ──────────────────────────────────────────────────────────

class DeviceRegisterRequest(BaseModel):
    name: str
    platform: str
    version: str = "0.1.0"
    autonomy: str = "semi"
    ip: Optional[str] = None


class DeviceUpdateRequest(BaseModel):
    name: Optional[str] = None
    autonomy: Optional[str] = None
    status: Optional[str] = None


class DeviceResponse(BaseModel):
    id: str
    name: str
    platform: str
    ip: Optional[str] = None
    version: Optional[str] = None
    autonomy: Optional[str] = None
    status: str
    last_seen: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class DeviceDetailResponse(DeviceResponse):
    threats_total: int = 0
    threats_today: int = 0


class RegisterResponse(BaseModel):
    device_id: str
    token: str


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _make_device_id() -> str:
    return uuid.uuid4().hex


def _make_token() -> str:
    return secrets.token_urlsafe(36)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    body: DeviceRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """Register a new agent device and return a Bearer token."""
    device_id = _make_device_id()
    now = datetime.utcnow()

    device = Device(
        id=device_id,
        name=body.name,
        platform=body.platform,
        ip=body.ip,
        version=body.version,
        autonomy=body.autonomy,
        status="online",
        last_seen=now,
        created_at=now,
    )
    db.add(device)

    token_value = _make_token()
    api_token = APIToken(
        token=token_value,
        device_id=device_id,
        name=f"auto:{body.name}",
        created_at=now,
        active=True,
    )
    db.add(api_token)

    await db.commit()

    return RegisterResponse(device_id=device_id, token=token_value)


@router.get("", response_model=list[DeviceResponse])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    _device_id: str = Depends(get_current_device),
) -> list[DeviceResponse]:
    """List all registered devices."""
    result = await db.execute(select(Device).order_by(Device.created_at.desc()))
    devices = result.scalars().all()
    return [DeviceResponse.model_validate(d) for d in devices]


@router.get("/{device_id}", response_model=DeviceDetailResponse)
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> DeviceDetailResponse:
    """Get a single device with threat counts."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device: Device | None = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    # Total threats
    total_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.device_id == device_id)
    )
    threats_total: int = total_result.scalar_one() or 0

    # Today's threats
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    today_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.device_id == device_id,
            func.date(ThreatEvent.timestamp) == today_str,
        )
    )
    threats_today: int = today_result.scalar_one() or 0

    resp = DeviceDetailResponse.model_validate(device)
    resp.threats_total = threats_total
    resp.threats_today = threats_today
    return resp


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str,
    body: DeviceUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> DeviceResponse:
    """Update device name, autonomy, or status."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device: Device | None = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if body.name is not None:
        device.name = body.name
    if body.autonomy is not None:
        device.autonomy = body.autonomy
    if body.status is not None:
        device.status = body.status

    await db.commit()
    await db.refresh(device)
    return DeviceResponse.model_validate(device)


@router.delete("/{device_id}")
async def delete_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """Delete a device and all associated data (cascade)."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device: Device | None = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    await db.delete(device)
    await db.commit()
    return {"status": "deleted"}


@router.post("/{device_id}/heartbeat")
async def heartbeat(
    device_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _current: str = Depends(get_current_device),
) -> dict:
    """Update last_seen timestamp for a device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device: Device | None = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    device.last_seen = datetime.utcnow()
    device.status = "online"

    # Optionally capture IP from request
    client_ip = request.client.host if request.client else None
    if client_ip:
        device.ip = client_ip

    await db.commit()
    return {"status": "ok"}
