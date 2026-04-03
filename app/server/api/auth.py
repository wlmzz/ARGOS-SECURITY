"""
ARGOS — Auth middleware and router.
Validates Bearer tokens stored in the api_tokens table.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db import APIToken, Device, get_db

# ─── SECURITY ─────────────────────────────────────────────────────────────────

security = HTTPBearer()
router = APIRouter()


# ─── DEPENDENCY ───────────────────────────────────────────────────────────────

async def get_current_device(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> str:
    """
    Validate Bearer token against the api_tokens table.
    Returns the associated device_id on success.
    Raises HTTP 401 on failure.
    """
    token_value = credentials.credentials

    result = await db.execute(
        select(APIToken).where(
            APIToken.token == token_value,
            APIToken.active == True,  # noqa: E712
        )
    )
    api_token: APIToken | None = result.scalar_one_or_none()

    if api_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return api_token.device_id


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("/me")
async def me(
    device_id: str = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify token and return the associated device info."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device: Device | None = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device associated with token not found.",
        )

    return {"device_id": device_id, "authenticated": True}
