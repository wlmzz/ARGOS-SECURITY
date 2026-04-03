"""
ARGOS — Database Layer
SQLAlchemy 2.x async with aiosqlite (SQLite for dev, PostgreSQL for prod).
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import AsyncGenerator, Optional

from fastapi import Request
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship

# ─── DATABASE URL ─────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///" + os.path.expanduser("~/.argos/server.db"),
)


# ─── ORM BASE ─────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ─── MODELS ───────────────────────────────────────────────────────────────────

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    platform = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    version = Column(String, nullable=True)
    autonomy = Column(String, nullable=True)
    status = Column(String, default="online", nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    threats = relationship("ThreatEvent", back_populates="device", cascade="all, delete-orphan")
    tokens = relationship("APIToken", back_populates="device", cascade="all, delete-orphan")
    honeypot_sessions = relationship("HoneypotSession", back_populates="device", cascade="all, delete-orphan")
    blocked_ips = relationship("BlockedIP", back_populates="device")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    threat_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    source_port = Column(Integer, nullable=True)
    target_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    description = Column(Text, nullable=False)
    raw_data = Column(Text, nullable=True)          # JSON string
    action_taken = Column(String, nullable=True)
    ai_analysis = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    evidence_path = Column(String, nullable=True)
    resolved = Column(Boolean, default=False, nullable=False)

    # Relationships
    device = relationship("Device", back_populates="threats")
    training_examples = relationship("TrainingExample", back_populates="event_ref")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    ip = Column(String, primary_key=True)
    reason = Column(String, nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    community = Column(Boolean, default=False, nullable=False)

    # Relationships
    device = relationship("Device", back_populates="blocked_ips")


class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    attacker_ip = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)
    interactions = Column(Integer, default=0, nullable=False)
    bytes_received = Column(Integer, default=0, nullable=False)
    evidence_path = Column(String, nullable=True)

    # Relationships
    device = relationship("Device", back_populates="honeypot_sessions")


class TrainingExample(Base):
    __tablename__ = "training_examples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, ForeignKey("threat_events.id"), nullable=True)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    source = Column(String, nullable=False)          # human / ai / claude
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    used_in_training = Column(Boolean, default=False, nullable=False)

    # Relationships
    event_ref = relationship("ThreatEvent", back_populates="training_examples")


class APIToken(Base):
    __tablename__ = "api_tokens"

    token = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)

    # Relationships
    device = relationship("Device", back_populates="tokens")


# ─── DATABASE CLASS ───────────────────────────────────────────────────────────

class Database:
    """Manages the async SQLAlchemy engine and session factory."""

    def __init__(self, url: str = DATABASE_URL) -> None:
        self.url = url
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    async def init(self) -> None:
        """Create the engine, configure SQLite pragmas, and create all tables."""
        # Ensure the directory exists for SQLite
        if self.url.startswith("sqlite"):
            db_path = self.url.split("///")[-1]
            db_path = os.path.expanduser(db_path)
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        connect_args: dict = {}
        if "sqlite" in self.url:
            connect_args["check_same_thread"] = False

        self._engine = create_async_engine(
            self.url,
            echo=False,
            connect_args=connect_args,
        )

        # Enable WAL mode for better concurrent reads on SQLite
        if "sqlite" in self.url:
            from sqlalchemy import text

            async with self._engine.begin() as conn:
                await conn.execute(text("PRAGMA journal_mode=WAL"))
                await conn.execute(text("PRAGMA foreign_keys=ON"))

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

        # Create all tables
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def get_session(self) -> AsyncSession:
        """Return a new AsyncSession. Caller is responsible for closing it."""
        if self._session_factory is None:
            raise RuntimeError("Database.init() has not been called yet.")
        return self._session_factory()


# ─── FASTAPI DEPENDENCY ───────────────────────────────────────────────────────

async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields an AsyncSession from the app-level Database."""
    db: Database = request.app.state.db
    async with db.get_session() as session:
        yield session
