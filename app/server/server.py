"""
ARGOS — Open Source AI Security Platform
Central Server v0.1.0

FastAPI application — serves agents, dashboard, and mobile app.
Runs the AI engine, stores threat intelligence, broadcasts real-time events.

MIT License
"""

import os
import json
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import asyncio

from server.api import auth, devices, events, dashboard, intelligence, ai_chat
from server.ai_engine.engine import AIEngine
from server.ai_engine.dream import run_dream_scheduler
from server.db import Database, get_db

# ─── LOGGING ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
log = logging.getLogger("argos.server")

# ─── APP LIFECYCLE ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ARGOS Server starting...")
    db = Database()
    await db.init()
    app.state.db = db
    ai_engine = AIEngine()
    await ai_engine.check_ollama()
    app.state.ai_engine = ai_engine
    app.state.ws_manager = WebSocketManager()

    # Start Dream scheduler (memory consolidation — from Claude Code autoDream)
    dream_task = asyncio.create_task(
        run_dream_scheduler(ai_engine._dream, check_interval_minutes=60)
    )
    app.state.dream_task = dream_task

    log.info("ARGOS Server ready")
    yield

    dream_task.cancel()
    log.info("ARGOS Server shutting down")

# ─── WEBSOCKET MANAGER ────────────────────────────────────────────────────────

class WebSocketManager:
    """Manages active WebSocket connections for real-time broadcast."""

    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, client_id: str, ws: WebSocket):
        await ws.accept()
        self.connections[client_id] = ws
        log.info(f"[WS] Connected: {client_id} (total: {len(self.connections)})")

    def disconnect(self, client_id: str):
        self.connections.pop(client_id, None)
        log.info(f"[WS] Disconnected: {client_id} (total: {len(self.connections)})")

    async def broadcast(self, message: dict):
        dead = []
        for cid, ws in self.connections.items():
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

    async def send_to(self, client_id: str, message: dict):
        ws = self.connections.get(client_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(client_id)

# ─── APP ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ARGOS Security Server",
    description="Open Source AI Security Platform — Central Server",
    version="0.1.0",
    lifespan=lifespan,
    redirect_slashes=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(intelligence.router, prefix="/api/intelligence", tags=["intelligence"])
app.include_router(ai_chat.router, prefix="/api/ai", tags=["ai"])

# ─── HEALTH & ROOT ────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "name": "ARGOS Security Server",
        "version": "0.1.0",
        "status": "ok",
        "dashboard": "http://localhost:3000",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

# ─── WEBSOCKET ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(ws: WebSocket, client_id: str, db: Database = Depends(get_db)):
    manager: WebSocketManager = ws.app.state.ws_manager
    await manager.connect(client_id, ws)
    try:
        while True:
            # Keep alive — clients can send pings
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(client_id)

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="ARGOS Central Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--tls", action="store_true", help="Enable TLS")
    parser.add_argument("--cert", default="certs/server.crt")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    ssl_kwargs = {}
    if args.tls:
        ssl_kwargs = {"ssl_certfile": args.cert, "ssl_keyfile": args.key}

    uvicorn.run(
        "server.server:app",
        host=args.host,
        port=args.port,
        log_level="debug" if args.debug else "info",
        **ssl_kwargs
    )

if __name__ == "__main__":
    main()
