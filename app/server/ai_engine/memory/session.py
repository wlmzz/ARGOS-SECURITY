"""
ARGOS — Session Memory
Adapted from Claude Code services/SessionMemory/sessionMemory.ts (Anthropic Inc.)

Maintains a running markdown file with the current session's threat context.
Updated in the background after every N tool calls (non-blocking).
Content is injected into the system prompt to give Seneca persistent context.

Thresholds (from sessionMemoryUtils.ts):
  minimumMessageTokensToInit: 10_000  (don't init before meaningful conversation)
  minimumTokensBetweenUpdate:  5_000  (don't re-extract if context hasn't grown)
  toolCallsBetweenUpdates:         3  (update every 3 tool calls)
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from .paths import get_session_memory_path, safe_write, is_memory_enabled

log = logging.getLogger("argos.memory.session")

# ─── CONFIG (from sessionMemoryUtils.ts) ──────────────────────────────────────

MIN_TOKENS_TO_INIT    = 10_000
MIN_TOKENS_BETWEEN    =  5_000
TOOL_CALLS_BETWEEN    =      3
MAX_MEMORY_CHARS      =  4_000   # max chars to inject into system prompt

_SYSTEM = """\
You are the ARGOS session memory manager.
Summarize the current threat investigation session into a compact markdown briefing.
Focus on: active threats, investigation progress, pending actions, key findings.
Max 200 words. Use bullet points.\
"""

# ─── SESSION MEMORY ────────────────────────────────────────────────────────────

class SessionMemory:
    """
    Lightweight in-session threat context that persists across tool calls.
    Injected into system prompt as an additional context section.
    """

    def __init__(
        self,
        session_id: str,
        llama_url: str = "http://localhost:8080",
        model: str = "argos-current",
        project_id: Optional[str] = None,
    ) -> None:
        self.session_id = session_id
        self.llama_url  = llama_url
        self.model      = model
        self.project_id = project_id

        self._content:           str   = ""
        self._tool_calls_since:  int   = 0
        self._tokens_at_last:    int   = 0
        self._initialized:       bool  = False
        self._update_task:       Optional[asyncio.Task] = None
        self._memory_path        = get_session_memory_path(session_id, project_id)

        # Load existing memory if available
        if self._memory_path.exists():
            self._content = self._memory_path.read_text(encoding="utf-8")[:MAX_MEMORY_CHARS]
            self._initialized = True

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_content(self) -> str:
        """Return current session memory for injection into system prompt."""
        return self._content

    def on_tool_call(self, estimated_tokens: int = 0) -> None:
        """
        Called after each tool execution (same trigger as Claude Code).
        Schedules background update if thresholds are met.
        """
        self._tool_calls_since += 1
        delta_tokens = estimated_tokens - self._tokens_at_last

        should_init   = not self._initialized and estimated_tokens >= MIN_TOKENS_TO_INIT
        should_update = (
            self._initialized
            and self._tool_calls_since >= TOOL_CALLS_BETWEEN
            and delta_tokens >= MIN_TOKENS_BETWEEN
        )

        if should_init or should_update:
            self._schedule_update(estimated_tokens)

    def on_event_analyzed(self, event: dict, decision: dict) -> None:
        """
        Lightweight fast-path: directly update memory content from event data
        without calling Seneca (for when Seneca is busy or unavailable).
        """
        ts   = datetime.now().strftime("%H:%M")
        line = (
            f"- [{ts}] **{decision.get('action','?').upper()}** "
            f"{event.get('threat_type','?')} from `{event.get('source_ip','?')}` "
            f"(conf: {decision.get('confidence', 0):.0%})\n"
        )
        self._content = (self._content + line)[-MAX_MEMORY_CHARS:]
        self._initialized = True
        self._persist()

    # ── Background update (forked agent pattern from Claude Code) ─────────────

    def _schedule_update(self, current_tokens: int) -> None:
        """Non-blocking: schedule background memory update."""
        if self._update_task and not self._update_task.done():
            return   # already running
        self._tokens_at_last    = current_tokens
        self._tool_calls_since  = 0
        self._update_task = asyncio.create_task(
            self._background_update(),
            name=f"session-memory-{self.session_id}",
        )

    async def _background_update(self) -> None:
        try:
            content = await self._generate_summary()
            if content:
                self._content = content[:MAX_MEMORY_CHARS]
                self._initialized = True
                self._persist()
                log.debug("[SessionMemory] Updated for session %s", self.session_id)
        except Exception as exc:
            log.debug("[SessionMemory] Update failed: %s", exc)

    async def _generate_summary(self) -> Optional[str]:
        if not self._content:
            return None
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":    self.model,
                        "messages": [
                            {"role": "system",    "content": _SYSTEM},
                            {"role": "user",      "content": f"Current session context:\n{self._content}"},
                        ],
                        "temperature": 0.1,
                        "max_tokens":  300,
                        "stream":      False,
                    },
                )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass
        return None

    def _persist(self) -> None:
        if is_memory_enabled() and self._content:
            try:
                safe_write(self._memory_path, self._content)
            except Exception:
                pass

    def to_system_section(self) -> str:
        """Format memory as a system prompt section (injected by prompts/sections.py)."""
        if not self._content:
            return ""
        return (
            "\n\n## Session Memory\n"
            "*Running context from this investigation session:*\n\n"
            + self._content
        )
