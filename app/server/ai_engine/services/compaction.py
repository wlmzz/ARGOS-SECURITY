"""
ARGOS — Auto-Compaction Service
Adapted from Claude Code services/compact/compact.ts (Anthropic Inc.)

Tracks conversation token usage and triggers compaction when Seneca-32B's
context window fills up. Adapted thresholds for QwQ-32B's 32K window.

Compact trigger (same logic as Claude Code):
  - Estimate tokens in current conversation
  - If > COMPACT_THRESHOLD (80%) of CONTEXT_WINDOW → compact
  - Summarize old messages → inject as <compact-context> → continue

After compaction the conversation is rebuilt as:
  [system_prompt] + [compact_summary_user_msg] + [recent_tail]
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

log = logging.getLogger("argos.compaction")

# ─── CONTEXT WINDOW CONFIG (Seneca-32B / QwQ-32B) ────────────────────────────

CONTEXT_WINDOW      = 32_768   # QwQ-32B context window (tokens)
COMPACT_THRESHOLD   = 0.80     # trigger at 80% full
COMPACT_AT_TOKENS   = int(CONTEXT_WINDOW * COMPACT_THRESHOLD)   # 26 214
COMPACT_MAX_SUMMARY = 4_096    # max output tokens for the summary LLM call
# After compaction keep a tail of recent messages to preserve continuity
COMPACT_TAIL_MSGS   = 6        # how many recent messages to keep verbatim

# ─── PROMPTS ─────────────────────────────────────────────────────────────────

_COMPACT_SYSTEM = """\
You are the ARGOS compaction assistant.
Summarize the conversation below into a compact context block.
Focus on: key findings, decisions made, tools called, and any pending work.
Be concise. Use bullet points. Max 300 words.\
"""


def _compact_prompt(messages: list[dict]) -> str:
    lines = ["Summarize this conversation into a compact context block.\n"]
    for m in messages:
        role    = m.get("role", "")
        content = m.get("content") or ""
        if isinstance(content, list):
            # flatten tool result / multipart content
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p)
                for p in content
            )
        lines.append(f"[{role.upper()}]: {str(content)[:500]}")
    return "\n".join(lines)


# ─── TOKEN ESTIMATION ─────────────────────────────────────────────────────────

def estimate_tokens(messages: list[dict]) -> int:
    """Rough token count: 4 chars ≈ 1 token (same heuristic as Claude Code)."""
    total = 0
    for m in messages:
        content = m.get("content") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", str(p)) if isinstance(p, dict) else str(p)
                for p in content
            )
        total += len(str(content)) // 4
        # tool_calls also consume tokens
        for tc in m.get("tool_calls") or []:
            total += len(str(tc)) // 4
    return total


def needs_compaction(messages: list[dict], system_prompt: str = "") -> bool:
    """Return True if the context exceeds the compact threshold."""
    system_tokens = len(system_prompt) // 4
    msg_tokens    = estimate_tokens(messages)
    used          = system_tokens + msg_tokens
    pct           = used / CONTEXT_WINDOW
    log.debug(
        "[Compact] Context: %d tokens (~%.0f%% of %d)",
        used, pct * 100, CONTEXT_WINDOW,
    )
    return used >= COMPACT_AT_TOKENS


# ─── COMPACTION ENGINE ────────────────────────────────────────────────────────

class CompactionEngine:
    """
    Watches token usage and compacts the conversation when needed.
    Integrated into SenecaEngine._run_loop() at the top of each iteration.
    """

    def __init__(
        self,
        llama_url: str  = "http://localhost:8080",
        model: str      = "argos-current",
    ) -> None:
        self.llama_url = llama_url
        self.model     = model
        self._compact_count: int = 0

    @property
    def compact_count(self) -> int:
        return self._compact_count

    async def maybe_compact(
        self,
        messages:      list[dict],
        system_prompt: str = "",
    ) -> list[dict]:
        """
        Check if compaction is needed; compact if so.
        Returns (possibly modified) message list.
        Same call site as Claude Code's autoCompact trigger.
        """
        if not needs_compaction(messages, system_prompt):
            return messages

        log.info(
            "[Compact] Context at/above threshold — compacting (pass #%d)",
            self._compact_count + 1,
        )
        compacted = await self._compact(messages)
        if compacted is not None:
            self._compact_count += 1
            log.info(
                "[Compact] Done. Messages: %d → %d",
                len(messages), len(compacted),
            )
            return compacted

        log.warning("[Compact] Compaction failed — proceeding with full context")
        return messages

    async def _compact(self, messages: list[dict]) -> Optional[list[dict]]:
        """
        Summarize old messages, keeping a tail of recent ones verbatim.
        Returns new message list with a <compact-context> injection.
        """
        if len(messages) <= COMPACT_TAIL_MSGS + 1:
            return None   # too short to compact

        tail_start = max(0, len(messages) - COMPACT_TAIL_MSGS)
        to_compact = messages[:tail_start]
        tail       = messages[tail_start:]

        summary = await self._summarize(to_compact)
        if not summary:
            return None

        from ..constants.xml import COMPACT_CONTEXT_OPEN, COMPACT_CONTEXT_CLOSE
        compact_msg = {
            "role":    "user",
            "content": (
                f"{COMPACT_CONTEXT_OPEN}\n"
                "The conversation above has been compacted. Summary:\n\n"
                f"{summary}\n"
                f"{COMPACT_CONTEXT_CLOSE}"
            ),
        }
        return [compact_msg] + tail

    async def _summarize(self, messages: list[dict]) -> Optional[str]:
        """Call Seneca (no tools) to produce a compact summary."""
        prompt = _compact_prompt(messages)
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":       self.model,
                        "messages": [
                            {"role": "system", "content": _COMPACT_SYSTEM},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens":  COMPACT_MAX_SUMMARY,
                        "stream":      False,
                    },
                )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
            log.warning("[Compact] Summarize call returned %d", r.status_code)
        except Exception as exc:
            log.warning("[Compact] Summarize failed: %s", exc)
        return None
