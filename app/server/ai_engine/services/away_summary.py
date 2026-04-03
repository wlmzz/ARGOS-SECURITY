"""
ARGOS — Away Summary
Adapted from Claude Code services/awaySummary.ts (Anthropic Inc.)

Generates a short "where we left off" recap when an operator returns
to an active session. Uses Seneca (no tools) on the last 30 messages.

Usage:
    summary = await generate_away_summary(messages, session_memory, llama_url)
    # Returns None if the conversation is too short or Seneca is unavailable.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

log = logging.getLogger("argos.away_summary")

# Number of recent messages to include in the recap (same as Claude Code: 30)
RECENT_WINDOW = 30

_AWAY_SYSTEM = """\
You are the ARGOS session recap assistant.
Write a brief "where we left off" summary for the security operator who just
returned to this session.
Max 3 short sentences: (1) what threat or investigation is active,
(2) what the AI determined or did, (3) what the next step is.\
"""


def _build_prompt(messages: list[dict], session_memory: Optional[str]) -> str:
    lines: list[str] = []

    if session_memory:
        lines.append(f"Session memory (broader context):\n{session_memory}\n")

    lines.append("Recent conversation:\n")
    for m in messages[-RECENT_WINDOW:]:
        role    = m.get("role", "")
        content = m.get("content") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p)
                for p in content
            )
        lines.append(f"[{role.upper()}]: {str(content)[:300]}")

    lines.append(
        "\nThe operator just returned. Write exactly 1-3 sentences. "
        "State the active threat/task, what was decided, and the next step."
    )
    return "\n".join(lines)


async def generate_away_summary(
    messages:       list[dict],
    session_memory: Optional[object] = None,
    llama_url:      str = "http://localhost:8080",
    model:          str = "argos-current",
) -> Optional[str]:
    """
    Generate a "while you were away" recap.
    Returns None if: not enough messages, Seneca unavailable, or error.
    """
    if len(messages) < 3:
        return None

    mem_text: Optional[str] = None
    if session_memory and hasattr(session_memory, "get_content"):
        mem_text = session_memory.get_content() or None

    prompt = _build_prompt(messages, mem_text)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{llama_url}/v1/chat/completions",
                json={
                    "model":       model,
                    "messages": [
                        {"role": "system", "content": _AWAY_SYSTEM},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens":  200,
                    "stream":      False,
                },
            )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
        log.debug("[AwaySummary] Seneca returned %d", r.status_code)
    except Exception as exc:
        log.debug("[AwaySummary] Failed: %s", exc)

    return None
