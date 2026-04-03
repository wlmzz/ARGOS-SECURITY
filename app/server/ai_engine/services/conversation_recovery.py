"""
ARGOS — Conversation Recovery
Adapted from Claude Code utils/conversationRecovery.ts (Anthropic Inc.)

Session resume with interruption detection and message chain cleanup.

Three interruption kinds (same logic as Claude Code):
  none              — turn completed normally; resume is a no-op
  interrupted_turn  — tool was mid-execution; inject "Continue from where you left off"
  interrupted_prompt — user sent a message but model never responded

After recovery the message list is always API-valid:
  - Orphaned tool_use blocks (no matching tool_result) are removed
  - Whitespace-only assistant messages are removed
  - If last relevant message is 'user', a synthetic assistant sentinel is appended

Usage:
    from .conversation_recovery import load_conversation_for_resume

    result = await load_conversation_for_resume("session-id")
    if result:
        messages = result.messages
        if result.interruption == "interrupted_turn":
            # engine will auto-continue
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Tuple

from .session_storage import (
    load_transcript,
    load_metadata,
    SessionMetadata,
    get_sessions_dir,
)
from pathlib import Path

log = logging.getLogger("argos.conversation_recovery")

# ─── TYPES ────────────────────────────────────────────────────────────────────

InterruptionKind = Literal["none", "interrupted_turn", "interrupted_prompt"]

CONTINUATION_MESSAGE = {
    "role":    "user",
    "content": "Continue from where you left off.",
    "_meta":   True,   # synthetic — not shown to operator
}

NO_RESPONSE_SENTINEL = {
    "role":    "assistant",
    "content": "[No response recorded]",
    "_sentinel": True,
}


@dataclass
class RecoveryResult:
    messages:    List[dict]
    interruption: InterruptionKind
    metadata:    Optional[SessionMetadata] = None
    session_id:  Optional[str] = None


# ─── FILTERING ────────────────────────────────────────────────────────────────

def filter_unresolved_tool_uses(messages: List[dict]) -> List[dict]:
    """
    Remove assistant messages with tool_calls that have no matching
    tool result in a subsequent user message.

    Orphaned tool_uses occur when the session is interrupted mid-tool:
    the tool call was recorded but the process died before the result arrived.
    These cause API errors on resume if left in the context.

    Same logic as Claude Code's filterUnresolvedToolUses().
    """
    # Build set of call_ids that have results
    result_ids: set[str] = set()
    for msg in messages:
        if msg.get("role") == "tool":
            call_id = msg.get("tool_call_id", "")
            if call_id:
                result_ids.add(call_id)
        # OpenAI format: tool results as user messages with tool_call_id
        if msg.get("role") == "user":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        result_ids.add(block.get("tool_use_id", ""))

    filtered = []
    for msg in messages:
        if msg.get("role") == "assistant":
            tool_calls = msg.get("tool_calls", []) or []
            unresolved = [
                tc for tc in tool_calls
                if tc.get("id", "") not in result_ids
            ]
            if unresolved and not msg.get("content", "").strip():
                # Pure tool-use message with no text — skip entirely
                continue
            if unresolved:
                # Has text content — keep but strip unresolved tool calls
                filtered.append({**msg, "tool_calls": [
                    tc for tc in tool_calls if tc.get("id", "") in result_ids
                ]})
                continue
        filtered.append(msg)

    return filtered


def filter_whitespace_only_assistant(messages: List[dict]) -> List[dict]:
    """
    Remove assistant messages whose text content is only whitespace.
    These occur when the model outputs '\n\n' before a thinking block
    and the session is cancelled mid-stream.
    """
    return [
        m for m in messages
        if not (
            m.get("role") == "assistant"
            and not m.get("tool_calls")
            and not str(m.get("content", "")).strip()
        )
    ]


# ─── INTERRUPTION DETECTION ───────────────────────────────────────────────────

def detect_interruption(messages: List[dict]) -> InterruptionKind:
    """
    Inspect the last turn-relevant message to determine if the session
    was interrupted, and if so how.

    Turn-relevant: role is 'user' or 'assistant' (not '_meta' sentinel).
    """
    relevant = [
        m for m in messages
        if m.get("role") in ("user", "assistant")
        and not m.get("_sentinel")
    ]

    if not relevant:
        return "none"

    last = relevant[-1]
    role = last.get("role", "")

    if role == "assistant":
        # Completed normally
        return "none"

    if role == "user":
        # Check if it's a synthetic meta message (e.g. our own CONTINUATION_MESSAGE)
        if last.get("_meta"):
            return "none"

        # Check if it's a tool result (mid-tool interruption)
        content = last.get("content", [])
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in content
        ):
            return "interrupted_turn"

        # Plain text user message — model never responded
        return "interrupted_prompt"

    return "none"


# ─── DESERIALIZE ──────────────────────────────────────────────────────────────

def deserialize_messages(raw_messages: List[dict]) -> Tuple[List[dict], InterruptionKind]:
    """
    Clean up a raw message list loaded from disk and detect interruption state.

    Pipeline (same as Claude Code):
      1. filter_unresolved_tool_uses
      2. filter_whitespace_only_assistant
      3. detect_interruption
      4. If interrupted_turn → inject CONTINUATION_MESSAGE
      5. If last relevant is 'user' → append NO_RESPONSE_SENTINEL

    Returns (cleaned_messages, interruption_kind).
    """
    messages = filter_unresolved_tool_uses(raw_messages)
    messages = filter_whitespace_only_assistant(messages)

    interruption = detect_interruption(messages)

    if interruption == "interrupted_turn":
        messages.append(dict(CONTINUATION_MESSAGE))
        interruption = "interrupted_prompt"

    # Append sentinel if last turn-relevant is 'user'
    relevant = [
        m for m in messages
        if m.get("role") in ("user", "assistant") and not m.get("_sentinel")
    ]
    if relevant and relevant[-1].get("role") == "user":
        messages.append(dict(NO_RESPONSE_SENTINEL))

    return messages, interruption


# ─── MAIN ENTRY POINT ─────────────────────────────────────────────────────────

async def load_conversation_for_resume(
    session_id:   str,
    sessions_dir: Optional[Path] = None,
    full:         bool = False,
) -> Optional[RecoveryResult]:
    """
    Load a session from disk and prepare it for resume.

    Returns None if no transcript exists for the given session_id.
    Returns RecoveryResult with cleaned messages and interruption state.

    The caller should check result.interruption:
      - "none"              → just restore context; wait for user input
      - "interrupted_prompt"→ re-send the queued user message (auto-continue)
    """
    base = sessions_dir or get_sessions_dir()

    raw = await load_transcript(session_id, base, full=full)
    if not raw:
        return None

    metadata = await load_metadata(session_id, base)

    messages, interruption = deserialize_messages(raw)

    log.info(
        "[recovery] Session %s: %d messages loaded, interruption=%s",
        session_id, len(messages), interruption,
    )

    return RecoveryResult(
        messages     = messages,
        interruption = interruption,
        metadata     = metadata,
        session_id   = session_id,
    )


async def load_most_recent_session(
    sessions_dir: Optional[Path] = None,
) -> Optional[RecoveryResult]:
    """
    Load the most recently modified session (--continue equivalent).
    Returns None if no sessions exist.
    """
    from .session_storage import list_sessions
    base = sessions_dir or get_sessions_dir()
    sessions = await list_sessions(base)
    if not sessions:
        return None
    return await load_conversation_for_resume(sessions[0].session_id, base)
