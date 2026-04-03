"""
ARGOS — Analytics / Audit Event Service
Adapted from Claude Code services/analytics/index.ts (Anthropic Inc.)

Provides a PII-safe event queue for threat detections, tool calls, and
session lifecycle events. Events are queued until a sink is attached;
designed so ARGOS can run without a sink (all events simply accumulate
and are replayed when the sink registers).

Key design:
  - NO dependencies on other ai_engine modules (avoids import cycles)
  - Metadata values are restricted to bool/int/float to prevent accidental
    code or file-path logging (PII/sensitive data risk)
  - String metadata requires explicit annotation to acknowledge the risk
  - _PROTO_* keys are filtered before general-access sinks (PII-tagged data
    goes only to privileged sinks, matching the 1P/Datadog split in Claude Code)

ARGOS-specific adaptations:
  - Added `log_threat_event(severity, confidence, **meta)` convenience helper
  - Severity/confidence are passed as numbers (not strings) — safe by design
  - "sink" in ARGOS context = SIEM/audit log writer (Splunk, ELK, etc.)
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Union

log = logging.getLogger("argos.analytics")

# ─── METADATA TYPE ────────────────────────────────────────────────────────────
# Values intentionally limited to bool/int/float to prevent accidentally logging
# code snippets or file paths. Use AnalyticsStr for verified-safe strings.

LogEventMetadata = Dict[str, Union[bool, int, float]]
"""
Safe analytics metadata type.
Keys: str. Values: bool, int, or float ONLY — no strings.
This mirrors Claude Code's LogEventMetadata intentional narrowing.

To log a string, cast it:
    my_str as str  # must have verified it contains no code / file paths
and use AnalyticsStr wrapper (see below).
"""


class AnalyticsStr(str):
    """
    Explicit marker for string analytics values.
    Subclass str; use only when you have verified the value contains no
    code snippets, file paths, or sensitive data.

    Usage:
        metadata={"tool": AnalyticsStr("bash")}  # tool name is safe
    """


# ─── PII FILTERING ────────────────────────────────────────────────────────────

def strip_proto_fields(metadata: dict) -> dict:
    """
    Remove _PROTO_* keys from a payload destined for general-access storage
    (e.g. Datadog, ELK). PII-tagged values in _PROTO_* keys must only reach
    privileged sinks (1P / compliant storage).

    Returns the same dict reference if no _PROTO_ keys are present.
    """
    has_proto = any(k.startswith("_PROTO_") for k in metadata)
    if not has_proto:
        return metadata
    return {k: v for k, v in metadata.items() if not k.startswith("_PROTO_")}


# ─── SINK INTERFACE ───────────────────────────────────────────────────────────

@dataclass
class AnalyticsSink:
    """
    Implement this dataclass and attach via `attach_analytics_sink()`.
    ARGOS ships without a built-in sink — you wire in your SIEM adapter.
    """
    log_event_fn:       Callable[[str, dict], None]
    log_event_async_fn: Callable[[str, dict], asyncio.coroutine]

    def log_event(self, event_name: str, metadata: dict) -> None:
        self.log_event_fn(event_name, metadata)

    async def log_event_async(self, event_name: str, metadata: dict) -> None:
        await self.log_event_async_fn(event_name, metadata)


# ─── QUEUE ────────────────────────────────────────────────────────────────────

@dataclass
class _QueuedEvent:
    event_name: str
    metadata:   dict
    is_async:   bool


_event_queue: list[_QueuedEvent] = []
_sink: Optional[AnalyticsSink] = None


# ─── PUBLIC API ───────────────────────────────────────────────────────────────

def attach_analytics_sink(new_sink: AnalyticsSink) -> None:
    """
    Attach the analytics sink. Idempotent — subsequent calls are no-ops.
    Queued events are drained asynchronously on the next event-loop iteration.
    """
    global _sink
    if _sink is not None:
        return
    _sink = new_sink

    if not _event_queue:
        return

    queued = list(_event_queue)
    _event_queue.clear()

    log.debug("[analytics] Sink attached; draining %d queued events", len(queued))

    async def _drain():
        for ev in queued:
            if ev.is_async:
                await _sink.log_event_async(ev.event_name, ev.metadata)
            else:
                _sink.log_event(ev.event_name, ev.metadata)

    try:
        loop = asyncio.get_event_loop()
        loop.call_soon(lambda: asyncio.ensure_future(_drain()))
    except RuntimeError:
        # No running loop — drain synchronously
        for ev in queued:
            _sink.log_event(ev.event_name, ev.metadata)


def log_event(event_name: str, metadata: LogEventMetadata) -> None:
    """
    Log an analytics event synchronously.
    If no sink is attached, event is queued for later replay.
    """
    if _sink is None:
        _event_queue.append(_QueuedEvent(event_name, dict(metadata), False))
        return
    _sink.log_event(event_name, strip_proto_fields(metadata))


async def log_event_async(event_name: str, metadata: LogEventMetadata) -> None:
    """
    Log an analytics event asynchronously.
    If no sink is attached, event is queued for later replay.
    """
    if _sink is None:
        _event_queue.append(_QueuedEvent(event_name, dict(metadata), True))
        return
    await _sink.log_event_async(event_name, strip_proto_fields(metadata))


# ─── ARGOS CONVENIENCE HELPERS ───────────────────────────────────────────────

def log_threat_event(
    severity: int,
    confidence: float,
    tool_name: str = "",
    session_id: str = "",
    **extra: Union[bool, int, float],
) -> None:
    """
    Log a threat detection event.
    severity: 0–10  (int, safe)
    confidence: 0.0–1.0 (float, safe)
    tool_name / session_id: use AnalyticsStr if non-empty
    """
    meta: dict = {"severity": severity, "confidence": confidence, **extra}
    if tool_name:
        meta["tool_name"] = AnalyticsStr(tool_name)
    if session_id:
        meta["_PROTO_session_id"] = AnalyticsStr(session_id)
    log_event("argos_threat_detected", meta)


def log_tool_call(tool_name: str, success: bool, duration_ms: int) -> None:
    """Log a tool execution result."""
    log_event("argos_tool_call", {
        "success": success,
        "duration_ms": duration_ms,
    })


def _reset_for_testing() -> None:
    """Reset analytics state for unit tests only."""
    global _sink
    _sink = None
    _event_queue.clear()
