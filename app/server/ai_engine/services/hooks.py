"""
ARGOS — Post-Sampling Hooks
Adapted from Claude Code utils/hooks/postSamplingHooks.ts (Anthropic Inc.)

Hooks registered here run after each model turn (when final text response arrives,
no more tool calls). Used for:
  - Threat memory extraction
  - Session memory updates
  - Metrics tracking
  - Alert notifications

Registration pattern is identical to Claude Code's:
  register_hook(name, async_fn)
  execute_hooks(context)
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

log = logging.getLogger("argos.hooks")

# ─── TYPES ────────────────────────────────────────────────────────────────────

@dataclass
class HookContext:
    """
    Passed to every hook. Mirrors Claude Code's REPLHookContext.
    Contains everything a hook might need.
    """
    event:          Optional[dict]  = None   # threat event that was analyzed
    decision:       Optional[dict]  = None   # AI decision result
    messages:       list[dict]      = field(default_factory=list)  # conversation so far
    tool_call_count: int            = 0      # how many tools were called this turn
    turn_duration_s: float          = 0.0
    session_id:     str             = ""
    metadata:       dict            = field(default_factory=dict)


HookFn = Callable[[HookContext], Coroutine[Any, Any, None]]

# ─── REGISTRY ─────────────────────────────────────────────────────────────────

_hooks: dict[str, HookFn] = {}


def register_hook(name: str, fn: HookFn) -> None:
    """Register a named post-sampling hook (overwrites if name exists)."""
    _hooks[name] = fn
    log.debug("[Hooks] Registered: %s", name)


def unregister_hook(name: str) -> None:
    _hooks.pop(name, None)


async def execute_hooks(ctx: HookContext) -> None:
    """
    Execute all registered hooks sequentially.
    Aborts on first unhandled error (same as Claude Code).
    """
    for name, fn in list(_hooks.items()):
        try:
            await fn(ctx)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("[Hooks] Hook '%s' failed: %s", name, exc)


def execute_hooks_background(ctx: HookContext) -> asyncio.Task:
    """Fire-and-forget hooks (non-blocking). Returns task."""
    return asyncio.create_task(execute_hooks(ctx), name="argos-hooks")


# ─── BUILT-IN HOOKS ───────────────────────────────────────────────────────────

def register_memory_extraction_hook(extractor: Any) -> None:
    """
    Hook that triggers ThreatMemoryExtractor after each analysis turn.
    (Claude Code: extractMemories runs at turn-end if main agent wrote no memory)
    """
    async def _hook(ctx: HookContext) -> None:
        if ctx.event and ctx.decision:
            extractor.schedule(ctx.event, ctx.decision)

    register_hook("memory_extraction", _hook)


def register_session_memory_hook(session_memory: Any) -> None:
    """
    Hook that updates SessionMemory with event results.
    (Claude Code: session memory updates every N tool calls)
    """
    async def _hook(ctx: HookContext) -> None:
        if ctx.event and ctx.decision:
            session_memory.on_event_analyzed(ctx.event, ctx.decision)
        if ctx.tool_call_count > 0:
            # rough token estimate: 4 chars per token
            total_chars = sum(len(str(m)) for m in ctx.messages)
            session_memory.on_tool_call(estimated_tokens=total_chars // 4)

    register_hook("session_memory", _hook)


def register_metrics_hook(metrics: Any) -> None:
    """
    Hook that records analysis metrics.
    (Claude Code: logEvent('tengu_turn_complete', {...}))
    """
    async def _hook(ctx: HookContext) -> None:
        if ctx.event and ctx.decision:
            metrics.record_analysis(
                threat_type   = ctx.event.get("threat_type"),
                action        = ctx.decision.get("action"),
                confidence    = ctx.decision.get("confidence", 0),
                tool_calls    = ctx.tool_call_count,
                duration_s    = ctx.turn_duration_s,
            )

    register_hook("metrics", _hook)


def register_dream_hook(dream_engine: Any) -> None:
    """
    Hook that notifies the Dream engine of new events.
    Triggers dream consolidation once enough events accumulate.
    """
    async def _hook(ctx: HookContext) -> None:
        if ctx.event:
            await dream_engine.maybe_dream(new_events=1)

    register_hook("dream", _hook)
