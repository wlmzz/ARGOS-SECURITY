"""
ARGOS — Workload Context
Adapted from Claude Code utils/workloadContext.ts (Anthropic Inc.)

Turn-scoped workload tag via Python contextvars.ContextVar.

WHY contextvars (not a global mutable slot):
  Background agents and cron tasks yield at their first await. Without an
  isolated context, a `set_workload('cron')` inside a background task would
  bleed into the parent turn once the event loop resumes it. ContextVar
  isolates state per async chain — same guarantee as Node's AsyncLocalStorage.

Usage:
    from .workload_context import run_with_workload, get_workload, WORKLOAD_CRON

    # Mark a block as background / cron
    async def run_scheduled_scan():
        async with run_with_workload(WORKLOAD_CRON):
            await do_scan()

    # Query inside any coroutine in the chain
    workload = get_workload()   # 'cron' | None
"""
from __future__ import annotations

import contextvars
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator, Optional

# ─── TYPES ────────────────────────────────────────────────────────────────────

# Server-side sanitizer accepts only lowercase [a-z0-9_-]{0,32}
Workload = Optional[str]
WORKLOAD_CRON: Workload = "cron"

# ─── STORAGE ──────────────────────────────────────────────────────────────────

_workload_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "argos_workload", default=None
)


# ─── PUBLIC API ───────────────────────────────────────────────────────────────

def get_workload() -> Optional[str]:
    """
    Return the current workload tag, or None if not set.
    Safe to call from any coroutine — each async chain has its own value.
    """
    return _workload_var.get()


@contextmanager
def run_with_workload_sync(workload: Optional[str]) -> Generator[None, None, None]:
    """
    Synchronous context manager. Sets the workload tag for the duration
    of the block and restores the previous value on exit.

    ALWAYS establishes a new context boundary even when workload is None
    (prevents leaked cron context from prior turns).
    """
    token = _workload_var.set(workload)
    try:
        yield
    finally:
        _workload_var.reset(token)


@asynccontextmanager
async def run_with_workload(workload: Optional[str]) -> AsyncGenerator[None, None]:
    """
    Async context manager. Sets the workload tag for the duration of the
    block and restores the previous value on exit.

    Usage:
        async with run_with_workload(WORKLOAD_CRON):
            await scheduled_scan()
    """
    token = _workload_var.set(workload)
    try:
        yield
    finally:
        _workload_var.reset(token)


def is_background_workload() -> bool:
    """Return True if the current workload is a background (non-interactive) task."""
    return get_workload() == WORKLOAD_CRON
