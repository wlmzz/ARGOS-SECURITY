"""
ARGOS — Async Sleep Utilities
Adapted from Claude Code utils/sleep.ts (Anthropic Inc.)

abort_sleep(ms, abort_event) — resolves after ms, or when abort_event is set.
with_timeout(coro, ms, message) — race a coroutine against a deadline.

Used by polling loops, backoff strategies, and agent orchestration
to ensure clean shutdown when sessions are cancelled.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Optional, TypeVar

T = TypeVar("T")


async def abort_sleep(
    ms: float,
    abort_event: Optional[asyncio.Event] = None,
    *,
    throw_on_abort: bool = False,
) -> None:
    """
    Sleep for `ms` milliseconds, or wake up early when `abort_event` is set.

    By default, abort resolves silently — the caller should check
    `abort_event.is_set()` after the await.

    Pass `throw_on_abort=True` to raise `asyncio.CancelledError` on abort;
    useful when the sleep is deep inside a retry loop and you want the
    exception to bubble up and cancel the whole operation.

    Python equivalent of Claude Code's `sleep(ms, signal, opts)`.
    """
    if ms <= 0:
        if abort_event and abort_event.is_set():
            if throw_on_abort:
                raise asyncio.CancelledError("abort_sleep: abort already set")
            return
        await asyncio.sleep(0)
        return

    if abort_event is None:
        await asyncio.sleep(ms / 1000.0)
        return

    # If already aborted before we even start, resolve/reject immediately
    if abort_event.is_set():
        if throw_on_abort:
            raise asyncio.CancelledError("abort_sleep: abort already set")
        return

    sleep_coro = asyncio.sleep(ms / 1000.0)
    abort_coro = abort_event.wait()

    done, pending = await asyncio.wait(
        [asyncio.ensure_future(sleep_coro), asyncio.ensure_future(abort_coro)],
        return_when=asyncio.FIRST_COMPLETED,
    )

    # Cancel the loser
    for task in pending:
        task.cancel()

    if abort_event.is_set() and throw_on_abort:
        raise asyncio.CancelledError("abort_sleep: aborted")


async def with_timeout(
    coro: Awaitable[T],
    ms: float,
    message: str,
) -> T:
    """
    Race `coro` against a `ms`-millisecond deadline.
    Raises `asyncio.TimeoutError(message)` if the deadline is hit.

    Does NOT cancel the underlying coroutine — control returns to the
    caller, but the coroutine keeps running if it holds internal state.
    Use `asyncio.wait_for` when you want hard cancellation.

    Python equivalent of Claude Code's `withTimeout(promise, ms, message)`.
    """
    try:
        return await asyncio.wait_for(asyncio.ensure_future(coro), timeout=ms / 1000.0)
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(message)
