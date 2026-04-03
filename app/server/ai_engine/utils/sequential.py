"""
ARGOS — Sequential Execution Wrapper
Adapted from Claude Code utils/sequential.ts (Anthropic Inc.)

Creates a queue-based wrapper ensuring async calls execute one at a time,
in order, while preserving correct return values for each caller.

Used by MagicDocsService and memory writers to prevent race conditions
on file writes and database updates.

Usage:
    from .sequential import sequential

    @sequential
    async def update_threat_db(event: dict) -> None:
        ...   # guaranteed to never run concurrently

    # Or wrap an existing coroutine function:
    safe_write = sequential(write_to_db)
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


def sequential(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
    """
    Wraps an async function so concurrent calls execute sequentially (FIFO).
    Concurrent callers each get their own result/exception — no dropped calls.

    Adapted from Claude Code's sequential.ts queue pattern.
    """
    queue: asyncio.Queue[tuple[tuple, dict, asyncio.Future]] = asyncio.Queue()
    _running = False

    async def _worker() -> None:
        nonlocal _running
        _running = True
        while not queue.empty():
            args, kwargs, future = await queue.get()
            try:
                result = await fn(*args, **kwargs)
                if not future.done():
                    future.set_result(result)
            except Exception as exc:
                if not future.done():
                    future.set_exception(exc)
            finally:
                queue.task_done()
        _running = False

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        loop    = asyncio.get_event_loop()
        future: asyncio.Future[T] = loop.create_future()
        await queue.put((args, kwargs, future))
        if not _running:
            asyncio.create_task(_worker())
        return await future

    return wrapper
