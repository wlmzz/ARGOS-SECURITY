"""
ARGOS — Memoize Utilities
Adapted from Claude Code utils/memoize.ts (Anthropic Inc.)

Three caching strategies:
  memoize_with_ttl       — sync, stale-while-revalidate TTL cache
  memoize_with_ttl_async — async, stale-while-revalidate with in-flight dedup
  memoize_with_lru       — sync LRU with bounded memory

Typical ARGOS use cases:
  - Threat intel lookups (TTL cache, stale ok for a few minutes)
  - File content reads (mtime-based; use LRU)
  - CVE database queries (async TTL)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Callable, Generic, Optional, Tuple, TypeVar

log = logging.getLogger("argos.memoize")

T = TypeVar("T")


def _make_key(args: tuple, kwargs: dict) -> str:
    """Serialize args/kwargs to a stable string key."""
    try:
        return json.dumps((args, kwargs), sort_keys=True, default=str)
    except Exception:
        return str((args, kwargs))


# ─── TTL CACHE (sync) ─────────────────────────────────────────────────────────

def memoize_with_ttl(
    fn: Callable,
    ttl_ms: int = 5 * 60 * 1000,  # 5 minutes default
) -> Callable:
    """
    Stale-while-revalidate TTL memoize for synchronous functions.
    - Fresh entry → return immediately
    - Stale entry → return stale value, refresh in background (via asyncio task
      if inside an event loop, else synchronously)
    - No entry → compute and cache

    Returns decorated function with `.cache.clear()` method.
    """
    cache: dict[str, dict] = {}

    def wrapper(*args, **kwargs):
        key = _make_key(args, kwargs)
        entry = cache.get(key)
        now_ms = int(time.monotonic() * 1000)

        if entry is None:
            value = fn(*args, **kwargs)
            cache[key] = {"value": value, "ts": now_ms, "refreshing": False}
            return value

        if now_ms - entry["ts"] > ttl_ms and not entry["refreshing"]:
            entry["refreshing"] = True
            stale_entry = entry

            def _refresh():
                try:
                    new_value = fn(*args, **kwargs)
                    if cache.get(key) is stale_entry:
                        cache[key] = {"value": new_value, "ts": int(time.monotonic() * 1000), "refreshing": False}
                except Exception as exc:
                    log.warning("[memoize_ttl] Background refresh failed: %s", exc)
                    if cache.get(key) is stale_entry:
                        del cache[key]

            try:
                loop = asyncio.get_running_loop()
                loop.run_in_executor(None, _refresh)
            except RuntimeError:
                _refresh()

            return entry["value"]

        return cache[key]["value"]

    wrapper.cache = type("_Cache", (), {"clear": lambda self: cache.clear()})()
    return wrapper


# ─── TTL CACHE (async) ────────────────────────────────────────────────────────

def memoize_with_ttl_async(
    fn: Callable,
    ttl_ms: int = 5 * 60 * 1000,
) -> Callable:
    """
    Stale-while-revalidate TTL memoize for async functions.
    Includes in-flight deduplication: concurrent cold-miss callers share
    a single coroutine invocation (same pattern as Claude Code's inFlight Map).
    """
    cache: dict[str, dict] = {}
    in_flight: dict[str, asyncio.Future] = {}

    async def wrapper(*args, **kwargs):
        key = _make_key(args, kwargs)
        entry = cache.get(key)
        now_ms = int(time.monotonic() * 1000)

        if entry is None:
            # In-flight deduplication
            pending = in_flight.get(key)
            if pending is not None:
                return await asyncio.shield(pending)

            loop = asyncio.get_event_loop()
            fut: asyncio.Future = loop.create_future()
            in_flight[key] = fut
            try:
                value = await fn(*args, **kwargs)
                if in_flight.get(key) is fut:
                    cache[key] = {"value": value, "ts": now_ms, "refreshing": False}
                fut.set_result(value)
                return value
            except Exception as exc:
                fut.set_exception(exc)
                raise
            finally:
                if in_flight.get(key) is fut:
                    del in_flight[key]

        if now_ms - entry["ts"] > ttl_ms and not entry["refreshing"]:
            entry["refreshing"] = True
            stale_entry = entry

            async def _refresh():
                try:
                    new_value = await fn(*args, **kwargs)
                    if cache.get(key) is stale_entry:
                        cache[key] = {"value": new_value, "ts": int(time.monotonic() * 1000), "refreshing": False}
                except Exception as exc:
                    log.warning("[memoize_ttl_async] Refresh failed: %s", exc)
                    if cache.get(key) is stale_entry:
                        del cache[key]

            asyncio.ensure_future(_refresh())
            return entry["value"]

        return cache[key]["value"]

    def _clear():
        cache.clear()
        in_flight.clear()

    wrapper.cache = type("_Cache", (), {"clear": lambda self: _clear()})()
    return wrapper


# ─── LRU CACHE ────────────────────────────────────────────────────────────────

class _LRUCache(Generic[T]):
    """Simple LRU cache backed by an OrderedDict."""

    def __init__(self, max_size: int = 100) -> None:
        self._max = max_size
        self._data: OrderedDict[str, T] = OrderedDict()

    def get(self, key: str) -> Optional[T]:
        if key not in self._data:
            return None
        # peek — do NOT move to end (avoids updating recency on read-only access)
        return self._data[key]

    def set(self, key: str, value: T) -> None:
        if key in self._data:
            del self._data[key]
        self._data[key] = value
        if len(self._data) > self._max:
            self._data.popitem(last=False)  # evict LRU

    def delete(self, key: str) -> bool:
        if key in self._data:
            del self._data[key]
            return True
        return False

    def has(self, key: str) -> bool:
        return key in self._data

    def clear(self) -> None:
        self._data.clear()

    @property
    def size(self) -> int:
        return len(self._data)


def memoize_with_lru(
    fn: Callable,
    key_fn: Optional[Callable] = None,
    max_size: int = 100,
) -> Callable:
    """
    LRU-bounded memoize for synchronous functions.

    key_fn(*args, **kwargs) → str  (defaults to JSON serialization)
    max_size controls how many entries are kept before eviction.

    Returns decorated function with:
      .cache.clear()
      .cache.size()
      .cache.delete(key)
      .cache.get(key)
      .cache.has(key)
    """
    lru: _LRUCache = _LRUCache(max_size)
    _key_fn = key_fn or (lambda *a, **kw: _make_key(a, kw))

    def wrapper(*args, **kwargs):
        key = _key_fn(*args, **kwargs)
        cached = lru.get(key)
        if cached is not None:
            return cached
        result = fn(*args, **kwargs)
        lru.set(key, result)
        return result

    class _CacheProxy:
        def clear(self): lru.clear()
        def size(self): return lru.size
        def delete(self, key: str): return lru.delete(key)
        def get(self, key: str): return lru.get(key)
        def has(self, key: str): return lru.has(key)

    wrapper.cache = _CacheProxy()
    return wrapper
