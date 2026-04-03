"""
ARGOS — File Read Cache
Adapted from Claude Code utils/fileReadCache.ts (Anthropic Inc.)

In-memory mtime-based file content cache.
Eliminates redundant file reads in tight edit loops (read → edit → read).

Cache invalidation: automatic on file mtime change.
Cache eviction: FIFO when max_size is exceeded (oldest entry dropped).

Usage:
    from .file_read_cache import file_read_cache

    content = file_read_cache.read_file("/path/to/file.py")
    # or use the global singleton directly
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("argos.file_read_cache")

_DEFAULT_MAX_SIZE = 1000


# ─── CACHE ENTRY ──────────────────────────────────────────────────────────────

@dataclass
class _CachedFile:
    content: str
    mtime:   float   # os.stat().st_mtime_ns (nanoseconds → float for precision)


# ─── CACHE CLASS ──────────────────────────────────────────────────────────────

class FileReadCache:
    """
    LRU-like file content cache with automatic mtime invalidation.
    Thread-safe for asyncio single-threaded loops; not safe for multi-threading.
    """

    def __init__(self, max_size: int = _DEFAULT_MAX_SIZE) -> None:
        self._max_size = max_size
        self._cache: dict[str, _CachedFile] = {}

    def read_file(self, file_path: str) -> str:
        """
        Return file content. Uses cached version if mtime is unchanged.
        Raises OSError if the file does not exist (removes stale cache entry).
        """
        try:
            stat = os.stat(file_path)
        except OSError:
            self._cache.pop(file_path, None)
            raise

        mtime = stat.st_mtime

        cached = self._cache.get(file_path)
        if cached is not None and cached.mtime == mtime:
            return cached.content

        # Cache miss or stale — read from disk
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read().replace("\r\n", "\n")

        self._cache[file_path] = _CachedFile(content=content, mtime=mtime)

        # FIFO eviction when over capacity
        if len(self._cache) > self._max_size:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
            log.debug("[file_read_cache] Evicted %s", oldest)

        return content

    def invalidate(self, file_path: str) -> None:
        """Remove a specific file from the cache (call after writes)."""
        self._cache.pop(file_path, None)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()

    def get_stats(self) -> dict:
        """Return cache size and list of cached paths (for debugging)."""
        return {
            "size":    len(self._cache),
            "entries": list(self._cache.keys()),
        }

    def __len__(self) -> int:
        return len(self._cache)


# ─── SINGLETON ────────────────────────────────────────────────────────────────

# Application-wide singleton — import and use directly
file_read_cache = FileReadCache()
