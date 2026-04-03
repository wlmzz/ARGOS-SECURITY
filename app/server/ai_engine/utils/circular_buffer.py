"""
ARGOS — Circular Buffer
Adapted from Claude Code utils/CircularBuffer.ts (Anthropic Inc.)

Fixed-size ring buffer that evicts the oldest item when full.
Useful for:
  - Rolling event windows (last N threat detections)
  - Command / tool-call history
  - Error log rotation
  - Conversation history sampling windows
"""
from __future__ import annotations

from typing import Generic, Iterator, List, Optional, TypeVar

T = TypeVar("T")


class CircularBuffer(Generic[T]):
    """
    Fixed-capacity ring buffer with O(1) add and O(n) iteration.

    >>> buf = CircularBuffer(3)
    >>> buf.add(1); buf.add(2); buf.add(3); buf.add(4)
    >>> buf.to_list()
    [2, 3, 4]
    """

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("CircularBuffer capacity must be >= 1")
        self._capacity = capacity
        self._buffer: List[Optional[T]] = [None] * capacity
        self._head: int = 0   # write pointer (next slot)
        self._size: int = 0

    # ─── WRITES ───────────────────────────────────────────────────────────────

    def add(self, item: T) -> None:
        """Add an item. Evicts the oldest item if the buffer is full."""
        self._buffer[self._head] = item
        self._head = (self._head + 1) % self._capacity
        if self._size < self._capacity:
            self._size += 1

    def add_all(self, items: List[T]) -> None:
        """Add multiple items at once."""
        for item in items:
            self.add(item)

    # ─── READS ────────────────────────────────────────────────────────────────

    def get_recent(self, count: int) -> List[T]:
        """
        Return the most recent `count` items in chronological order.
        Returns fewer items if the buffer holds fewer than `count`.
        """
        available = min(count, self._size)
        if available == 0:
            return []

        start = 0 if self._size < self._capacity else self._head
        result: List[T] = []
        for i in range(available):
            idx = (start + self._size - available + i) % self._capacity
            result.append(self._buffer[idx])  # type: ignore[arg-type]
        return result

    def to_list(self) -> List[T]:
        """Return all items in chronological order (oldest → newest)."""
        if self._size == 0:
            return []
        start = 0 if self._size < self._capacity else self._head
        return [
            self._buffer[(start + i) % self._capacity]  # type: ignore[misc]
            for i in range(self._size)
        ]

    # ─── MISC ─────────────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Remove all items."""
        self._buffer = [None] * self._capacity
        self._head = 0
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def __iter__(self) -> Iterator[T]:
        return iter(self.to_list())

    def __repr__(self) -> str:
        return f"CircularBuffer(capacity={self._capacity}, size={self._size})"
