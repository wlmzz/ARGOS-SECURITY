"""
ARGOS — Tool Result Persistence
Adapted from Claude Code utils/toolResultStorage.ts (Anthropic Inc.)

When a tool returns a very large output (nmap scan, full log file, large grep),
instead of truncating it blindly we:
  1. Write the full output to disk:  /opt/argos/tool-results/{session_id}/{call_id}.txt
  2. Replace the in-message content with a <persisted-output> stub + 2KB preview
  3. The model can use read_file to retrieve the full content if needed

This prevents context overflow while keeping full data accessible.
Uses the exact same XML tag format as Claude Code so the model understands the pattern.

Thresholds (same order of magnitude as Claude Code's DEFAULT_MAX_RESULT_SIZE_CHARS):
  PERSIST_THRESHOLD  = 20_000 chars  (≈ 5k tokens) — persist anything above this
  PREVIEW_BYTES      = 2_000         (≈ 500 tokens) — preview shown inline

Usage (integrated in ToolExecutor.execute()):
    from .tool_persistence import ToolPersistence
    persistence = ToolPersistence(session_id="session-abc")
    result = await persistence.maybe_persist(
        tool_name="bash", call_id="call-123", content=large_output
    )
    # result is either the original string or a <persisted-output>...</persisted-output> stub
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("argos.tool_persistence")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Char threshold above which we persist to disk (≈5k tokens)
PERSIST_THRESHOLD = int(os.getenv("ARGOS_PERSIST_THRESHOLD", "20000"))

# Size of the inline preview left in the conversation (≈500 tokens)
PREVIEW_BYTES = 2_000

# Root directory for persisted tool results
_DEFAULT_ROOT = Path(os.getenv("ARGOS_TOOL_RESULTS_ROOT", "/opt/argos/tool-results"))
_FALLBACK_ROOT = Path.home() / ".argos" / "tool-results"

# Per-tool thresholds (tool_name → chars). Infinity = never persist (circular).
_TOOL_THRESHOLDS: dict[str, int] = {
    "read_file":    100_000,   # read_file self-references tool results — higher threshold
    "bash":          20_000,
    "grep":          30_000,
    "glob":          10_000,
    "web_fetch":     50_000,
    "web_search":    30_000,
    "query_qdrant":  20_000,
    "get_threat_history": 20_000,
}

# XML tags (identical to Claude Code — model already knows these)
from ..constants.xml import PERSISTED_OUTPUT_OPEN as _TAG_OPEN, PERSISTED_OUTPUT_CLOSE as _TAG_CLOSE
_CLEARED = "[Old tool result content cleared]"


# ─── PERSISTENCE ENGINE ───────────────────────────────────────────────────────

class ToolPersistence:
    """
    Manages on-disk storage of large tool results.
    One instance per session.
    """

    def __init__(
        self,
        session_id: str = "default",
    ) -> None:
        self.session_id = session_id
        root = _DEFAULT_ROOT if _DEFAULT_ROOT.parent.exists() else _FALLBACK_ROOT
        self._dir = root / _sanitize(session_id)
        self._dir.mkdir(parents=True, exist_ok=True)

    def get_threshold(self, tool_name: str) -> int:
        return _TOOL_THRESHOLDS.get(tool_name, PERSIST_THRESHOLD)

    async def maybe_persist(
        self,
        tool_name: str,
        call_id:   str,
        content:   str,
    ) -> str:
        """
        If content is large enough, write to disk and return a stub.
        Otherwise return content unchanged.
        """
        threshold = self.get_threshold(tool_name)
        if len(content) <= threshold:
            return content

        path = self._get_path(call_id)
        written = _write_once(path, content)   # skip re-write if already exists
        preview, has_more = _make_preview(content, PREVIEW_BYTES)

        size_kb = len(content) / 1024
        stub = (
            f"{_TAG_OPEN}\n"
            f"Output too large ({size_kb:.1f} KB). Full output saved to: {path}\n\n"
            f"Preview (first {PREVIEW_BYTES} bytes):\n"
            f"{preview}"
            + ("\n..." if has_more else "")
            + f"\n{_TAG_CLOSE}"
        )

        if written:
            log.debug("[Persist] %s → %s (%.1f KB)", tool_name, path, size_kb)
        return stub

    def clear_session(self) -> None:
        """Remove all persisted results for this session (call on session end)."""
        try:
            import shutil
            shutil.rmtree(self._dir, ignore_errors=True)
        except Exception:
            pass

    def _get_path(self, call_id: str) -> Path:
        safe = _sanitize(call_id)[:64] or hashlib.md5(call_id.encode()).hexdigest()
        return self._dir / f"{safe}.txt"


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _write_once(path: Path, content: str) -> bool:
    """Write to path only if it doesn't already exist (wx mode). Returns True if written."""
    try:
        path.write_text(content, encoding="utf-8")
        return True
    except FileExistsError:
        return False   # already persisted from a prior turn (compaction replay)
    except Exception as exc:
        log.warning("[Persist] Write failed %s: %s", path, exc)
        return False


def _make_preview(content: str, max_bytes: int) -> tuple[str, bool]:
    """Return (preview_str, has_more_flag)."""
    encoded = content.encode("utf-8")
    if len(encoded) <= max_bytes:
        return content, False
    preview = encoded[:max_bytes].decode("utf-8", errors="replace")
    return preview, True


def _sanitize(s: str) -> str:
    import re
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)
