"""
ARGOS — Diff Utilities
Adapted from Claude Code utils/diff.ts (Anthropic Inc.)

Generate unified diffs for file change auditing.
Used when Seneca edits files so the operator has a clear audit trail.

Python stdlib `difflib` replaces the `diff` npm package.
`get_patch_from_contents` returns a list of hunk dicts compatible with
the StructuredPatch format Claude Code uses, so callers have a consistent API.
"""
from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("argos.diff")

CONTEXT_LINES = 3
DIFF_TIMEOUT_MS = 5_000  # informational; Python difflib has no timeout


# ─── HUNK DATACLASS ───────────────────────────────────────────────────────────

@dataclass
class DiffHunk:
    """
    Represents one hunk of a unified diff.
    Compatible with the StructuredPatchHunk shape used in Claude Code.
    """
    old_start:  int
    old_lines:  int
    new_start:  int
    new_lines:  int
    lines:      List[str] = field(default_factory=list)


# ─── CORE DIFF FUNCTION ───────────────────────────────────────────────────────

def get_patch_from_contents(
    file_path:         str,
    old_content:       str,
    new_content:       str,
    context_lines:     int  = CONTEXT_LINES,
) -> List[DiffHunk]:
    """
    Generate structured diff hunks between `old_content` and `new_content`.
    Returns a list of DiffHunk objects; empty list if contents are identical.

    Uses Python's difflib.unified_diff under the hood, parsed into hunks
    for structured access (line counts, per-line +/- markers).
    """
    if old_content == new_content:
        return []

    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        n=context_lines,
    ))

    return _parse_unified_diff(diff)


def get_patch_as_string(
    file_path:     str,
    old_content:   str,
    new_content:   str,
    context_lines: int = CONTEXT_LINES,
) -> str:
    """
    Return a plain unified-diff string suitable for display or logging.
    """
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    return "".join(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        n=context_lines,
    ))


# ─── LINE-CHANGE COUNTER ──────────────────────────────────────────────────────

def count_lines_changed(hunks: List[DiffHunk], new_file_content: str = "") -> dict:
    """
    Count additions and removals from a hunk list.
    For new files (empty hunks), pass new_file_content to count all lines as additions.
    Returns {"added": int, "removed": int}.
    """
    if not hunks and new_file_content:
        return {"added": len(new_file_content.splitlines()), "removed": 0}

    added   = sum(1 for h in hunks for l in h.lines if l.startswith("+"))
    removed = sum(1 for h in hunks for l in h.lines if l.startswith("-"))
    return {"added": added, "removed": removed}


# ─── HUNK LINE-NUMBER ADJUSTMENT ──────────────────────────────────────────────

def adjust_hunk_line_numbers(hunks: List[DiffHunk], offset: int) -> List[DiffHunk]:
    """
    Shift hunk line numbers by `offset`.
    Use when the diff was computed on a file slice rather than the full file.
    """
    if offset == 0:
        return hunks
    return [
        DiffHunk(
            old_start = h.old_start + offset,
            old_lines = h.old_lines,
            new_start = h.new_start + offset,
            new_lines = h.new_lines,
            lines     = h.lines,
        )
        for h in hunks
    ]


# ─── UNIFIED-DIFF PARSER ──────────────────────────────────────────────────────

_HUNK_HEADER = __import__("re").compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


def _parse_unified_diff(diff_lines: List[str]) -> List[DiffHunk]:
    """Parse raw unified-diff output lines into DiffHunk objects."""
    hunks: List[DiffHunk] = []
    current: Optional[DiffHunk] = None

    for line in diff_lines:
        m = _HUNK_HEADER.match(line)
        if m:
            if current is not None:
                hunks.append(current)
            current = DiffHunk(
                old_start = int(m.group(1)),
                old_lines = int(m.group(2)) if m.group(2) is not None else 1,
                new_start = int(m.group(3)),
                new_lines = int(m.group(4)) if m.group(4) is not None else 1,
                lines     = [],
            )
        elif current is not None and (
            line.startswith("+") or line.startswith("-") or line.startswith(" ")
        ):
            # Strip trailing newline from content lines for clean storage
            current.lines.append(line.rstrip("\n"))

    if current is not None:
        hunks.append(current)

    return hunks
