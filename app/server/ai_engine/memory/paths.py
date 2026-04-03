"""
ARGOS — Threat Memory Path Management
Adapted from Claude Code memdir/paths.ts (Anthropic Inc.)

Hierarchy:
  /opt/argos/memory/
    THREATS.md              ← entrypoint index (≤200 lines, like MEMORY.md)
    logs/YYYY/MM/DD.md      ← daily append-only threat log
    detections/{id}.md      ← per-threat detail file
    incidents/{id}.md       ← post-incident review
    ioc/ioc_list.md         ← Indicators of Compromise

Security: validates all paths before writes (same rules as Claude Code paths.ts).
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─── CONFIG ───────────────────────────────────────────────────────────────────

_DEFAULT_ROOT    = Path(os.getenv("ARGOS_MEMORY_ROOT", "/opt/argos/memory"))
_FALLBACK_ROOT   = Path.home() / ".argos" / "memory"
ENTRYPOINT_NAME  = "THREATS.md"
MAX_ENTRYPOINT_LINES = 200
MAX_ENTRYPOINT_BYTES = 25_600   # 25 KB (same limit as Claude Code)

# ─── PATH HELPERS ─────────────────────────────────────────────────────────────

def get_memory_root(project_id: Optional[str] = None) -> Path:
    base = _DEFAULT_ROOT if _DEFAULT_ROOT.parent.exists() else _FALLBACK_ROOT
    if project_id:
        return base / _sanitize_id(project_id)
    return base


def get_entrypoint(project_id: Optional[str] = None) -> Path:
    return get_memory_root(project_id) / ENTRYPOINT_NAME


def get_daily_log_path(
    date: Optional[datetime] = None,
    project_id: Optional[str] = None,
) -> Path:
    d = date or datetime.now()
    return (
        get_memory_root(project_id)
        / "logs"
        / f"{d.year:04d}"
        / f"{d.month:02d}"
        / f"{d.year:04d}-{d.month:02d}-{d.day:02d}.md"
    )


def get_detection_path(threat_id: str, project_id: Optional[str] = None) -> Path:
    return get_memory_root(project_id) / "detections" / f"{_sanitize_id(threat_id)}.md"


def get_incident_path(incident_id: str, project_id: Optional[str] = None) -> Path:
    return get_memory_root(project_id) / "incidents" / f"{_sanitize_id(incident_id)}.md"


def get_ioc_path(project_id: Optional[str] = None) -> Path:
    return get_memory_root(project_id) / "ioc" / "ioc_list.md"


def get_session_memory_path(session_id: str, project_id: Optional[str] = None) -> Path:
    return get_memory_root(project_id) / "sessions" / f"{_sanitize_id(session_id)}_memory.md"


# ─── INIT ─────────────────────────────────────────────────────────────────────

def ensure_memory_root(project_id: Optional[str] = None) -> Path:
    """Create the memory directory tree if it doesn't exist."""
    root = get_memory_root(project_id)
    for subdir in ("logs", "detections", "incidents", "ioc", "sessions"):
        (root / subdir).mkdir(parents=True, exist_ok=True)

    # Bootstrap entrypoint if missing
    ep = root / ENTRYPOINT_NAME
    if not ep.exists():
        ep.write_text(
            "# ARGOS Threat Intelligence Memory\n\n"
            "*This file is an index. Max 200 lines. Content lives in topic files.*\n\n"
            "## Active Threats\n\n"
            "## Recent Incidents\n\n"
            "## IOC Index\n",
            encoding="utf-8",
        )
    return root


def is_memory_enabled() -> bool:
    """Check if the memory root is accessible."""
    try:
        root = get_memory_root()
        return root.exists() or root.parent.exists()
    except Exception:
        return False


# ─── PATH SECURITY (from Claude Code paths.ts) ────────────────────────────────

_NULL_BYTE      = re.compile(r"\x00")
_RELATIVE       = re.compile(r"(?:^|/)\.\.(?:/|$)")
_WINDOWS_DRIVE  = re.compile(r"^[A-Za-z]:\\")
_UNC_PATH       = re.compile(r"^\\\\")

def validate_path(path: str | Path) -> tuple[bool, str]:
    """
    Security-validate a filesystem path before writing.
    Returns (valid, reason). Adapted from Claude Code filesystem.ts validation.
    """
    s = str(path)
    if _NULL_BYTE.search(s):
        return False, "path contains null bytes"
    if _RELATIVE.search(s):
        return False, "path traversal (..) not allowed"
    if _WINDOWS_DRIVE.match(s):
        return False, "Windows drive roots not allowed"
    if _UNC_PATH.match(s):
        return False, "UNC paths not allowed (credential leak risk)"
    if not s.startswith("/") and not s.startswith(str(Path.home())):
        return False, "only absolute paths allowed"
    return True, ""


def safe_write(path: Path, content: str) -> bool:
    """Write with path validation. Returns True on success."""
    ok, reason = validate_path(path)
    if not ok:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def safe_append(path: Path, content: str) -> bool:
    """Append with path validation."""
    ok, reason = validate_path(path)
    if not ok:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(content)
    return True


# ─── ENTRYPOINT PRUNING (from autoDream Phase 4) ──────────────────────────────

def prune_entrypoint(project_id: Optional[str] = None) -> bool:
    """
    Keep the THREATS.md index under MAX_ENTRYPOINT_LINES and MAX_ENTRYPOINT_BYTES.
    Removes blank lines and trims oldest entries when over limit.
    Returns True if pruning was needed.
    """
    ep = get_entrypoint(project_id)
    if not ep.exists():
        return False

    content = ep.read_text(encoding="utf-8")
    if len(content.encode()) <= MAX_ENTRYPOINT_BYTES:
        lines = content.splitlines()
        if len(lines) <= MAX_ENTRYPOINT_LINES:
            return False

    lines = content.splitlines()
    # Remove consecutive blank lines
    cleaned: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        cleaned.append(line)
        prev_blank = is_blank

    # Trim to limit (keep headers, remove oldest body entries)
    while len(cleaned) > MAX_ENTRYPOINT_LINES or len("\n".join(cleaned).encode()) > MAX_ENTRYPOINT_BYTES:
        # Remove last non-header line
        for i in range(len(cleaned) - 1, -1, -1):
            if not cleaned[i].startswith("#") and cleaned[i].strip():
                cleaned.pop(i)
                break
        else:
            break

    ep.write_text("\n".join(cleaned), encoding="utf-8")
    return True


# ─── PRIVATE ──────────────────────────────────────────────────────────────────

def _sanitize_id(s: str) -> str:
    """Make a string safe for use as a filename."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)[:64]
