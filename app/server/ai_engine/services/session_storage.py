"""
ARGOS — Session Storage
Adapted from Claude Code utils/sessionStorage.ts (Anthropic Inc.)

JSONL transcript persistence for ARGOS sessions.
Each session is one JSONL file: {sessions_dir}/{session_id}.jsonl
Each line is a JSON-encoded message dict (user, assistant, system).

Lite log pattern:
  - On load, if the file exceeds MAX_LITE_READ_BYTES, read only head+tail
    (a lite log). Callers that need the full log call load_full_log().
  - This prevents OOM when session files grow to hundreds of MB.

Session metadata sidecar:
  - Stored in {session_id}.meta.json alongside the JSONL
  - Tracks: session title, tags, start/end time, git branch, tool call count

ARGOS adaptations:
  - No subagent/worktree/CCR complexity — single-process sessions only
  - Uses the same JSONL format as Claude Code for interoperability
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, List, Optional

log = logging.getLogger("argos.session_storage")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Default sessions directory
_DEFAULT_SESSIONS_ROOT = Path(
    os.getenv("ARGOS_SESSIONS_DIR", Path.home() / ".argos" / "sessions")
)

# Read head+tail for files larger than this (lite log pattern)
MAX_LITE_READ_BYTES = 512 * 1024     # 512 KB
MAX_FULL_READ_BYTES = 50 * 1024 * 1024  # 50 MB — OOM guard

# Bytes from head and tail to include in lite read
LITE_HEAD_BYTES = 128 * 1024
LITE_TAIL_BYTES = 128 * 1024


# ─── SESSION METADATA ─────────────────────────────────────────────────────────

@dataclass
class SessionMetadata:
    session_id:     str
    created_at:     float = field(default_factory=time.time)
    updated_at:     float = field(default_factory=time.time)
    title:          Optional[str]  = None
    tag:            Optional[str]  = None
    git_branch:     Optional[str]  = None
    git_root:       Optional[str]  = None
    tool_call_count: int           = 0
    message_count:   int           = 0
    model:          Optional[str]  = None


# ─── PATH HELPERS ─────────────────────────────────────────────────────────────

def get_sessions_dir() -> Path:
    return _DEFAULT_SESSIONS_ROOT


def get_transcript_path(session_id: str, sessions_dir: Optional[Path] = None) -> Path:
    base = sessions_dir or get_sessions_dir()
    return base / f"{session_id}.jsonl"


def get_metadata_path(session_id: str, sessions_dir: Optional[Path] = None) -> Path:
    base = sessions_dir or get_sessions_dir()
    return base / f"{session_id}.meta.json"


def new_session_id() -> str:
    return str(uuid.uuid4())


# ─── WRITE ────────────────────────────────────────────────────────────────────

async def record_transcript(
    session_id: str,
    messages:   List[dict],
    sessions_dir: Optional[Path] = None,
) -> Path:
    """
    Persist messages as JSONL to disk.
    Appends new lines; does not rewrite the full file.
    Returns the transcript path.
    """
    path = get_transcript_path(session_id, sessions_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = "\n".join(json.dumps(m, ensure_ascii=False) for m in messages) + "\n"
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(lines)
    except OSError as exc:
        log.warning("[session_storage] Write failed %s: %s", path, exc)
        raise

    return path


async def record_message(
    session_id: str,
    message:    dict,
    sessions_dir: Optional[Path] = None,
) -> Path:
    """Append a single message to the session transcript."""
    return await record_transcript(session_id, [message], sessions_dir)


# ─── READ ─────────────────────────────────────────────────────────────────────

async def load_transcript(
    session_id:  str,
    sessions_dir: Optional[Path] = None,
    full:        bool = False,
) -> List[dict]:
    """
    Load messages from a JSONL transcript file.

    If the file is larger than MAX_LITE_READ_BYTES and full=False,
    returns only the head+tail slice (lite log). Call with full=True
    when you need the complete history (away_summary, context analysis).

    Returns [] if the file doesn't exist.
    """
    path = get_transcript_path(session_id, sessions_dir)
    if not path.exists():
        return []

    file_size = path.stat().st_size

    if not full and file_size > MAX_LITE_READ_BYTES:
        raw = _read_head_and_tail(path, LITE_HEAD_BYTES, LITE_TAIL_BYTES)
    elif file_size > MAX_FULL_READ_BYTES:
        log.warning(
            "[session_storage] Session %s is %.1f MB — loading tail only",
            session_id, file_size / 1024 / 1024,
        )
        raw = _read_tail(path, MAX_FULL_READ_BYTES)
    else:
        raw = path.read_text(encoding="utf-8", errors="replace")

    messages = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            messages.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # skip corrupt lines

    return messages


async def load_full_transcript(
    session_id:   str,
    sessions_dir: Optional[Path] = None,
) -> List[dict]:
    """Always load the full transcript regardless of file size."""
    return await load_transcript(session_id, sessions_dir, full=True)


# ─── METADATA ─────────────────────────────────────────────────────────────────

async def save_metadata(
    metadata:    SessionMetadata,
    sessions_dir: Optional[Path] = None,
) -> None:
    path = get_metadata_path(metadata.session_id, sessions_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata.updated_at = time.time()
    path.write_text(json.dumps(asdict(metadata), indent=2, ensure_ascii=False), encoding="utf-8")


async def load_metadata(
    session_id:  str,
    sessions_dir: Optional[Path] = None,
) -> Optional[SessionMetadata]:
    path = get_metadata_path(session_id, sessions_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return SessionMetadata(**data)
    except Exception as exc:
        log.warning("[session_storage] Corrupt metadata %s: %s", path, exc)
        return None


# ─── LIST SESSIONS ────────────────────────────────────────────────────────────

async def list_sessions(sessions_dir: Optional[Path] = None) -> List[SessionMetadata]:
    """
    Return metadata for all saved sessions, sorted newest first.
    Sessions without a .meta.json get a stub metadata entry.
    """
    base = sessions_dir or get_sessions_dir()
    if not base.exists():
        return []

    sessions = []
    for jsonl_path in sorted(base.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
        session_id = jsonl_path.stem
        meta = await load_metadata(session_id, base)
        if meta is None:
            meta = SessionMetadata(
                session_id = session_id,
                created_at = jsonl_path.stat().st_mtime,
                updated_at = jsonl_path.stat().st_mtime,
            )
        sessions.append(meta)

    return sessions


async def delete_session(
    session_id:   str,
    sessions_dir: Optional[Path] = None,
) -> None:
    """Delete transcript and metadata files for a session."""
    for path in [
        get_transcript_path(session_id, sessions_dir),
        get_metadata_path(session_id, sessions_dir),
    ]:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("[session_storage] Delete failed %s: %s", path, exc)


# ─── FILE HELPERS ─────────────────────────────────────────────────────────────

def _read_head_and_tail(path: Path, head_bytes: int, tail_bytes: int) -> str:
    """
    Read the first `head_bytes` and last `tail_bytes` of a file.
    Joined with a marker line for transparency.
    This is the lite log pattern from Claude Code's sessionStoragePortable.ts.
    """
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(head_bytes).decode("utf-8", errors="replace")
        if size <= head_bytes + tail_bytes:
            return head
        fh.seek(-tail_bytes, 2)
        tail = fh.read().decode("utf-8", errors="replace")

    skipped = size - head_bytes - tail_bytes
    marker = f'\n{{"_note": "... {skipped:,} bytes skipped (lite log) ..."}}\n'
    return head + marker + tail


def _read_tail(path: Path, max_bytes: int) -> str:
    """Read the last `max_bytes` of a file."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(-max_bytes, 2)
        return fh.read().decode("utf-8", errors="replace")
