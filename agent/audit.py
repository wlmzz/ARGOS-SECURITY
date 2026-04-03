"""
ARGOS Audit Logger — wraps every tool execution with a tamper-evident log.
Inspired by OpenClaw's security audit framework.

Every tool call is recorded with: timestamp, session, tool, sanitized params,
result status, duration, and a SHA256 chain hash for tamper detection.
"""
from __future__ import annotations
import hashlib, json, os, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

AUDIT_LOG = Path(os.getenv("ARGOS_AUDIT_LOG", "/opt/argos/logs/audit.jsonl"))

# Secrets to scrub from params before logging
_SECRET_KEYS = {"password", "token", "key", "secret", "api_key", "auth", "credential",
                "passwd", "pass", "pwd", "authorization"}

_last_hash = ""


def _scrub(obj: Any, depth: int = 0) -> Any:
    """Recursively scrub secret values from dicts."""
    if depth > 5:
        return obj
    if isinstance(obj, dict):
        return {
            k: "***REDACTED***" if any(s in k.lower() for s in _SECRET_KEYS) else _scrub(v, depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_scrub(i, depth + 1) for i in obj]
    return obj


def _chain_hash(prev_hash: str, entry: dict) -> str:
    """SHA256 of previous hash + current entry — detects log tampering."""
    content = prev_hash + json.dumps(entry, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


def log_tool_call(session_id: str, tool_name: str, params: dict,
                  result: Any, duration_ms: float, success: bool) -> None:
    global _last_hash
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session": session_id,
        "tool": tool_name,
        "params": _scrub(params),
        "success": success,
        "duration_ms": round(duration_ms, 1),
        "result_size": len(json.dumps(result, default=str)) if result else 0,
    }
    entry["chain_hash"] = _chain_hash(_last_hash, entry)
    _last_hash = entry["chain_hash"]

    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


def wrap_tools(all_tools: dict, session_id: str = "unknown") -> dict:
    """Return a copy of all_tools where every fn is wrapped with audit logging."""
    wrapped = {}
    for name, tool_def in all_tools.items():
        original_fn: Callable = tool_def["fn"]

        def make_wrapper(fn: Callable, tool_name: str) -> Callable:
            def wrapper(*args, **kwargs):
                start = time.monotonic()
                success = True
                result = None
                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as e:
                    success = False
                    result = {"error": str(e)}
                    raise
                finally:
                    duration_ms = (time.monotonic() - start) * 1000
                    params = kwargs.copy()
                    if args:
                        params["_args"] = list(args)
                    log_tool_call(
                        session_id=session_id,
                        tool_name=tool_name,
                        params=params,
                        result=result,
                        duration_ms=duration_ms,
                        success=success,
                    )
            return wrapper

        wrapped[name] = {**tool_def, "fn": make_wrapper(original_fn, name)}
    return wrapped


def tail_audit(lines: int = 50) -> list[dict]:
    """Return the last N audit log entries."""
    if not AUDIT_LOG.exists():
        return []
    entries = []
    for line in AUDIT_LOG.read_text().splitlines()[-lines:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    return entries


def verify_audit_integrity() -> dict:
    """Verify the audit log chain hash — detects if log was tampered with."""
    if not AUDIT_LOG.exists():
        return {"status": "no_log", "entries": 0}
    entries = []
    for line in AUDIT_LOG.read_text().splitlines():
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    if not entries:
        return {"status": "empty", "entries": 0}

    prev = ""
    for i, entry in enumerate(entries):
        stored_hash = entry.get("chain_hash", "")
        entry_without_hash = {k: v for k, v in entry.items() if k != "chain_hash"}
        expected = _chain_hash(prev, entry_without_hash)
        if stored_hash != expected:
            return {
                "status": "TAMPERED",
                "tampered_at_entry": i,
                "timestamp": entry.get("ts"),
                "entries_checked": i + 1,
            }
        prev = stored_hash

    return {"status": "INTACT", "entries": len(entries), "last_hash": prev[:16] + "..."}
