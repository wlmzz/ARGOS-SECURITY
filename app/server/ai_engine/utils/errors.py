"""
ARGOS — Error Hierarchy
Adapted from Claude Code utils/errors.ts (Anthropic Inc.)

Defines ARGOS-specific exception classes and classification utilities.
Use these instead of generic exceptions to make error handling consistent
and telemetry-safe throughout the engine.

Exception hierarchy:
  ArgosError                 — base
    ArgosAbortError          — operation cancelled (asyncio.CancelledError wrapper)
    ArgosConfigError         — configuration parse/validation failure
    ArgosToolError           — tool execution failure (wraps stdout/stderr/code)
    ArgosLLMError            — LLM call failure (wraps status code)
    ArgosMemoryError         — memory read/write failure

Utilities (same as Claude Code's errors.ts helpers):
  error_message(e)           — safe string from any exception
  classify_http_error(e)     — buckets httpx errors into auth/timeout/network/http
  is_fs_inaccessible(e)      — ENOENT/EACCES/EPERM/ENOTDIR/ELOOP
  short_error_stack(e, n=5)  — first N traceback frames (saves context tokens)
"""
from __future__ import annotations

import traceback
from typing import Literal, Optional


# ─── BASE EXCEPTIONS ──────────────────────────────────────────────────────────

class ArgosError(Exception):
    """Base class for all ARGOS exceptions."""


class ArgosAbortError(ArgosError):
    """Operation was cancelled (user abort or asyncio.CancelledError)."""


class ArgosConfigError(ArgosError):
    """
    Configuration file parse or validation error.
    Includes the file path and a safe default config.
    """
    def __init__(self, message: str, file_path: str = "", default_config: object = None) -> None:
        super().__init__(message)
        self.file_path      = file_path
        self.default_config = default_config


class ArgosToolError(ArgosError):
    """
    Tool execution failure.
    Wraps stdout/stderr/exit code from bash or subprocess tools.
    """
    def __init__(
        self,
        message:     str = "Tool command failed",
        stdout:      str = "",
        stderr:      str = "",
        code:        int = 1,
        interrupted: bool = False,
    ) -> None:
        super().__init__(message)
        self.stdout      = stdout
        self.stderr      = stderr
        self.code        = code
        self.interrupted = interrupted

    def __str__(self) -> str:
        parts = [self.args[0]]
        if self.stderr:
            parts.append(f"stderr: {self.stderr[:200]}")
        if self.code:
            parts.append(f"exit: {self.code}")
        return " | ".join(parts)


class ArgosLLMError(ArgosError):
    """
    LLM / llama.cpp API call failure.
    """
    def __init__(self, message: str, status_code: int = 0, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body        = body


class ArgosMemoryError(ArgosError):
    """Memory subsystem read/write failure."""


# ─── ABORT DETECTION ──────────────────────────────────────────────────────────

def is_abort_error(e: object) -> bool:
    """
    True if the exception represents an intentional cancellation.
    Handles asyncio.CancelledError, ArgosAbortError, and KeyboardInterrupt.
    Same semantics as Claude Code's isAbortError().
    """
    import asyncio
    return isinstance(e, (ArgosAbortError, asyncio.CancelledError, KeyboardInterrupt))


# ─── ERROR UTILITIES ──────────────────────────────────────────────────────────

def error_message(e: object) -> str:
    """
    Safe string from any caught exception.
    Never raises — same as Claude Code's errorMessage().
    """
    if isinstance(e, BaseException):
        return str(e) or type(e).__name__
    return str(e)


def short_error_stack(e: object, max_frames: int = 5) -> str:
    """
    Return error message + first N traceback frames.
    Keeps tool_result content lean — full stacks waste context tokens.
    Adapted from Claude Code's shortErrorStack().
    """
    if not isinstance(e, BaseException):
        return str(e)
    tb = traceback.format_exception(type(e), e, e.__traceback__)
    if not tb:
        return str(e)
    lines = "".join(tb).splitlines()
    # First line is "Traceback (most recent call last):" — keep it
    # Then frame lines: "  File ...", "    code line"
    # Last line: "ExceptionType: message"
    header    = [lines[0]] if lines else []
    frames    = [l for l in lines[1:-1] if l.strip()][:max_frames * 2]
    footer    = [lines[-1]] if len(lines) > 1 else []
    return "\n".join(header + frames + footer)


# ─── FILESYSTEM ERRORS ────────────────────────────────────────────────────────

_FS_INACCESSIBLE_ERRNOS = frozenset({"ENOENT", "EACCES", "EPERM", "ENOTDIR", "ELOOP"})


def is_fs_inaccessible(e: object) -> bool:
    """
    True if the error means the path is missing or inaccessible.
    Covers ENOENT, EACCES, EPERM, ENOTDIR, ELOOP.
    Use in catch blocks after file operations to distinguish
    expected "nothing there" from unexpected errors.
    """
    if isinstance(e, OSError):
        import errno as _errno
        code = e.errno
        # Python OSError stores integer errno; map to name
        try:
            name = _errno.errorcode.get(code, "")
        except Exception:
            name = ""
        return name in _FS_INACCESSIBLE_ERRNOS
    return False


# ─── HTTP ERROR CLASSIFICATION ────────────────────────────────────────────────

HttpErrorKind = Literal["auth", "timeout", "network", "http", "other"]


def classify_http_error(e: object) -> dict:
    """
    Classify a caught httpx/requests error into one of these buckets:
      auth     — 401 / 403
      timeout  — ReadTimeout, ConnectTimeout
      network  — ConnectError, network unreachable
      http     — other HTTP error (has status code)
      other    — not an HTTP error

    Returns {"kind": str, "status": int|None, "message": str}.
    Adapted from Claude Code's classifyAxiosError().
    """
    msg    = error_message(e)
    status: Optional[int] = None

    try:
        import httpx
        if isinstance(e, httpx.HTTPStatusError):
            status = e.response.status_code
            if status in (401, 403):
                return {"kind": "auth",    "status": status, "message": msg}
            return     {"kind": "http",    "status": status, "message": msg}
        if isinstance(e, (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout)):
            return     {"kind": "timeout", "status": None,   "message": msg}
        if isinstance(e, (httpx.ConnectError, httpx.NetworkError)):
            return     {"kind": "network", "status": None,   "message": msg}
        if isinstance(e, httpx.HTTPError):
            return     {"kind": "http",    "status": None,   "message": msg}
    except ImportError:
        pass

    return {"kind": "other", "status": None, "message": msg}
