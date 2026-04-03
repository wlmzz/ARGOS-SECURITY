"""
ARGOS — Agentic Tool System
Ported from Claude Code (Anthropic) — adapted for Python + llama.cpp/OpenAI API

Tools:
  bash                    — Execute shell commands (BashTool)
  read_file               — Read files with line numbers (FileReadTool)
  write_file              — Write/create files (FileWriteTool)
  edit_file               — String replacement in files (FileEditTool)
  grep                    — Regex search via ripgrep (GrepTool)
  glob                    — Find files by pattern (GlobTool)
  web_fetch               — Fetch URL content (WebFetchTool)
  web_search              — Search via SearXNG (WebSearchTool)
  get_network_connections — Active network connections
  get_threat_history      — ARGOS SQLite threat DB
  get_system_info         — CPU/memory/disk/processes
  query_qdrant            — RAG knowledge base

MIT License — Architecture inspired by Claude Code (Anthropic Inc.)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable, Coroutine, Optional

import httpx

from .utils.sanitization import recursively_sanitize_unicode

log = logging.getLogger("argos.tools")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

LLAMA_URL   = os.getenv("ARGOS_LLAMA_URL", "http://localhost:8080")
SEARXNG_URL = os.getenv("SEARXNG_URL",     "http://localhost:8888")
QDRANT_URL  = os.getenv("QDRANT_URL",      "http://localhost:6333")
ARGOS_DB    = os.getenv("ARGOS_DB_PATH",   str(Path.home() / ".argos" / "threats.db"))

MAX_BASH_TIMEOUT   = 120
MAX_FILE_LINES     = 2000
MAX_OUTPUT_CHARS   = 100_000
MAX_GREP_RESULTS   = 250
MAX_READ_CHARS     = 40_000   # per read_file call — prevents log floods filling 32K ctx

# ─── TRUNCATION (adapted from Claude Code utils/truncate.ts) ──────────────────

def _truncate_middle(text: str, max_chars: int, label: str = "") -> str:
    """
    Keep the head and tail of a long output, cut the middle.
    Better than tail-only for log files: preserves both context header + recent events.
    e.g.: first 60% of budget → "..." → last 40% of budget
    """
    if len(text) <= max_chars:
        return text
    head_chars = int(max_chars * 0.60)
    tail_chars = max_chars - head_chars - 40   # 40 for the banner
    head = text[:head_chars]
    tail = text[-tail_chars:] if tail_chars > 0 else ""
    cut  = len(text) - head_chars - (len(tail) if tail else 0)
    banner = f"\n\n[...{label}{cut:,} chars truncated...]\n\n"
    return head + banner + tail


def _truncate_tail(text: str, max_chars: int) -> str:
    """Simple tail truncation for outputs where only recency matters."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[...truncated...]"


# ─── SECURITY: blocked command patterns (from Claude Code BashTool) ──────────

_BLOCKED = [
    r"\brm\s+-rf\s*/\b",
    r"\bdd\s+if=",
    r"\bmkfs\.",
    r":\(\)\s*\{",           # fork bomb
    r">\s*/dev/sd[a-z]",
    r"\bshred\s+/dev/",
]
_BLOCKED_RE = [re.compile(p) for p in _BLOCKED]


def _check_command(cmd: str) -> tuple[bool, str]:
    for rx in _BLOCKED_RE:
        if rx.search(cmd):
            return False, f"Blocked by security rule: {rx.pattern}"
    return True, ""


# ─── TOOL DEFINITIONS (OpenAI function-calling format) ────────────────────────

BASH_DEF = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Execute a shell command on the ARGOS server. Use for system investigation, "
            "log analysis, network checks, process inspection. Do NOT use for destructive ops."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command":     {"type": "string",  "description": "Shell command to run"},
                "timeout":     {"type": "integer", "description": f"Timeout seconds (max {MAX_BASH_TIMEOUT}, default 30)"},
                "description": {"type": "string",  "description": "Brief description of what the command does"},
            },
            "required": ["command"],
        },
    },
}

FILE_READ_DEF = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read a file with line numbers. Use offset/limit for large files.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string",  "description": "Absolute path"},
                "offset":    {"type": "integer", "description": "Start line (1-indexed)"},
                "limit":     {"type": "integer", "description": f"Lines to read (default {MAX_FILE_LINES})"},
            },
            "required": ["file_path"],
        },
    },
}

FILE_WRITE_DEF = {
    "type": "function",
    "function": {
        "name": "write_file",
        "description": "Write content to a file. Creates parent dirs automatically.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path"},
                "content":   {"type": "string", "description": "Content to write"},
            },
            "required": ["file_path", "content"],
        },
    },
}

FILE_EDIT_DEF = {
    "type": "function",
    "function": {
        "name": "edit_file",
        "description": "Replace an exact string in a file. Use read_file first to verify content.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":   {"type": "string",  "description": "Absolute path"},
                "old_string":  {"type": "string",  "description": "Exact text to replace"},
                "new_string":  {"type": "string",  "description": "Replacement text"},
                "replace_all": {"type": "boolean", "description": "Replace all occurrences (default false)"},
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    },
}

GREP_DEF = {
    "type": "function",
    "function": {
        "name": "grep",
        "description": (
            "Search file contents with regex (ripgrep). "
            "output_mode: 'content' shows lines, 'files_with_matches' shows paths, 'count' shows stats."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern":          {"type": "string",  "description": "Regex pattern"},
                "path":             {"type": "string",  "description": "File or directory"},
                "glob":             {"type": "string",  "description": "File filter e.g. '*.log'"},
                "output_mode":      {"type": "string",  "enum": ["content", "files_with_matches", "count"], "description": "Output format"},
                "case_insensitive": {"type": "boolean", "description": "Case insensitive"},
                "context":          {"type": "integer", "description": "Context lines around match"},
                "head_limit":       {"type": "integer", "description": "Max results"},
            },
            "required": ["pattern"],
        },
    },
}

GLOB_DEF = {
    "type": "function",
    "function": {
        "name": "glob",
        "description": "Find files by glob pattern, sorted by modification time.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern e.g. '**/*.log'"},
                "path":    {"type": "string", "description": "Base directory (default: /opt/argos)"},
            },
            "required": ["pattern"],
        },
    },
}

WEB_FETCH_DEF = {
    "type": "function",
    "function": {
        "name": "web_fetch",
        "description": "Fetch content from a URL. Use for CVE details, threat intel, documentation.",
        "parameters": {
            "type": "object",
            "properties": {
                "url":     {"type": "string",  "description": "URL to fetch"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 15)"},
            },
            "required": ["url"],
        },
    },
}

WEB_SEARCH_DEF = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web via SearXNG. Use for CVE lookups, IP reputation, attack patterns.",
        "parameters": {
            "type": "object",
            "properties": {
                "query":       {"type": "string",  "description": "Search query"},
                "num_results": {"type": "integer", "description": "Results (default 5, max 10)"},
            },
            "required": ["query"],
        },
    },
}

NETWORK_CONNS_DEF = {
    "type": "function",
    "function": {
        "name": "get_network_connections",
        "description": "Get active network connections on the ARGOS server. Filter by IP or status.",
        "parameters": {
            "type": "object",
            "properties": {
                "filter_ip": {"type": "string", "description": "Filter for specific IP"},
                "status":    {"type": "string", "description": "Connection status (ESTABLISHED, LISTEN, ...)"},
            },
            "required": [],
        },
    },
}

THREAT_HISTORY_DEF = {
    "type": "function",
    "function": {
        "name": "get_threat_history",
        "description": "Query the ARGOS SQLite threat database for past incidents and blocked IPs.",
        "parameters": {
            "type": "object",
            "properties": {
                "source_ip":   {"type": "string",  "description": "Filter by IP"},
                "threat_type": {"type": "string",  "description": "Filter by type (port_scan, brute_force, ...)"},
                "limit":       {"type": "integer", "description": "Records to return (default 20)"},
            },
            "required": [],
        },
    },
}

SYSTEM_INFO_DEF = {
    "type": "function",
    "function": {
        "name": "get_system_info",
        "description": "Get server status: CPU, memory, disk, top processes, open ports.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}

QDRANT_QUERY_DEF = {
    "type": "function",
    "function": {
        "name": "query_qdrant",
        "description": "Query the ARGOS RAG knowledge base (Qdrant) for threat intel and CVE data.",
        "parameters": {
            "type": "object",
            "properties": {
                "query":      {"type": "string", "description": "Natural language query"},
                "collection": {
                    "type": "string",
                    "enum": ["argos_attacks", "cve_database", "threat_intel"],
                    "description": "Collection to search (default: argos_attacks)",
                },
                "limit": {"type": "integer", "description": "Results (default 5)"},
            },
            "required": ["query"],
        },
    },
}

# ─── TOOL SETS ────────────────────────────────────────────────────────────────

ALL_TOOLS: list[dict] = [
    BASH_DEF, FILE_READ_DEF, FILE_WRITE_DEF, FILE_EDIT_DEF,
    GREP_DEF, GLOB_DEF, WEB_FETCH_DEF, WEB_SEARCH_DEF,
    NETWORK_CONNS_DEF, THREAT_HISTORY_DEF, SYSTEM_INFO_DEF, QDRANT_QUERY_DEF,
]

# Read-only investigation tools for threat analysis
ANALYSIS_TOOLS: list[dict] = [
    BASH_DEF, FILE_READ_DEF, GREP_DEF, GLOB_DEF,
    WEB_SEARCH_DEF, WEB_FETCH_DEF,
    NETWORK_CONNS_DEF, THREAT_HISTORY_DEF, SYSTEM_INFO_DEF, QDRANT_QUERY_DEF,
]


# ─── TOOL EXECUTOR ────────────────────────────────────────────────────────────

class ToolExecutor:
    """Executes tool calls. Instantiate once and reuse. All methods are async."""

    def __init__(
        self,
        db_path:     Optional[str]    = None,
        searxng_url: Optional[str]    = None,
        qdrant_url:  Optional[str]    = None,
        llama_url:   Optional[str]    = None,
        magic_docs:  Optional[object] = None,   # MagicDocsService instance
        persistence: Optional[object] = None,   # ToolPersistence instance
    ) -> None:
        self.db_path     = db_path     or ARGOS_DB
        self.searxng_url = searxng_url or SEARXNG_URL
        self.qdrant_url  = qdrant_url  or QDRANT_URL
        self.llama_url   = llama_url   or LLAMA_URL
        self._magic_docs  = magic_docs   # notified on every read_file call
        self._persistence = persistence  # persists large tool outputs to disk

        self._dispatch: dict[str, Callable[..., Coroutine[Any, Any, str]]] = {
            "bash":                    self.bash,
            "read_file":               self.read_file,
            "write_file":              self.write_file,
            "edit_file":               self.edit_file,
            "grep":                    self.grep,
            "glob":                    self.glob,
            "web_fetch":               self.web_fetch,
            "web_search":              self.web_search,
            "get_network_connections": self.get_network_connections,
            "get_threat_history":      self.get_threat_history,
            "get_system_info":         self.get_system_info,
            "query_qdrant":            self.query_qdrant,
        }

    async def execute(self, name: str, args: dict, call_id: str = "") -> str:
        handler = self._dispatch.get(name)
        if handler is None:
            return f"[ERROR] Unknown tool: {name}"
        try:
            # Sanitize input args — remove Unicode hidden chars that could be
            # injected via threat samples or external data sources (HackerOne #3086545)
            args = recursively_sanitize_unicode(args)

            result = await handler(args)

            # Sanitize tool output before it enters the conversation context —
            # prevents prompt injection via crafted file contents or network data
            result = recursively_sanitize_unicode(result)

            # Persist large outputs to disk and replace with <persisted-output> stub.
            # Prevents context overflow for nmap scans, large log reads, etc.
            # (Claude Code toolResultStorage.ts pattern)
            if self._persistence and hasattr(self._persistence, "maybe_persist"):
                result = await self._persistence.maybe_persist(name, call_id or name, result)

            return result
        except Exception as exc:
            log.exception("[ToolExecutor] Error in '%s'", name)
            return f"[ERROR] Tool '{name}' failed: {exc}"

    # ── bash ──────────────────────────────────────────────────────────────────

    async def bash(self, args: dict) -> str:
        command = args.get("command", "").strip()
        if not command:
            return "[ERROR] Empty command"
        timeout = min(int(args.get("timeout", 30)), MAX_BASH_TIMEOUT)

        ok, reason = _check_command(command)
        if not ok:
            return f"[BLOCKED] {reason}"

        log.debug("[bash] %s", command[:120])
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return f"[TIMEOUT] Exceeded {timeout}s"

            parts: list[str] = []
            if stdout:
                parts.append(stdout.decode("utf-8", errors="replace"))
            if stderr:
                parts.append(f"[stderr]\n{stderr.decode('utf-8', errors='replace')}")

            result = "\n".join(parts).strip()
            if len(result) > MAX_OUTPUT_CHARS:
                result = result[:MAX_OUTPUT_CHARS] + "\n[...truncated...]"
            return result or "(no output)"
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── read_file ─────────────────────────────────────────────────────────────

    async def read_file(self, args: dict) -> str:
        file_path = args.get("file_path", "")
        offset    = max(1, int(args.get("offset", 1)))
        limit     = min(int(args.get("limit", MAX_FILE_LINES)), MAX_FILE_LINES * 2)

        try:
            path = Path(file_path)
            if str(path).startswith("/dev/"):
                return "[ERROR] Device files cannot be read"
            if not path.exists():
                return f"[ERROR] File not found: {file_path}"
            if not path.is_file():
                return f"[ERROR] Not a regular file: {file_path}"

            lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            total  = len(lines)
            start  = offset - 1
            end    = min(start + limit, total)

            numbered = "".join(
                f"{i + start + 1:6}\t{line}"
                for i, line in enumerate(lines[start:end])
            )
            if end < total:
                numbered += f"\n[...lines {offset}-{end} of {total}. Use offset/limit to read more...]"

            # Middle-truncate if the result is very large (protects 32K context window)
            numbered = _truncate_middle(numbered, MAX_READ_CHARS, label="file content — ")

            # Notify MagicDocsService if attached (same as Claude Code's registerFileReadListener)
            if self._magic_docs and hasattr(self._magic_docs, "on_file_read"):
                raw_content = path.read_text(encoding="utf-8", errors="replace")
                self._magic_docs.on_file_read(str(path.resolve()), raw_content)

            return numbered or "(empty file)"
        except PermissionError:
            return f"[ERROR] Permission denied: {file_path}"
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── write_file ────────────────────────────────────────────────────────────

    async def write_file(self, args: dict) -> str:
        file_path = args.get("file_path", "")
        content   = args.get("content", "")
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            existed = path.exists()
            path.write_text(content, encoding="utf-8")
            verb  = "Updated" if existed else "Created"
            return f"{verb}: {file_path} ({content.count(chr(10)) + 1} lines, {len(content)} bytes)"
        except PermissionError:
            return f"[ERROR] Permission denied: {file_path}"
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── edit_file ─────────────────────────────────────────────────────────────

    async def edit_file(self, args: dict) -> str:
        file_path   = args.get("file_path", "")
        old_string  = args.get("old_string", "")
        new_string  = args.get("new_string", "")
        replace_all = bool(args.get("replace_all", False))

        if not old_string:
            return "[ERROR] old_string cannot be empty"
        try:
            path = Path(file_path)
            if not path.exists():
                return f"[ERROR] File not found: {file_path}"

            content = path.read_text(encoding="utf-8", errors="replace")
            count   = content.count(old_string)

            if count == 0:
                return f"[ERROR] old_string not found in {file_path}"
            if count > 1 and not replace_all:
                return (
                    f"[ERROR] old_string found {count} times — "
                    "use replace_all=true or add more context to make it unique"
                )

            new_content = (
                content.replace(old_string, new_string)
                if replace_all
                else content.replace(old_string, new_string, 1)
            )
            path.write_text(new_content, encoding="utf-8")
            return f"Replaced {count if replace_all else 1} occurrence(s) in {file_path}"
        except PermissionError:
            return f"[ERROR] Permission denied: {file_path}"
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── grep ──────────────────────────────────────────────────────────────────

    async def grep(self, args: dict) -> str:
        pattern          = args.get("pattern", "")
        path             = args.get("path", ".")
        glob_filter      = args.get("glob", "")
        output_mode      = args.get("output_mode", "files_with_matches")
        case_insensitive = bool(args.get("case_insensitive", False))
        context          = int(args.get("context", 0))
        head_limit       = min(int(args.get("head_limit", MAX_GREP_RESULTS)), MAX_GREP_RESULTS)

        if not pattern:
            return "[ERROR] Pattern cannot be empty"

        cmd = ["rg", "--no-heading", "--color=never"]
        if output_mode == "files_with_matches":
            cmd.append("-l")
        elif output_mode == "count":
            cmd.append("-c")
        else:
            cmd.append("-n")
        if case_insensitive:
            cmd.append("-i")
        if context:
            cmd += ["-C", str(context)]
        if glob_filter:
            cmd += ["--glob", glob_filter]
        cmd += ["--glob", "!.git", "--glob", "!__pycache__"]
        cmd.append(pattern)
        if path:
            cmd.append(path)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
            if len(lines) > head_limit:
                lines = lines[:head_limit]
                lines.append(f"[...limited to {head_limit} results...]")
            return "\n".join(lines) or "No matches found"
        except FileNotFoundError:
            return await self._grep_fallback(pattern, path, case_insensitive, head_limit)
        except asyncio.TimeoutError:
            return "[TIMEOUT] grep exceeded 30s"
        except Exception as exc:
            return f"[ERROR] {exc}"

    async def _grep_fallback(self, pattern: str, path: str, ci: bool, limit: int) -> str:
        cmd = ["grep", "-r", "-l"]
        if ci:
            cmd.append("-i")
        cmd += [pattern, path]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            lines = stdout.decode("utf-8", errors="replace").strip().splitlines()[:limit]
            return "\n".join(lines) or "No matches found"
        except Exception as exc:
            return f"[ERROR] grep fallback: {exc}"

    # ── glob ──────────────────────────────────────────────────────────────────

    async def glob(self, args: dict) -> str:
        pattern   = args.get("pattern", "")
        base_path = args.get("path", "/opt/argos")
        if not pattern:
            return "[ERROR] Pattern cannot be empty"
        try:
            base = Path(base_path)
            if not base.exists():
                return f"[ERROR] Directory not found: {base_path}"
            matches = sorted(
                base.glob(pattern),
                key=lambda p: p.stat().st_mtime if p.exists() else 0,
                reverse=True,
            )
            if not matches:
                return f"No files matching '{pattern}' in {base_path}"
            truncated = len(matches) > 100
            output = "\n".join(str(m) for m in matches[:100])
            if truncated:
                output += "\n[...truncated to 100 results...]"
            return output
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── web_fetch ─────────────────────────────────────────────────────────────

    async def web_fetch(self, args: dict) -> str:
        url     = args.get("url", "")
        timeout = min(int(args.get("timeout", 15)), 60)
        if not url.startswith(("http://", "https://")):
            return "[ERROR] URL must start with http:// or https://"
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "ARGOS-SecurityBot/1.0"},
            ) as client:
                r = await client.get(url)
                ct = r.headers.get("content-type", "")
                if "text/html" in ct:
                    text = re.sub(r"<[^>]+>", " ", r.text)
                    text = re.sub(r"\s{2,}", " ", text).strip()
                elif "application/json" in ct:
                    try:
                        text = json.dumps(r.json(), indent=2)
                    except Exception:
                        text = r.text
                else:
                    text = r.text
                if len(text) > 50_000:
                    text = text[:50_000] + "\n[...truncated at 50k chars...]"
                return f"[HTTP {r.status_code}] {url}\n\n{text}"
        except httpx.TimeoutException:
            return f"[TIMEOUT] {url} exceeded {timeout}s"
        except Exception as exc:
            return f"[ERROR] Fetch failed: {exc}"

    # ── web_search ────────────────────────────────────────────────────────────

    async def web_search(self, args: dict) -> str:
        query       = args.get("query", "")
        num_results = min(int(args.get("num_results", 5)), 10)
        if not query:
            return "[ERROR] Query cannot be empty"
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"{self.searxng_url}/search",
                    params={"q": query, "format": "json"},
                    headers={"User-Agent": "ARGOS-SecurityBot/1.0"},
                )
                if r.status_code != 200:
                    return f"[ERROR] SearXNG returned {r.status_code}"
                results = r.json().get("results", [])[:num_results]
                if not results:
                    return f"No results for: {query}"
                lines = [f"Web search: {query}\n"]
                for i, res in enumerate(results, 1):
                    lines.append(f"{i}. {res.get('title', 'No title')}")
                    lines.append(f"   {res.get('url', '')}")
                    snippet = res.get("content", "")[:300]
                    if snippet:
                        lines.append(f"   {snippet}")
                    lines.append("")
                return "\n".join(lines)
        except httpx.ConnectError:
            return f"[ERROR] Cannot reach SearXNG at {self.searxng_url}"
        except Exception as exc:
            return f"[ERROR] Search failed: {exc}"

    # ── get_network_connections ───────────────────────────────────────────────

    async def get_network_connections(self, args: dict) -> str:
        filter_ip     = args.get("filter_ip", "")
        status_filter = args.get("status", "").upper()
        try:
            import psutil
            lines: list[str] = []
            for c in psutil.net_connections(kind="inet"):
                if not (c.laddr and c.raddr):
                    if status_filter in ("LISTEN", "") and c.laddr and c.status == "LISTEN":
                        if not filter_ip:
                            lines.append(f"LISTEN :{c.laddr.port} pid={c.pid or '?'}")
                    continue
                if filter_ip and filter_ip not in (c.raddr.ip, c.laddr.ip):
                    continue
                if status_filter and c.status != status_filter:
                    continue
                t = "TCP" if c.type.value == 1 else "UDP"
                lines.append(
                    f"{t} {c.laddr.ip}:{c.laddr.port} → {c.raddr.ip}:{c.raddr.port} "
                    f"[{c.status}] pid={c.pid or '?'}"
                )
            if not lines:
                return "No matching connections found"
            return f"Network connections ({len(lines)}):\n" + "\n".join(lines[:200])
        except ImportError:
            return await self.bash({"command": "ss -tnp", "timeout": 10})
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── get_threat_history ────────────────────────────────────────────────────

    async def get_threat_history(self, args: dict) -> str:
        source_ip   = args.get("source_ip", "")
        threat_type = args.get("threat_type", "")
        limit       = min(int(args.get("limit", 20)), 100)

        if not Path(self.db_path).exists():
            return "[INFO] ARGOS threat database not yet initialized"
        try:
            import aiosqlite
            parts  = ["SELECT * FROM threats WHERE 1=1"]
            params: list = []
            if source_ip:
                parts.append("AND source_ip = ?")
                params.append(source_ip)
            if threat_type:
                parts.append("AND threat_type = ?")
                params.append(threat_type)
            parts.append("ORDER BY timestamp DESC LIMIT ?")
            params.append(limit)

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(" ".join(parts), params) as cur:
                    rows = await cur.fetchall()

            if not rows:
                return "No threats found"
            lines = [f"Threat history ({len(rows)} records):\n"]
            for row in rows:
                lines.append(f"[{row['timestamp']}] {row['severity'].upper()} {row['threat_type']}")
                lines.append(f"  {row['source_ip']}:{row['source_port']} → port {row['target_port']}")
                lines.append(f"  {row['description']}")
                if row["ai_analysis"]:
                    lines.append(f"  AI: {row['ai_analysis']}")
                lines.append(f"  Action: {row['action_taken']}\n")
            return "\n".join(lines)
        except ImportError:
            return "[ERROR] aiosqlite not installed"
        except Exception as exc:
            return f"[ERROR] DB error: {exc}"

    # ── get_system_info ───────────────────────────────────────────────────────

    async def get_system_info(self, args: dict) -> str:
        try:
            import psutil
            cpu  = psutil.cpu_percent(interval=0.5)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    procs.append(p.info)
                except psutil.NoSuchProcess:
                    pass
            procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)

            listen_ports = sorted({
                c.laddr.port for c in psutil.net_connections("inet")
                if c.status == "LISTEN" and c.laddr
            })

            lines = [
                f"CPU:    {cpu:.1f}%",
                f"Memory: {mem.percent:.1f}%  ({mem.used // 2**30:.1f} / {mem.total // 2**30:.1f} GB)",
                f"Disk /:  {disk.percent:.1f}% ({disk.used // 2**30:.1f} / {disk.total // 2**30:.1f} GB)",
                f"Ports:  {', '.join(map(str, listen_ports[:30]))}",
                "\nTop CPU processes:",
            ]
            for p in procs[:8]:
                if (p.get("cpu_percent") or 0) > 0.1:
                    lines.append(f"  PID {p['pid']:6}: {(p['name'] or '')[:30]:30} {p['cpu_percent']:.1f}%")
            return "\n".join(lines)
        except ImportError:
            return await self.bash({"command": "top -bn1 | head -25 && df -h /", "timeout": 15})
        except Exception as exc:
            return f"[ERROR] {exc}"

    # ── query_qdrant ──────────────────────────────────────────────────────────

    async def query_qdrant(self, args: dict) -> str:
        query      = args.get("query", "")
        collection = args.get("collection", "argos_attacks")
        limit      = min(int(args.get("limit", 5)), 20)
        if not query:
            return "[ERROR] Query cannot be empty"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{self.qdrant_url}/collections/{collection}")
                if r.status_code == 404:
                    return f"[INFO] Qdrant collection '{collection}' not yet set up."

                # Try vector search via llama.cpp embeddings endpoint
                try:
                    emb = await client.post(
                        f"{self.llama_url}/v1/embeddings",
                        json={"input": query, "model": "argos-current"},
                        timeout=10,
                    )
                    if emb.status_code == 200:
                        vec = emb.json()["data"][0]["embedding"]
                        sr = await client.post(
                            f"{self.qdrant_url}/collections/{collection}/points/search",
                            json={"vector": vec, "limit": limit, "with_payload": True},
                        )
                        if sr.status_code == 200:
                            return self._fmt_qdrant(sr.json().get("result", []), query, collection)
                except Exception:
                    pass

                # Fallback: scroll (no embedding required)
                scr = await client.post(
                    f"{self.qdrant_url}/collections/{collection}/points/scroll",
                    json={"limit": limit, "with_payload": True},
                )
                if scr.status_code == 200:
                    pts = scr.json().get("result", {}).get("points", [])
                    return self._fmt_qdrant(pts, query, collection)
                return f"[ERROR] Qdrant scroll failed: {scr.status_code}"

        except httpx.ConnectError:
            return "[INFO] Qdrant not reachable. Knowledge base offline."
        except Exception as exc:
            return f"[ERROR] Qdrant: {exc}"

    @staticmethod
    def _fmt_qdrant(results: list, query: str, collection: str) -> str:
        if not results:
            return f"No results in '{collection}' for: {query}"
        lines = [f"Qdrant '{collection}' — {query}\n"]
        for r in results:
            score = r.get("score", "")
            if score != "":
                lines.append(f"Score: {score:.3f}")
            for k, v in r.get("payload", {}).items():
                lines.append(f"  {k}: {str(v)[:300]}")
            lines.append("")
        return "\n".join(lines)
