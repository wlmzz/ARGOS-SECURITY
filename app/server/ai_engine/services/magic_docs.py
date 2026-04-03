"""
ARGOS — Magic Docs
Adapted from Claude Code services/MagicDocs/magicDocs.ts (Anthropic Inc.)

Automatically maintains markdown threat intelligence files marked with:
  # MAGIC DOC: [title]

When Seneca reads a file with this header, it is registered as a Magic Doc.
After each analysis turn (when the AI is idle), Seneca re-reads the file and
updates it with new threat intelligence from the session.

Relevant files for ARGOS:
  THREATS.md              → # MAGIC DOC: Active Threat Dashboard
  ioc/ioc_list.md         → # MAGIC DOC: IOC Master List
  Any custom runbook      → # MAGIC DOC: SSH Brute Force Runbook

Usage:
    from .magic_docs import MagicDocsService
    magic = MagicDocsService(llama_url, model)
    magic.on_file_read("/opt/argos/memory/THREATS.md", content)
    ...
    # After each analysis turn:
    await magic.maybe_update(last_assistant_text, messages)
"""
from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional

import httpx

from ..memory.paths import safe_write, validate_path

log = logging.getLogger("argos.magic_docs")

# ─── MAGIC DOC DETECTION ──────────────────────────────────────────────────────

# Matches: # MAGIC DOC: Active Threat Dashboard
_HEADER_RE  = re.compile(r"^#\s*MAGIC\s+DOC:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
# Optional italic instructions on the line after the header
_ITALICS_RE = re.compile(r"^[_*](.+?)[_*]\s*$", re.MULTILINE)


def detect_magic_doc(content: str) -> Optional[dict]:
    """
    Check if file content has a Magic Doc header.
    Returns {"title": str, "instructions": str|None} or None.
    """
    m = _HEADER_RE.search(content)
    if not m:
        return None
    title    = m.group(1).strip()
    after    = content[m.end():]
    # Look for italics on the next non-blank line
    nl_match = re.match(r"\s*\n(?:\s*\n)?(.+?)(?:\n|$)", after)
    instructions: Optional[str] = None
    if nl_match:
        next_line = nl_match.group(1)
        it = _ITALICS_RE.match(next_line)
        if it:
            instructions = it.group(1).strip()
    return {"title": title, "instructions": instructions}


# ─── MAGIC DOCS SERVICE ───────────────────────────────────────────────────────

_UPDATE_PROMPT_TEMPLATE = """\
You are maintaining the following Magic Doc: **{title}**
{instructions_block}
Current document content:
---
{current_doc}
---

Conversation context (most recent turns summarized):
{context_summary}

Update the document to incorporate new threat intelligence from this session.
- Keep the `# MAGIC DOC: {title}` header on the first line
- Keep the document focused, concise, and well-structured
- Add new relevant information; remove or condense stale entries
- Use markdown formatting

Return ONLY the complete updated document content, no preamble.\
"""


class MagicDocsService:
    """
    Tracks markdown files with `# MAGIC DOC:` headers and updates them
    in the background after each idle analysis turn.
    """

    def __init__(
        self,
        llama_url: str = "http://localhost:8080",
        model:     str = "argos-current",
    ) -> None:
        self.llama_url = llama_url
        self.model     = model
        # path → {"title": str, "instructions": str|None}
        self._tracked: dict[str, dict] = {}
        self._last_update: dict[str, float] = {}
        # Minimum seconds between updates for the same file
        self._min_interval = 120.0

    # ── Public API ─────────────────────────────────────────────────────────────

    def on_file_read(self, path: str, content: str) -> None:
        """
        Call this whenever a file is read by any tool.
        Registers it as a Magic Doc if the header is detected.
        Same as Claude Code's registerFileReadListener().
        """
        info = detect_magic_doc(content)
        if info and path not in self._tracked:
            self._tracked[path] = info
            log.debug("[MagicDocs] Registered: %s (%s)", path, info["title"])

    async def maybe_update(
        self,
        last_response_text: str,
        messages:           list[dict],
    ) -> None:
        """
        Trigger Magic Doc updates if the AI turn ended without tool calls
        (i.e., conversation is idle — same check as Claude Code).
        """
        if not self._tracked:
            return

        # Only update when idle (no tool_calls in the last assistant message)
        has_tool_calls = any(
            m.get("role") == "assistant" and m.get("tool_calls")
            for m in messages[-3:]
        )
        if has_tool_calls:
            return

        now = time.monotonic()
        context = _summarize_messages(messages)

        for path, info in list(self._tracked.items()):
            # Rate-limit per file
            since = now - self._last_update.get(path, 0)
            if since < self._min_interval:
                log.debug("[MagicDocs] Skipping %s (%.0fs since last update)", path, since)
                continue

            await self._update_file(path, info, context)
            self._last_update[path] = now

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _update_file(self, path: str, info: dict, context: str) -> None:
        ok, reason = validate_path(path)
        if not ok:
            log.warning("[MagicDocs] Skipping %s: %s", path, reason)
            return

        file_path = Path(path)
        if not file_path.exists():
            self._tracked.pop(path, None)
            return

        current_doc = file_path.read_text(encoding="utf-8")

        # Re-verify header still present
        if not detect_magic_doc(current_doc):
            self._tracked.pop(path, None)
            return

        instructions = info.get("instructions") or ""
        instructions_block = (
            f"*Instructions: {instructions}*\n\n" if instructions else ""
        )
        prompt = _UPDATE_PROMPT_TEMPLATE.format(
            title              = info["title"],
            instructions_block = instructions_block,
            current_doc        = current_doc[:3000],   # cap to avoid context overflow
            context_summary    = context,
        )

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":       self.model,
                        "messages":    [{"role": "user", "content": prompt}],
                        "temperature": 0.2,
                        "max_tokens":  1500,
                        "stream":      False,
                    },
                )
            if r.status_code != 200:
                log.warning("[MagicDocs] Seneca returned %d for %s", r.status_code, path)
                return

            updated = r.json()["choices"][0]["message"]["content"].strip()

            # Safety: ensure the magic doc header survived
            if not detect_magic_doc(updated):
                log.warning("[MagicDocs] Updated content lost header — aborting write for %s", path)
                return

            safe_write(file_path, updated)
            log.info("[MagicDocs] Updated: %s", path)

        except Exception as exc:
            log.warning("[MagicDocs] Update failed for %s: %s", path, exc)

    def clear(self) -> None:
        """Unregister all tracked docs (call on session reset)."""
        self._tracked.clear()
        self._last_update.clear()


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _summarize_messages(messages: list[dict], max_chars: int = 1500) -> str:
    """Build a compact context summary from the last N messages."""
    lines: list[str] = []
    total = 0
    for m in reversed(messages[-10:]):
        role    = m.get("role", "")
        content = m.get("content") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p)
                for p in content
            )
        snippet = str(content)[:200]
        line    = f"[{role.upper()}]: {snippet}"
        total  += len(line)
        lines.append(line)
        if total >= max_chars:
            break
    return "\n".join(reversed(lines))
