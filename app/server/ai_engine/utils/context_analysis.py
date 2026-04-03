"""
ARGOS — Context Analysis
Adapted from Claude Code utils/contextAnalysis.ts (Anthropic Inc.)

Analyzes the token breakdown of a conversation:
  - Tokens per tool (requests vs results separately)
  - Human vs assistant messages
  - Duplicate file reads (wasted tokens)
  - Total context usage vs 32K window

Useful for:
  - Debugging why compaction triggers early
  - Understanding which tools are most expensive
  - /context slash command output
  - Logging before each compaction

Usage:
    from .context_analysis import analyze_context, format_context_report
    stats = analyze_context(messages)
    print(format_context_report(stats))
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Seneca-32B context window
CONTEXT_WINDOW = 32_768

# 4 chars ≈ 1 token (same rough estimate as rest of ARGOS codebase)
CHARS_PER_TOKEN = 4


def _count_tokens(obj) -> int:
    """Estimate token count for any serialisable object."""
    if isinstance(obj, str):
        return len(obj) // CHARS_PER_TOKEN
    try:
        return len(json.dumps(obj, ensure_ascii=False)) // CHARS_PER_TOKEN
    except Exception:
        return len(str(obj)) // CHARS_PER_TOKEN


# ─── DATA CLASSES ─────────────────────────────────────────────────────────────

@dataclass
class DuplicateReadInfo:
    path:   str
    count:  int
    tokens: int   # wasted tokens (duplicate reads only)


@dataclass
class ContextStats:
    """Token breakdown for a conversation (mirrors Claude Code's TokenStats)."""
    tool_requests:  dict[str, int]    = field(default_factory=dict)  # tool_name → tokens
    tool_results:   dict[str, int]    = field(default_factory=dict)  # tool_name → tokens
    human_tokens:   int = 0
    assistant_tokens: int = 0
    total:          int = 0
    duplicate_reads: list[DuplicateReadInfo] = field(default_factory=list)

    @property
    def duplicate_tokens(self) -> int:
        return sum(d.tokens for d in self.duplicate_reads)

    @property
    def tool_request_total(self) -> int:
        return sum(self.tool_requests.values())

    @property
    def tool_result_total(self) -> int:
        return sum(self.tool_results.values())

    @property
    def pct_used(self) -> float:
        return self.total / CONTEXT_WINDOW * 100


# ─── ANALYSIS ─────────────────────────────────────────────────────────────────

def analyze_context(messages: list[dict]) -> ContextStats:
    """
    Walk conversation messages and count tokens per category.
    Detects duplicate read_file calls on the same path.

    Works with OpenAI message format (role/content/tool_calls).
    """
    stats = ContextStats()

    # Maps: tool_call_id → tool_name (assistant side)
    id_to_name: dict[str, str] = {}
    # Maps: tool_call_id → file_path (for read_file duplicate tracking)
    id_to_path: dict[str, str] = {}
    # Maps: file_path → {count, total_tokens}
    path_reads: dict[str, dict] = {}

    for msg in messages:
        role    = msg.get("role", "")
        content = msg.get("content") or ""

        # ── assistant message ──────────────────────────────────────────────────
        if role == "assistant":
            text = content if isinstance(content, str) else ""
            if isinstance(content, list):
                text = " ".join(
                    b.get("text", "") if isinstance(b, dict) else str(b)
                    for b in content
                )
            stats.assistant_tokens += _count_tokens(text)
            stats.total            += _count_tokens(text)

            # Track tool_calls metadata
            for tc in msg.get("tool_calls") or []:
                call_id  = tc.get("id", "")
                fn       = tc.get("function", {})
                name     = fn.get("name", "unknown")
                tc_tokens = _count_tokens(tc)

                id_to_name[call_id] = name
                stats.tool_requests[name] = stats.tool_requests.get(name, 0) + tc_tokens
                stats.total += tc_tokens

                # Track read_file file paths for duplicate detection
                if name == "read_file":
                    try:
                        args = json.loads(fn.get("arguments", "{}"))
                        path = args.get("file_path", "")
                        if path:
                            id_to_path[call_id] = path
                    except Exception:
                        pass

        # ── tool result message ────────────────────────────────────────────────
        elif role == "tool":
            call_id    = msg.get("tool_call_id", "")
            name       = id_to_name.get(call_id, "unknown")
            result_tok = _count_tokens(content)

            stats.tool_results[name] = stats.tool_results.get(name, 0) + result_tok
            stats.total += result_tok

            # Track read_file duplicate reads
            if name == "read_file":
                path = id_to_path.get(call_id, "")
                if path:
                    entry = path_reads.setdefault(path, {"count": 0, "total": 0})
                    entry["count"] += 1
                    entry["total"] += result_tok

        # ── user message ───────────────────────────────────────────────────────
        elif role == "user":
            text = content if isinstance(content, str) else json.dumps(content)
            user_tok = _count_tokens(text)
            stats.human_tokens += user_tok
            stats.total        += user_tok

    # Calculate duplicate read waste
    for path, data in path_reads.items():
        if data["count"] > 1:
            avg    = data["total"] // data["count"]
            wasted = avg * (data["count"] - 1)
            stats.duplicate_reads.append(
                DuplicateReadInfo(path=path, count=data["count"], tokens=wasted)
            )

    # Sort duplicate reads by waste descending
    stats.duplicate_reads.sort(key=lambda d: d.tokens, reverse=True)
    return stats


# ─── REPORTING ────────────────────────────────────────────────────────────────

def format_context_report(stats: ContextStats) -> str:
    """
    Human-readable context breakdown. Shown by /context command or before compaction.
    """
    lines: list[str] = [
        f"## Context Analysis ({stats.total:,} / {CONTEXT_WINDOW:,} tokens  {stats.pct_used:.0f}%)",
        "",
        f"  Human messages:    {stats.human_tokens:>8,} tokens  ({stats.human_tokens/max(stats.total,1)*100:.0f}%)",
        f"  Assistant text:    {stats.assistant_tokens:>8,} tokens  ({stats.assistant_tokens/max(stats.total,1)*100:.0f}%)",
        f"  Tool requests:     {stats.tool_request_total:>8,} tokens  ({stats.tool_request_total/max(stats.total,1)*100:.0f}%)",
        f"  Tool results:      {stats.tool_result_total:>8,} tokens  ({stats.tool_result_total/max(stats.total,1)*100:.0f}%)",
    ]

    if stats.tool_results:
        lines.append("")
        lines.append("  Top tools by result size:")
        for name, tok in sorted(stats.tool_results.items(), key=lambda x: -x[1])[:6]:
            lines.append(f"    {name:<25} {tok:>7,} tokens")

    if stats.duplicate_reads:
        lines.append("")
        lines.append(f"  ⚠ Duplicate file reads ({stats.duplicate_tokens:,} wasted tokens):")
        for d in stats.duplicate_reads[:5]:
            short = d.path if len(d.path) <= 50 else "…" + d.path[-48:]
            lines.append(f"    {short}  ×{d.count}  (~{d.tokens:,} wasted)")

    lines.append("")
    remaining = CONTEXT_WINDOW - stats.total
    lines.append(f"  Remaining: {remaining:,} tokens ({remaining/CONTEXT_WINDOW*100:.0f}%)")
    return "\n".join(lines)
