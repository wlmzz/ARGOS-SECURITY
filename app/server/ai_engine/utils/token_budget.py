"""
ARGOS — Token Budget Parser
Adapted from Claude Code utils/tokenBudget.ts (Anthropic Inc.)

Parses user messages for token budget directives:
  "+500k"          → 500_000 tokens
  "use 2M tokens"  → 2_000_000 tokens
  "spend 32k"      → 32_000 tokens

Used by the chat interface to allow operators to set analysis depth:
  "Investigate this threat, use 10k tokens"
  "Full deep-dive +32k"

Returns None if no directive found (use default budget).
"""
from __future__ import annotations

import re
from typing import Optional

# Shorthand at start: "+500k", "+2.5m"
_START_RE   = re.compile(r"^\s*\+(\d+(?:\.\d+)?)\s*(k|m|b)\b", re.IGNORECASE)
# Shorthand at end: "... +500k"
_END_RE     = re.compile(r"\s\+(\d+(?:\.\d+)?)\s*(k|m|b)\s*[.!?]?\s*$", re.IGNORECASE)
# Verbose anywhere: "use 2M tokens", "spend 32k tokens"
_VERBOSE_RE = re.compile(r"\b(?:use|spend)\s+(\d+(?:\.\d+)?)\s*(k|m|b)\s*tokens?\b", re.IGNORECASE)

_MULTIPLIERS = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}


def _parse_match(value: str, suffix: str) -> int:
    return int(float(value) * _MULTIPLIERS[suffix.lower()])


def parse_token_budget(text: str) -> Optional[int]:
    """
    Extract a token budget from a user message.
    Returns the integer token count, or None if not found.

    Priority: start shorthand > end shorthand > verbose.
    """
    m = _START_RE.match(text)
    if m:
        return _parse_match(m.group(1), m.group(2))

    m = _END_RE.search(text)
    if m:
        return _parse_match(m.group(1), m.group(2))

    m = _VERBOSE_RE.search(text)
    if m:
        return _parse_match(m.group(1), m.group(2))

    return None


def budget_continuation_message(pct: float, used_tokens: int, budget: int) -> str:
    """
    Message injected when the model hits the token budget mid-turn.
    Tells the model to keep working without summarizing — same as Claude Code.
    """
    return (
        f"Stopped at {pct:.0f}% of token target "
        f"({used_tokens:,} / {budget:,}). "
        "Keep working — do not summarize."
    )
