"""
ARGOS — Unicode Sanitization
Adapted from Claude Code utils/sanitization.ts (Anthropic Inc.)

Security measures against Unicode-based hidden character attacks:
ASCII Smuggling and Hidden Prompt Injection vulnerabilities.
These attacks use invisible Unicode characters (Tag chars, format controls,
private-use areas) to hide malicious instructions that are invisible to users
but processed by AI models.

Vulnerability demonstrated in HackerOne #3086545 targeting Claude Desktop's
MCP implementation. ARGOS applies this sanitization to all external inputs:
threat samples, scanned file contents, tool results.

Reference: https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Union

# Safety limit to prevent infinite loops on adversarial input
_MAX_ITERATIONS = 10

# Explicit dangerous character ranges (fallback for environments where
# regex Unicode property classes behave unexpectedly)
_EXPLICIT_RANGES = re.compile(
    r"[\u200B-\u200F"   # Zero-width spaces, LTR/RTL marks
    r"\u202A-\u202E"    # Directional formatting characters
    r"\u2066-\u2069"    # Directional isolates
    r"\uFEFF"           # Byte order mark
    r"\uE000-\uF8FF]"  # Basic Multilingual Plane private use
)

# Unicode property class equivalents — covers Cf (format), Co (private-use),
# Cn (unassigned/noncharacter). Python's unicodedata lets us check categories.
_DANGEROUS_CATEGORIES = frozenset({"Cf", "Co", "Cn"})


def _strip_by_category(text: str) -> str:
    """Remove chars in dangerous Unicode general categories (Cf, Co, Cn)."""
    return "".join(
        ch for ch in text
        if unicodedata.category(ch) not in _DANGEROUS_CATEGORIES
    )


def partially_sanitize_unicode(prompt: str) -> str:
    """
    Iteratively apply NFKC normalization + dangerous-character stripping
    until the string stabilises or MAX_ITERATIONS is reached.

    Raises ValueError if MAX_ITERATIONS is hit (indicates adversarial input
    or a bug — fail loudly so the issue is not silently ignored).
    """
    current = prompt
    previous = ""
    iterations = 0

    while current != previous and iterations < _MAX_ITERATIONS:
        previous = current

        # 1. NFKC normalization — decompose + recompose, handles composed seqs
        current = unicodedata.normalize("NFKC", current)

        # 2. Strip by Unicode category (primary defence)
        current = _strip_by_category(current)

        # 3. Explicit range fallback (belt-and-suspenders)
        current = _EXPLICIT_RANGES.sub("", current)

        iterations += 1

    if iterations >= _MAX_ITERATIONS:
        raise ValueError(
            f"Unicode sanitization reached maximum iterations ({_MAX_ITERATIONS}) "
            f"for input: {prompt[:100]!r}"
        )

    return current


def recursively_sanitize_unicode(value: Any) -> Any:
    """
    Recursively sanitize all string values in a nested structure
    (str, list, dict). Non-string primitives pass through unchanged.

    Safe to call on any tool result or LLM message before processing.
    """
    if isinstance(value, str):
        return partially_sanitize_unicode(value)

    if isinstance(value, list):
        return [recursively_sanitize_unicode(item) for item in value]

    if isinstance(value, dict):
        return {
            recursively_sanitize_unicode(k): recursively_sanitize_unicode(v)
            for k, v in value.items()
        }

    # numbers, booleans, None — pass through unchanged
    return value
