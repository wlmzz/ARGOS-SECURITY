"""
ARGOS — Modular System Prompt Sections
Adapted from Claude Code constants/systemPromptSections.ts (Anthropic Inc.)

Two section types (same as Claude Code):
  - Cached sections: computed once, reused across turns (static content)
  - Volatile sections: recomputed every turn (session memory, live threat context)

Usage:
    from .sections import build_system_prompt, clear_cache

    prompt = await build_system_prompt(
        base_prompt    = ANALYSIS_SYSTEM_PROMPT,
        session_memory = session_memory_obj,
        active_event   = event_dict,
    )
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Union

log = logging.getLogger("argos.prompts.sections")

ComputeFn = Callable[[], Union[Optional[str], Awaitable[Optional[str]]]]

# ─── SECTION TYPE ─────────────────────────────────────────────────────────────

@dataclass
class PromptSection:
    """
    A named system prompt section.
    volatile=False → cached after first compute (like Claude Code's cacheBreak=false).
    volatile=True  → recomputed every turn (like DANGEROUS_uncachedSystemPromptSection).
    """
    name:     str
    compute:  ComputeFn
    volatile: bool = False


# ─── SECTION FACTORY FUNCTIONS ────────────────────────────────────────────────

def cached_section(name: str, compute: ComputeFn) -> PromptSection:
    """Static section: computed once and cached until clear_cache()."""
    return PromptSection(name=name, compute=compute, volatile=False)


def volatile_section(name: str, compute: ComputeFn) -> PromptSection:
    """Dynamic section: recomputed every turn. Use sparingly (breaks prompt cache)."""
    return PromptSection(name=name, compute=compute, volatile=True)


# ─── CACHE ────────────────────────────────────────────────────────────────────

_section_cache: dict[str, Optional[str]] = {}


def clear_cache() -> None:
    """
    Clear the section cache. Called after /compact or session reset.
    Mirrors Claude Code's clearSystemPromptSections().
    """
    _section_cache.clear()
    log.debug("[Sections] Cache cleared")


# ─── RESOLUTION ───────────────────────────────────────────────────────────────

async def _resolve_one(section: PromptSection) -> Optional[str]:
    if not section.volatile and section.name in _section_cache:
        return _section_cache[section.name]

    result = section.compute()
    if asyncio.iscoroutine(result):
        value = await result
    else:
        value = result

    if not section.volatile:
        _section_cache[section.name] = value

    return value


async def resolve_sections(sections: list[PromptSection]) -> list[str]:
    """
    Resolve all sections in parallel (same as Claude Code's Promise.all).
    Returns list of non-empty strings in order.
    """
    results = await asyncio.gather(*[_resolve_one(s) for s in sections])
    return [r for r in results if r]


# ─── HIGH-LEVEL BUILDER ───────────────────────────────────────────────────────

async def build_system_prompt(
    base_prompt:    str,
    session_memory: Optional[object] = None,
    active_event:   Optional[dict]   = None,
    extra_sections: Optional[list[PromptSection]] = None,
) -> str:
    """
    Assemble the full system prompt from sections.

    Structure:
      1. Base prompt (cached static)
      2. Session memory (volatile — updated every N tool calls)
      3. Active threat context (volatile — changes per event)
      4. Any extra custom sections

    The base prompt is always first so llama.cpp can cache it.
    Volatile sections go last to minimize cache misses on the static prefix.
    """
    sections: list[PromptSection] = [
        cached_section("base", lambda: base_prompt),
    ]

    # Session memory — injected from SessionMemory.to_system_section()
    if session_memory is not None:
        mem_obj = session_memory   # capture for closure
        sections.append(
            volatile_section(
                "session_memory",
                lambda: mem_obj.to_system_section() if hasattr(mem_obj, "to_system_section") else None,
            )
        )

    # Active threat context
    if active_event is not None:
        evt = active_event  # capture for closure
        sections.append(
            volatile_section(
                "active_threat",
                lambda: _format_active_threat(evt),
            )
        )

    if extra_sections:
        sections.extend(extra_sections)

    parts = await resolve_sections(sections)
    return "\n\n".join(parts)


def _format_active_threat(event: dict) -> Optional[str]:
    """Format the current event as a system prompt section."""
    if not event:
        return None
    lines = [
        "\n## Active Threat Context",
        f"- **Type:** {event.get('threat_type', 'unknown')}",
        f"- **Severity:** {event.get('severity', 'unknown')}",
        f"- **Source IP:** `{event.get('source_ip', 'unknown')}`",
        f"- **Target Port:** `{event.get('target_port', 0)}`",
    ]
    if event.get("history_count"):
        lines.append(f"- **Prior incidents from this IP:** {event['history_count']}")
    return "\n".join(lines)
