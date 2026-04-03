"""
ARGOS — Agent Summary
Adapted from Claude Code services/AgentSummary/agentSummary.ts (Anthropic Inc.)

Periodically generates 3-5 word progress summaries for coordinator worker agents.
"Reading /var/log/auth.log", "Querying Qdrant threat intel", etc.

Used by CoordinatorEngine to surface live worker status to the operator.
Runs as a background asyncio task — stops automatically when the worker finishes.

Usage:
    from .agent_summary import AgentSummarizer
    summarizer = AgentSummarizer(worker_id="ip_research", llama_url=...)
    summarizer.start(messages_getter=lambda: worker.messages)
    ...
    summarizer.stop()
    print(summarizer.latest)   # "Querying SearXNG for 1.2.3.4"
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

import httpx

log = logging.getLogger("argos.agent_summary")

# How often to regenerate the summary (same as Claude Code: 30s)
SUMMARY_INTERVAL_S = 30

_SYSTEM = """\
Describe the worker agent's most recent action in 3-5 words, present tense (-ing).
Name the specific tool, file, or IP — never be vague.
Return ONLY the 3-5 word phrase. No punctuation, no explanation.\
"""

def _build_prompt(messages: list[dict], previous: Optional[str]) -> str:
    # Extract the last few tool names + results for context
    lines: list[str] = []
    for m in messages[-6:]:
        role    = m.get("role", "")
        content = m.get("content") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p) for p in content
            )
        if role in ("assistant", "tool"):
            lines.append(f"[{role.upper()}]: {str(content)[:200]}")

    prev_line = f'\nPrevious summary: "{previous}" — say something NEW.' if previous else ""

    return (
        "Recent worker activity:\n"
        + "\n".join(lines)
        + prev_line
        + "\n\nDescribe the MOST RECENT action in 3-5 words."
    )


class AgentSummarizer:
    """
    Runs a background loop that every SUMMARY_INTERVAL_S seconds
    calls Seneca (no tools) to produce a short progress label.
    """

    def __init__(
        self,
        worker_id: str,
        llama_url: str = "http://localhost:8080",
        model:     str = "argos-current",
    ) -> None:
        self.worker_id  = worker_id
        self.llama_url  = llama_url
        self.model      = model
        self.latest:    Optional[str] = None
        self._task:     Optional[asyncio.Task] = None
        self._stopped   = False

    def start(self, messages_getter: Callable[[], list[dict]]) -> None:
        """
        Start the background summarization loop.
        messages_getter: a callable that returns the worker's current messages list.
        """
        if self._task and not self._task.done():
            return
        self._stopped = False
        self._task = asyncio.create_task(
            self._loop(messages_getter),
            name=f"agent-summary-{self.worker_id}",
        )

    def stop(self) -> None:
        """Stop the background summarization loop."""
        self._stopped = True
        if self._task and not self._task.done():
            self._task.cancel()

    async def _loop(self, messages_getter: Callable[[], list[dict]]) -> None:
        await asyncio.sleep(SUMMARY_INTERVAL_S)   # first summary after a delay
        while not self._stopped:
            try:
                messages = messages_getter()
                if len(messages) >= 3:
                    summary = await self._generate(messages)
                    if summary:
                        self.latest = summary
                        log.debug("[AgentSummary] %s: %s", self.worker_id, summary)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("[AgentSummary] %s error: %s", self.worker_id, exc)

            if not self._stopped:
                try:
                    await asyncio.sleep(SUMMARY_INTERVAL_S)
                except asyncio.CancelledError:
                    break

    async def _generate(self, messages: list[dict]) -> Optional[str]:
        prompt = _build_prompt(messages, self.latest)
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":       self.model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens":  20,
                        "stream":      False,
                    },
                )
            if r.status_code == 200:
                text = r.json()["choices"][0]["message"]["content"].strip()
                # Enforce max length (trim to ≤ 8 words)
                words = text.split()
                return " ".join(words[:8])
        except Exception as exc:
            log.debug("[AgentSummary] Generation failed: %s", exc)
        return None
