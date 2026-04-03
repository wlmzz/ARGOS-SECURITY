"""
ARGOS — Seneca Engine
Agentic analysis using Seneca-32B (QwQ-32B base) via llama.cpp OpenAI-compatible API.

Architecture inspired by Claude Code's query loop (Anthropic Inc.).
Adapted for Python + OpenAI API format + ARGOS cybersecurity context.

Loop pattern (from Claude Code):
  1. Call model with messages + tools
  2. Parse tool_calls from response → execute → append results → repeat
  3. When no more tool_calls → extract final text response
  4. Stop at max_iterations as safety net

Integrated features (all from Claude Code patterns):
  - Auto-compaction    — compact conversation when approaching 32K context limit
  - Session memory     — volatile system prompt section updated every 3 tool calls
  - Post-sampling hooks — memory extraction, metrics, dream notification at turn-end
  - Modular prompts    — cached static + volatile dynamic system prompt sections
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Optional

import httpx

from .tools import ALL_TOOLS, ANALYSIS_TOOLS, ToolExecutor
from .services.compaction import CompactionEngine
from .services.hooks import (
    HookContext,
    execute_hooks_background,
)
from .prompts.sections import build_system_prompt, clear_cache as clear_prompt_cache

log = logging.getLogger("argos.seneca")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

LLAMA_URL   = os.getenv("ARGOS_LLAMA_URL",   "http://localhost:8080")
LLAMA_MODEL = os.getenv("ARGOS_LLAMA_MODEL", "argos-current")

MAX_ANALYSIS_ITER = 8    # max tool-call rounds for threat analysis
MAX_CHAT_ITER     = 20   # max rounds for interactive chat
ANALYSIS_TIMEOUT  = 120  # seconds per llama.cpp call during analysis
CHAT_TIMEOUT      = 60   # seconds per llama.cpp call during chat

# ─── SYSTEM PROMPTS ───────────────────────────────────────────────────────────
# Adapted from Claude Code's prompts.ts for ARGOS cybersecurity context

ANALYSIS_SYSTEM_PROMPT = """\
You are ARGOS, an autonomous cybersecurity AI analyst powered by Seneca-32B.
Analyze security threats using tools to gather evidence before drawing conclusions.

Investigation workflow:
1. check_threat_history for the source IP — look for repeat offenders
2. get_network_connections — verify if the threat is still active
3. web_search for the IP/pattern — check threat intelligence feeds
4. bash — inspect server logs if needed (e.g. grep /var/log/auth.log)
5. query_qdrant — check known attack signatures in the knowledge base

After investigation, end your response with a JSON block:
```json
{
  "severity_confirmed": true,
  "action": "block_ip",
  "reasoning": "Confirmed SSH brute force from known botnet. 47 prior incidents. Active connection confirmed.",
  "confidence": 0.95,
  "escalate_to_human": false
}
```

Valid actions:
  block_ip        — confirmed attacker, brute force, repeat offender (confidence > 0.8)
  deploy_honeypot — port scan detected, gather attacker intelligence
  isolate_process — confirmed malware process running
  close_port      — actively exploited vulnerable port
  alert_human     — ambiguous, novel attack, or confidence < 0.6
  monitor         — low-risk anomaly, needs observation

Always end with the JSON block, even if investigation is inconclusive.\
"""

CHAT_SYSTEM_PROMPT = """\
You are ARGOS, an autonomous cybersecurity AI powered by Seneca-32B.
You assist security operators with threat investigation, incident response, and system analysis.

You have tools for:
- Running commands on the ARGOS server (bash)
- Reading, writing, editing files (read_file, write_file, edit_file)
- Searching file contents (grep, glob)
- Fetching web content and threat intel (web_fetch, web_search)
- Checking network connections (get_network_connections)
- Querying the ARGOS threat database (get_threat_history)
- Server system status (get_system_info)
- RAG knowledge base (query_qdrant)

Use tools proactively. Be technical and concise. Give evidence-based answers.\
"""

# ─── JSON EXTRACTION ──────────────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[dict]:
    """Extract a JSON object from model output (handles markdown code blocks)."""
    # Try ```json ... ``` block first
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # Try bare JSON object anywhere in the text
    start = text.find("{")
    end   = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    return None


# ─── SENECA ENGINE ─────────────────────────────────────────────────────────────

class SenecaEngine:
    """
    Drop-in replacement for AIEngine that uses Seneca-32B with tool-augmented
    investigation instead of a single-shot prompt.

    Integrates:
      - CompactionEngine   — auto-compacts at 80% of 32K context window
      - SessionMemory      — injects running session context into system prompt
      - Post-sampling hooks — fires memory extraction, metrics, dream at turn-end
    """

    def __init__(
        self,
        llama_url:      Optional[str]          = None,
        model:          Optional[str]          = None,
        tool_executor:  Optional[ToolExecutor] = None,
        session_memory: Optional[object]       = None,   # SessionMemory instance
        session_id:     str                    = "",
    ) -> None:
        self.llama_url      = llama_url or LLAMA_URL
        self.model          = model or LLAMA_MODEL
        self._executor      = tool_executor or ToolExecutor(llama_url=self.llama_url)
        self._session_memory = session_memory
        self._session_id    = session_id
        self._compaction    = CompactionEngine(
            llama_url=self.llama_url,
            model=self.model,
        )
        self._available: Optional[bool] = None

    # ── Availability check ─────────────────────────────────────────────────────

    async def check_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.llama_url}/v1/models")
                self._available = r.status_code == 200
        except Exception:
            self._available = False

        state = "available" if self._available else "NOT reachable"
        log.info("[Seneca] llama.cpp %s at %s", state, self.llama_url)
        return bool(self._available)

    @property
    def available(self) -> bool:
        return self._available is True

    # ── Threat analysis (drop-in for AIEngine.analyze) ─────────────────────────

    async def analyze(self, event: dict) -> Optional[dict]:
        """
        Investigate a threat event with tool-augmented reasoning.
        Returns normalized decision dict or None on failure (caller falls back).
        """
        if not self.available:
            return None

        # Build system prompt with session memory + active threat context sections
        system = await build_system_prompt(
            base_prompt    = ANALYSIS_SYSTEM_PROMPT,
            session_memory = self._session_memory,
            active_event   = event,
        )

        prompt   = _build_threat_prompt(event)
        messages = [{"role": "user", "content": prompt}]

        t0 = time.monotonic()
        try:
            response, tool_call_count = await self._run_loop(
                system=system,
                messages=messages,
                tools=ANALYSIS_TOOLS,
                max_iter=MAX_ANALYSIS_ITER,
                timeout=ANALYSIS_TIMEOUT,
            )
        except Exception as exc:
            log.error("[Seneca] analyze() failed: %s", exc)
            return None

        duration_s = time.monotonic() - t0
        log.info("[Seneca] Analysis done in %.1fs (%d tool calls)", duration_s, tool_call_count)

        result = _extract_json(response)
        if result is None:
            log.warning("[Seneca] No JSON in response — returning None")
            return None

        decision = {
            "severity_confirmed": bool(result.get("severity_confirmed", True)),
            "action":             str(result.get("action", "alert_human")),
            "reasoning":          str(result.get("reasoning", "")),
            "confidence":         float(result.get("confidence", 0.7)),
            "escalate_to_human":  bool(result.get("escalate_to_human", False)),
        }

        # Post-sampling hooks (fire-and-forget — same pattern as Claude Code)
        ctx = HookContext(
            event           = event,
            decision        = decision,
            messages        = messages,
            tool_call_count = tool_call_count,
            turn_duration_s = duration_s,
            session_id      = self._session_id,
        )
        execute_hooks_background(ctx)

        return decision

    # ── Interactive chat ───────────────────────────────────────────────────────

    async def chat(
        self,
        messages: list[dict],
        system:   Optional[str] = None,
    ) -> str:
        """
        Interactive chat with full tool access.
        messages: list of {role, content} dicts (OpenAI format).
        Returns the final assistant text.
        """
        effective_system = system
        if effective_system is None:
            effective_system = await build_system_prompt(
                base_prompt    = CHAT_SYSTEM_PROMPT,
                session_memory = self._session_memory,
            )

        t0 = time.monotonic()
        response, tool_call_count = await self._run_loop(
            system   = effective_system,
            messages = messages,
            tools    = ALL_TOOLS,
            max_iter = MAX_CHAT_ITER,
            timeout  = CHAT_TIMEOUT,
        )

        # Post-sampling hooks for chat turns (no event/decision, but track metrics)
        ctx = HookContext(
            messages        = messages,
            tool_call_count = tool_call_count,
            turn_duration_s = time.monotonic() - t0,
            session_id      = self._session_id,
        )
        execute_hooks_background(ctx)

        return response

    # ── Core agentic loop ──────────────────────────────────────────────────────

    async def _run_loop(
        self,
        system:   str,
        messages: list[dict],
        tools:    list[dict],
        max_iter: int,
        timeout:  int,
    ) -> tuple[str, int]:
        """
        Claude Code-style agentic loop adapted for OpenAI format + llama.cpp.

        Returns (final_text, total_tool_call_count).

        Each iteration:
          - Auto-compact if approaching 32K context limit
          - Call the model
          - If response contains tool_calls → execute → append results → loop
          - If response is plain text → return it
        """
        conversation      = list(messages)
        total_tool_calls  = 0

        for iteration in range(max_iter):
            log.debug("[Seneca] Iteration %d/%d", iteration + 1, max_iter)

            # Auto-compact before calling the model (same trigger point as Claude Code)
            conversation = await self._compaction.maybe_compact(conversation, system)
            if self._compaction.compact_count > 0:
                # Cache-break prompt sections after compaction (like clearSystemPromptSections)
                clear_prompt_cache()

            msg = await self._call_llm(system, conversation, tools, timeout)
            if msg is None:
                return (
                    '{"action":"alert_human","reasoning":"AI engine unavailable",'
                    '"confidence":0,"escalate_to_human":true}',
                    total_tool_calls,
                )

            conversation.append(msg)

            # Update session memory token estimate after each model call
            if self._session_memory and hasattr(self._session_memory, "on_tool_call"):
                total_chars = sum(len(str(m)) for m in conversation)
                self._session_memory.on_tool_call(estimated_tokens=total_chars // 4)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                # No tool calls → final answer
                return msg.get("content") or "", total_tool_calls

            # Execute all tool calls (concurrently)
            tool_results = await self._execute_tool_calls(tool_calls)
            conversation.extend(tool_results)
            total_tool_calls += len(tool_calls)

        # Exhausted iterations — return last text response
        log.warning("[Seneca] Reached max iterations (%d)", max_iter)
        for msg in reversed(conversation):
            if msg.get("role") == "assistant" and msg.get("content"):
                return msg["content"], total_tool_calls
        return (
            '{"action":"alert_human","reasoning":"Analysis incomplete",'
            '"confidence":0.3,"escalate_to_human":true}',
            total_tool_calls,
        )

    # ── LLM call ──────────────────────────────────────────────────────────────

    async def _call_llm(
        self,
        system:   str,
        messages: list[dict],
        tools:    list[dict],
        timeout:  int,
    ) -> Optional[dict]:
        """POST to llama.cpp /v1/chat/completions. Returns assistant message dict."""
        all_messages = [{"role": "system", "content": system}] + messages

        payload: dict[str, Any] = {
            "model":       self.model,
            "messages":    all_messages,
            "temperature": 0.1,
            "max_tokens":  2048,
            "stream":      False,
        }
        if tools:
            payload["tools"]       = tools
            payload["tool_choice"] = "auto"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json=payload,
                )

            if r.status_code != 200:
                log.error("[Seneca] llama.cpp returned %d: %s", r.status_code, r.text[:400])
                self._available = False
                return None

            choice = r.json().get("choices", [{}])[0]
            return choice.get("message", {})

        except httpx.TimeoutException:
            log.error("[Seneca] LLM call timed out after %ds", timeout)
            return None
        except Exception as exc:
            log.error("[Seneca] LLM call error: %s", exc)
            self._available = False
            return None

    # ── Tool execution ─────────────────────────────────────────────────────────

    async def _execute_tool_calls(self, tool_calls: list[dict]) -> list[dict]:
        """Execute tool calls concurrently, return list of tool result messages."""

        async def _run(tc: dict) -> tuple[str, str]:
            call_id = tc.get("id", "")
            fn      = tc.get("function", {})
            name    = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}
            log.info("[Seneca] → %s(%s)", name, str(args)[:80])
            t0     = time.monotonic()
            result = await self._executor.execute(name, args, call_id=call_id)
            log.debug("[Seneca] ← %s in %.2fs", name, time.monotonic() - t0)
            return call_id, result

        outcomes = await asyncio.gather(*[_run(tc) for tc in tool_calls], return_exceptions=True)

        messages: list[dict] = []
        for i, outcome in enumerate(outcomes):
            if isinstance(outcome, Exception):
                call_id = tool_calls[i].get("id", str(i))
                content = f"[ERROR] {outcome}"
            else:
                call_id, content = outcome

            messages.append({
                "role":         "tool",
                "tool_call_id": call_id,
                "content":      str(content),
            })
        return messages


# ─── PROMPT BUILDER ───────────────────────────────────────────────────────────

def _build_threat_prompt(event: dict) -> str:
    lines = [
        "Analyze this security threat and determine the best response.",
        "",
        f"Threat Type:  {event.get('threat_type', 'unknown')}",
        f"Severity:     {event.get('severity', 'unknown')}",
        f"Source IP:    {event.get('source_ip', 'unknown')}",
        f"Target Port:  {event.get('target_port', 0)}",
        f"Protocol:     {event.get('protocol', 'tcp')}",
        f"Description:  {event.get('description', '')}",
        f"Raw Data:\n{json.dumps(event.get('raw_data', {}), indent=2)}",
    ]
    if event.get("history_count"):
        lines.append(f"Previous incidents from this IP: {event['history_count']}")
    if event.get("device_platform"):
        lines.append(f"Server platform: {event['device_platform']}")
    lines += ["", "Use your tools to investigate, then provide your JSON analysis."]
    return "\n".join(lines)
