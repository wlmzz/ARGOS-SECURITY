"""
ARGOS Autonomous Agent — Core loop (inspired by OpenClaw's pi-embedded-runner).

Architecture:
  User message → session history → LLM (Seneca-32B @ llama.cpp :8080)
    → tool calls → execute → add results → repeat until final answer
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable

import urllib.request

from session import Session
from tools import ALL_TOOLS

log = logging.getLogger("argos.agent")

# Configurable via env vars for flexibility
# ARGOS_LLM_URL  → default port 8080 (Seneca-32B, slow but powerful)
# ARGOS_LLM_FAST → port 8090 (professor 7B models, faster when loaded)
import os
LLAMA_API  = os.getenv("ARGOS_LLM_URL", "http://localhost:8080/v1/chat/completions")
LLAMA_KEY  = os.getenv("ARGOS_LLM_KEY", "change_me_secret_key")
MODEL_NAME = os.getenv("ARGOS_LLM_MODEL", "seneca-32b")
MAX_LOOPS  = int(os.getenv("ARGOS_MAX_LOOPS", "8"))   # max tool-calling iterations
MAX_RETRY  = 3                                          # retries on API error

SYSTEM_PROMPT = """You are ARGOS, an advanced autonomous cybersecurity AI agent.

Your capabilities:
- Network reconnaissance: port scanning, DNS, WHOIS, traceroute
- OSINT: CVE lookups, IP reputation, hash analysis, IOC extraction
- Log analysis: detect brute force, SQL injection, XSS, C2 beacons, ransomware
- Threat intelligence: MITRE ATT&CK mapping, incident classification
- Security reports: structured findings with severity and remediation

Operational guidelines:
- Only perform reconnaissance on systems you are explicitly authorized to scan
- Always state your findings clearly with severity levels (CRITICAL/HIGH/MEDIUM/LOW)
- Use multiple tools to triangulate findings before drawing conclusions
- When analyzing logs or incidents, extract IOCs and map to MITRE ATT&CK techniques
- Generate structured reports for significant findings
- Think step by step: plan → gather data → analyze → report

You are running on the ARGOS server. Respond in the same language as the user."""


def _build_tool_spec(tool_name: str, tool_def: dict) -> dict:
    """Convert internal tool definition to OpenAI function-calling format."""
    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": tool_def["description"],
            "parameters": tool_def["parameters"],
        }
    }


def _call_llm(messages: list[dict], tools: list[dict],
              temperature: float = 0.3, max_tokens: int = 2048) -> dict:
    """Call llama.cpp OpenAI-compatible API."""
    payload = json.dumps({
        "model": MODEL_NAME,
        "messages": messages,
        "tools": tools if tools else None,
        "tool_choice": "auto" if tools else None,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }, ensure_ascii=False).encode()

    req = urllib.request.Request(
        LLAMA_API,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LLAMA_KEY}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def _execute_tool(name: str, args: dict, session_id: str = "unknown") -> str:
    """Execute a tool and return JSON result string."""
    import time as _time
    from audit import log_tool_call
    if name not in ALL_TOOLS:
        return json.dumps({"error": f"Unknown tool: {name}"})
    tool_def = ALL_TOOLS[name]
    start = _time.monotonic()
    success = True
    result = None
    try:
        result = tool_def["fn"](**args)
        return json.dumps(result, ensure_ascii=False, default=str)[:6000]
    except Exception as e:
        success = False
        result = {"error": str(e)}
        log.exception("Tool %s failed: %s", name, e)
        return json.dumps(result)
    finally:
        log_tool_call(
            session_id=session_id,
            tool_name=name,
            params=args,
            result=result,
            duration_ms=(_time.monotonic() - start) * 1000,
            success=success,
        )


def run(user_message: str, session: Session,
        on_chunk: Callable[[str], None] | None = None) -> str:
    """
    Main agentic loop — returns final response string.
    on_chunk: called with partial text as it becomes available.
    """
    session.add("user", user_message)

    tools_spec = [_build_tool_spec(n, d) for n, d in ALL_TOOLS.items()]
    system = [{"role": "system", "content": SYSTEM_PROMPT}]

    loop_count = 0
    final_response = ""

    while loop_count < MAX_LOOPS:
        loop_count += 1
        messages = system + session.get_messages()

        # Check if compaction needed
        if session.needs_compaction():
            log.info("Session needs compaction, summarizing...")
            summary_resp = _call_llm(
                system + session.get_messages() + [
                    {"role": "user", "content": "Summarize the conversation so far in 3-5 sentences for context."}
                ],
                tools=[],
                max_tokens=300,
            )
            summary = summary_resp["choices"][0]["message"]["content"]
            session.compact(summary)
            messages = system + session.get_messages()

        # Call LLM
        for attempt in range(MAX_RETRY):
            try:
                response = _call_llm(messages, tools_spec)
                break
            except Exception as e:
                log.warning("LLM call failed (attempt %d/%d): %s", attempt + 1, MAX_RETRY, e)
                if attempt == MAX_RETRY - 1:
                    return f"[ARGOS ERROR] Unable to reach model after {MAX_RETRY} attempts: {e}"
                time.sleep(2 ** attempt)

        choice = response["choices"][0]
        msg = choice["message"]
        finish_reason = choice.get("finish_reason", "stop")

        # No tool calls → final answer
        if finish_reason == "stop" or not msg.get("tool_calls"):
            final_response = msg.get("content", "").strip()
            session.add("assistant", final_response)
            if on_chunk:
                on_chunk(final_response)
            break

        # Process tool calls
        tool_calls = msg.get("tool_calls", [])
        session.add("assistant", msg.get("content") or "")

        for tc in tool_calls:
            fn = tc["function"]
            tool_name = fn["name"]
            try:
                args = json.loads(fn.get("arguments", "{}"))
            except Exception:
                args = {}

            log.info("Executing tool: %s(%s)", tool_name,
                     json.dumps(args, ensure_ascii=False)[:100])

            result = _execute_tool(tool_name, args, session_id=session.session_id)

            # Add tool result to history
            session.history.append({
                "role": "tool",
                "tool_call_id": tc.get("id", tool_name),
                "name": tool_name,
                "content": result,
            })

    else:
        final_response = "[ARGOS] Maximum tool iterations reached. Summarizing findings..."
        session.add("assistant", final_response)

    return final_response
