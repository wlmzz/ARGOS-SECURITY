"""
ARGOS — Threat Memory Extraction
Adapted from Claude Code services/extractMemories/extractMemories.ts (Anthropic Inc.)

Runs as a background task at the end of each threat analysis turn.
Forks a lightweight Seneca call to extract durable threat intel and write it to:
  - THREATS.md  (entrypoint index, ≤200 lines)
  - logs/YYYY/MM/DD.md  (daily append-only log)
  - detections/{id}.md  (per-threat detail)
  - ioc/ioc_list.md  (Indicators of Compromise)

Key adaptations from Claude Code:
  - No "forked agent" with shared prompt cache (Python async task instead)
  - cursor tracking via _last_extracted_event_id (avoid re-extracting same events)
  - Writes to ARGOS memory hierarchy instead of ~/.claude/
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from .paths import (
    ensure_memory_root,
    get_daily_log_path,
    get_detection_path,
    get_entrypoint,
    get_ioc_path,
    is_memory_enabled,
    prune_entrypoint,
    safe_append,
    safe_write,
)

log = logging.getLogger("argos.memory.extract")

LLAMA_URL  = ""   # set at runtime by ThreatMemoryExtractor
LLAMA_MODEL = ""

# Cursor: last event ID processed (avoids re-extraction, same pattern as Claude Code)
_last_extracted_id: Optional[str] = None

# ─── EXTRACTION PROMPTS ───────────────────────────────────────────────────────

_EXTRACT_SYSTEM = """\
You are ARGOS threat intelligence archivist.
Extract durable threat intelligence from the provided analysis and format it for storage.
Be concise, technical, and precise. Use MITRE ATT&CK technique IDs when applicable.\
"""

def _build_extraction_prompt(event: dict, decision: dict) -> str:
    return f"""\
Threat analysis completed. Extract intelligence for long-term storage.

Event:
  Type: {event.get('threat_type')}
  Severity: {event.get('severity')}
  Source IP: {event.get('source_ip')}
  Target Port: {event.get('target_port')}
  Description: {event.get('description', '')}

Decision:
  Action: {decision.get('action')}
  Confidence: {decision.get('confidence', 0):.2f}
  Reasoning: {decision.get('reasoning', '')}

Extract and output a JSON object with:
{{
  "threat_summary": "1-2 sentence summary for index",
  "iocs": ["IP addresses", "domains", "hashes"],
  "mitre_techniques": ["T1595", "..."],
  "threat_actor_notes": "attribution if known, else null",
  "remediation_status": "pending|applied|verified",
  "tags": ["brute_force", "repeat_offender", "..."],
  "severity": "low|medium|high|critical",
  "daily_log_entry": "one-line entry for daily log"
}}
Output only the JSON object.\
"""


# ─── EXTRACTOR ────────────────────────────────────────────────────────────────

class ThreatMemoryExtractor:
    """
    Extracts threat intelligence from analysis results and persists to memory.
    Runs as a background asyncio task (non-blocking to main analysis loop).
    """

    def __init__(
        self,
        llama_url: str = "http://localhost:8080",
        model: str = "argos-current",
        project_id: Optional[str] = None,
    ) -> None:
        self.llama_url  = llama_url
        self.model      = model
        self.project_id = project_id

    def schedule(self, event: dict, decision: dict) -> asyncio.Task:
        """
        Schedule background extraction (non-blocking).
        Returns the task (can be awaited or ignored).
        Same pattern as Claude Code's 'run forked agent without awaiting'.
        """
        return asyncio.create_task(
            self._extract(event, decision),
            name=f"extract-{event.get('id', 'unknown')}",
        )

    async def _extract(self, event: dict, decision: dict) -> None:
        global _last_extracted_id
        event_id = event.get("id", "")

        # Cursor check: skip if already extracted (Claude Code extractMemories pattern)
        if event_id and event_id == _last_extracted_id:
            log.debug("[Extract] Skipping already-extracted event %s", event_id)
            return

        if not is_memory_enabled():
            return

        ensure_memory_root(self.project_id)

        t0 = time.monotonic()
        try:
            intel = await self._call_seneca(event, decision)
            if intel:
                await asyncio.gather(
                    self._update_entrypoint(event, decision, intel),
                    self._append_daily_log(event, decision, intel),
                    self._write_detection_file(event, decision, intel),
                    self._update_ioc_list(intel),
                )
                _last_extracted_id = event_id
                log.info("[Extract] Extraction done in %.2fs", time.monotonic() - t0)
        except Exception as exc:
            log.warning("[Extract] Failed: %s", exc)

    async def _call_seneca(self, event: dict, decision: dict) -> Optional[dict]:
        """Lightweight Seneca call — no tools, just extraction."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":       self.model,
                        "messages":    [
                            {"role": "system", "content": _EXTRACT_SYSTEM},
                            {"role": "user",   "content": _build_extraction_prompt(event, decision)},
                        ],
                        "temperature": 0.05,
                        "max_tokens":  512,
                        "stream":      False,
                    },
                )
            if r.status_code == 200:
                content = r.json()["choices"][0]["message"]["content"].strip()
                content = content.lstrip("```json").lstrip("```").rstrip("```").strip()
                return json.loads(content)
        except Exception as exc:
            log.debug("[Extract] Seneca call failed: %s — using fallback", exc)
        return self._fallback_intel(event, decision)

    def _fallback_intel(self, event: dict, decision: dict) -> dict:
        """Rule-based fallback when Seneca is unavailable."""
        return {
            "threat_summary": f"{event.get('severity','?').upper()} {event.get('threat_type','unknown')} from {event.get('source_ip','?')}",
            "iocs":            [event.get("source_ip")] if event.get("source_ip") else [],
            "mitre_techniques": [],
            "threat_actor_notes": None,
            "remediation_status": "pending",
            "tags": [event.get("threat_type", "unknown")],
            "severity": event.get("severity", "medium"),
            "daily_log_entry": (
                f"[{event.get('threat_type')}] {event.get('source_ip')} → "
                f"port {event.get('target_port')} → action: {decision.get('action')}"
            ),
        }

    # ── Writers ───────────────────────────────────────────────────────────────

    async def _update_entrypoint(self, event: dict, decision: dict, intel: dict) -> None:
        """
        Add a one-line pointer to THREATS.md index.
        Format: - [Title](detection/{id}.md) — summary  (Claude Code index pattern)
        """
        ep = get_entrypoint(self.project_id)
        event_id   = event.get("id", f"unknown_{int(time.time())}")
        severity   = intel.get("severity", "medium").upper()
        summary    = intel.get("threat_summary", "")[:120]
        rel_path   = f"detections/{event_id}.md"
        ts         = datetime.now().strftime("%Y-%m-%d %H:%M")
        entry      = f"- [{severity} {event.get('threat_type')}]({rel_path}) — {summary} `{ts}`\n"

        if not ep.exists():
            ep.parent.mkdir(parents=True, exist_ok=True)
            ep.write_text(
                "# ARGOS Threat Intelligence\n\n## Active Threats\n\n## IOC Index\n",
                encoding="utf-8",
            )

        # Insert under "## Active Threats" section
        content = ep.read_text(encoding="utf-8")
        if "## Active Threats" in content:
            content = content.replace("## Active Threats\n", f"## Active Threats\n{entry}")
        else:
            content += f"\n{entry}"
        ep.write_text(content, encoding="utf-8")
        prune_entrypoint(self.project_id)

    async def _append_daily_log(self, event: dict, decision: dict, intel: dict) -> None:
        """Append to daily log (append-only, like Claude Code daily logs)."""
        log_path = get_daily_log_path(project_id=self.project_id)
        ts       = datetime.now().strftime("%H:%M:%S")
        entry = (
            f"### {ts} — {intel.get('severity','?').upper()} {event.get('threat_type','unknown')}\n"
            f"- IP: `{event.get('source_ip','?')}` → port `{event.get('target_port',0)}`\n"
            f"- Action: **{decision.get('action','?')}** (confidence {decision.get('confidence',0):.0%})\n"
            f"- {intel.get('daily_log_entry', event.get('description',''))}\n"
        )
        if intel.get("mitre_techniques"):
            entry += f"- MITRE: {', '.join(intel['mitre_techniques'])}\n"
        entry += "\n"
        safe_append(log_path, entry)

    async def _write_detection_file(self, event: dict, decision: dict, intel: dict) -> None:
        """Write per-threat detail file (like Claude Code topic files)."""
        event_id  = event.get("id", f"unknown_{int(time.time())}")
        det_path  = get_detection_path(event_id, self.project_id)
        ts        = datetime.now().isoformat()
        content   = f"""\
# Detection: {event.get('threat_type','unknown')} — {event.get('source_ip','?')}

*Created: {ts}*

## Summary
{intel.get('threat_summary', '')}

## Event Details
| Field | Value |
|-------|-------|
| Threat Type | {event.get('threat_type')} |
| Severity | {intel.get('severity', event.get('severity'))} |
| Source IP | `{event.get('source_ip')}` |
| Target Port | `{event.get('target_port')}` |
| Protocol | {event.get('protocol','tcp')} |

## Decision
- **Action:** {decision.get('action')}
- **Confidence:** {decision.get('confidence', 0):.0%}
- **Reasoning:** {decision.get('reasoning', '')}

## Indicators of Compromise
{chr(10).join(f'- `{ioc}`' for ioc in intel.get('iocs', [])) or '- None identified'}

## MITRE ATT&CK
{chr(10).join(f'- [{t}](https://attack.mitre.org/techniques/{t.replace(".", "/")})' for t in intel.get('mitre_techniques', [])) or '- Not mapped'}

## Threat Actor
{intel.get('threat_actor_notes') or 'Unknown'}

## Remediation Status
{intel.get('remediation_status', 'pending').upper()}

## Tags
{', '.join(f'`{t}`' for t in intel.get('tags', []))}
"""
        safe_write(det_path, content)

    async def _update_ioc_list(self, intel: dict) -> None:
        """Append new IOCs to the IOC master list."""
        iocs = intel.get("iocs", [])
        if not iocs:
            return
        ioc_path = get_ioc_path(self.project_id)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = "\n".join(
            f"| `{ioc}` | {intel.get('severity','?')} | {ts} |"
            for ioc in iocs
        )
        if not ioc_path.exists():
            header = "# IOC List\n\n| IOC | Severity | First Seen |\n|-----|----------|------------|\n"
            safe_write(ioc_path, header)
        safe_append(ioc_path, lines + "\n")
