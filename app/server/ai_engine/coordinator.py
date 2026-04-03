"""
ARGOS — Coordinator Engine
Multi-agent threat investigation using parallel Seneca workers.

Adapted from Claude Code's Coordinator Mode (2/ directory, Anthropic Inc.):
  - Coordinator spawns parallel workers for independent investigation angles
  - Workers return results via <task-notification> XML (same protocol as Claude Code)
  - Coordinator synthesizes findings into final threat decision

For complex/high-severity threats, the coordinator fans out investigation:
  Worker 1 → IP reputation + threat intel (web_search, web_fetch, query_qdrant)
  Worker 2 → Server logs + auth attempts  (bash, grep, read_file)
  Worker 3 → Live network analysis        (get_network_connections, get_threat_history)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .seneca_engine import SenecaEngine, _build_threat_prompt
from .tools import ToolExecutor, ANALYSIS_TOOLS

log = logging.getLogger("argos.coordinator")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Threats that trigger full coordinator investigation
HIGH_SEVERITY = {"critical", "high"}
COORDINATOR_THREAT_TYPES = {
    "brute_force", "port_scan", "repeat_offender",
    "ransomware", "exfiltration", "ddos", "suspicious_process",
}

# Worker-specific tool subsets (from coordinator pattern in Claude Code)
IP_RESEARCH_TOOLS = ["web_search", "web_fetch", "query_qdrant", "get_threat_history"]
LOG_ANALYSIS_TOOLS = ["bash", "read_file", "grep", "glob"]
NETWORK_TOOLS = ["get_network_connections", "get_system_info", "bash"]

# ─── TASK NOTIFICATION FORMAT ────────────────────────────────────────────────
# Same XML format as Claude Code's coordinator/coordinatorMode.ts

def _build_task_notification(task_id: str, status: str, summary: str, result: str) -> str:
    """Build <task-notification> XML (same format as Claude Code coordinator)."""
    return (
        f"<task-notification>\n"
        f"<task-id>{task_id}</task-id>\n"
        f"<status>{status}</status>\n"
        f"<summary>{summary}</summary>\n"
        f"<result>{result}</result>\n"
        f"</task-notification>"
    )


# ─── WORKER DEFINITION ───────────────────────────────────────────────────────

@dataclass
class WorkerSpec:
    task_id:  str
    role:     str   # "ip_research" | "log_analysis" | "network"
    prompt:   str
    tools:    list[str]  # allowed tool names

    @classmethod
    def ip_research(cls, event: dict) -> "WorkerSpec":
        ip   = event.get("source_ip", "unknown")
        port = event.get("target_port", 0)
        return cls(
            task_id = f"worker-ip-{uuid.uuid4().hex[:6]}",
            role    = "ip_research",
            tools   = IP_RESEARCH_TOOLS,
            prompt  = (
                f"Investigate IP {ip} (attacked port {port}).\n"
                f"1. web_search: '{ip} threat intelligence malicious'\n"
                f"2. web_search: '{ip} abuse report'\n"
                f"3. get_threat_history: check ARGOS database for this IP\n"
                f"4. query_qdrant: check knowledge base for known attack patterns\n"
                f"Summarize: IP reputation, attack history, threat actor attribution if available."
            ),
        )

    @classmethod
    def log_analysis(cls, event: dict) -> "WorkerSpec":
        ip          = event.get("source_ip", "unknown")
        threat_type = event.get("threat_type", "unknown")
        return cls(
            task_id = f"worker-log-{uuid.uuid4().hex[:6]}",
            role    = "log_analysis",
            tools   = LOG_ANALYSIS_TOOLS,
            prompt  = (
                f"Analyze server logs for evidence of {threat_type} from {ip}.\n"
                f"1. grep /var/log/auth.log for '{ip}' (last 100 lines)\n"
                f"2. grep /var/log/syslog for '{ip}'\n"
                f"3. bash: journalctl -n 200 --no-pager | grep '{ip}' (if systemd)\n"
                f"4. Check /var/log/nginx/access.log or /var/log/apache2/ if applicable\n"
                f"Summarize: number of attempts, timeframe, targeted services, any successful auth."
            ),
        )

    @classmethod
    def network_analysis(cls, event: dict) -> "WorkerSpec":
        ip   = event.get("source_ip", "unknown")
        port = event.get("target_port", 0)
        return cls(
            task_id = f"worker-net-{uuid.uuid4().hex[:6]}",
            role    = "network",
            tools   = NETWORK_TOOLS,
            prompt  = (
                f"Analyze live network activity related to IP {ip} on port {port}.\n"
                f"1. get_network_connections: filter for '{ip}'\n"
                f"2. get_system_info: check current server load\n"
                f"3. bash: ss -tnp | grep '{ip}' (check active sessions)\n"
                f"4. bash: netstat -an | grep '{port}' | head -20 (port activity)\n"
                f"Summarize: is the threat still active? open connections? server impact?"
            ),
        )


# ─── COORDINATOR ENGINE ───────────────────────────────────────────────────────

COORDINATOR_SYSTEM_PROMPT = """\
You are ARGOS Coordinator, an autonomous cybersecurity orchestrator powered by Seneca-32B.

Your role (adapted from Claude Code Coordinator Mode):
- Direct parallel workers to investigate threats from different angles
- Synthesize worker findings into a definitive threat assessment
- Never fabricate or predict worker results — wait for their actual output

Worker results arrive as <task-notification> XML blocks. Parse them to extract findings.

After all workers report, synthesize findings and provide final JSON:
```json
{
  "severity_confirmed": true,
  "action": "block_ip",
  "reasoning": "3-point synthesis of worker findings",
  "confidence": 0.95,
  "escalate_to_human": false,
  "worker_findings": {
    "ip_research": "summary",
    "log_analysis": "summary",
    "network": "summary"
  }
}
```

Valid actions: block_ip | deploy_honeypot | isolate_process | close_port | alert_human | monitor\
"""


class CoordinatorEngine:
    """
    Multi-agent threat coordinator.

    Spawns parallel Seneca workers (IP research, log analysis, network check)
    then synthesizes their findings into a final decision.

    Usage:
        coordinator = CoordinatorEngine(seneca_engine)
        result = await coordinator.investigate(event_dict)
    """

    def __init__(self, seneca: Optional[SenecaEngine] = None) -> None:
        self._seneca   = seneca or SenecaEngine()
        self._executor = self._seneca._executor

    def should_coordinate(self, event: dict) -> bool:
        """Decide if this threat warrants full coordinator investigation."""
        severity    = event.get("severity", "")
        threat_type = event.get("threat_type", "")
        return (
            severity in HIGH_SEVERITY
            or threat_type in COORDINATOR_THREAT_TYPES
        )

    async def investigate(self, event: dict) -> Optional[dict]:
        """
        Full coordinator investigation: spawn workers, synthesize findings.
        Returns normalized decision dict or None on failure.
        """
        if not self._seneca.available:
            return None

        log.info(
            "[Coordinator] Starting investigation: %s from %s",
            event.get("threat_type"), event.get("source_ip"),
        )
        t0 = time.monotonic()

        # Phase 1: Research — spawn workers in parallel
        workers = [
            WorkerSpec.ip_research(event),
            WorkerSpec.log_analysis(event),
            WorkerSpec.network_analysis(event),
        ]

        worker_results = await asyncio.gather(
            *[self._run_worker(w) for w in workers],
            return_exceptions=True,
        )

        # Phase 2: Synthesis — coordinator reads findings
        notifications = []
        for spec, result in zip(workers, worker_results):
            if isinstance(result, Exception):
                summary = f"Worker failed: {result}"
                text    = "No findings available"
            else:
                summary = f"Worker '{spec.role}' completed"
                text    = str(result)[:2000]

            notifications.append(
                _build_task_notification(spec.task_id, "completed", summary, text)
            )

        # Build synthesis prompt
        synthesis_prompt = self._build_synthesis_prompt(event, workers, notifications)

        # Phase 3: Coordinator synthesizes
        try:
            response = await self._seneca._run_loop(
                system   = COORDINATOR_SYSTEM_PROMPT,
                messages = [{"role": "user", "content": synthesis_prompt}],
                tools    = [],   # coordinator doesn't need tools here — just synthesis
                max_iter = 2,
                timeout  = 60,
            )
        except Exception as exc:
            log.error("[Coordinator] Synthesis failed: %s", exc)
            return None

        log.info("[Coordinator] Investigation done in %.1fs", time.monotonic() - t0)

        from .seneca_engine import _extract_json
        result = _extract_json(response)
        if result is None:
            return None

        return {
            "severity_confirmed": bool(result.get("severity_confirmed", True)),
            "action":             str(result.get("action", "alert_human")),
            "reasoning":          str(result.get("reasoning", "")),
            "confidence":         float(result.get("confidence", 0.7)),
            "escalate_to_human":  bool(result.get("escalate_to_human", False)),
            "coordinator_used":   True,
            "worker_findings":    result.get("worker_findings", {}),
        }

    async def _run_worker(self, spec: WorkerSpec) -> str:
        """Run a single worker using a filtered tool executor."""
        # Create a tool-filtered executor for this worker
        filtered_executor = _FilteredExecutor(self._executor, set(spec.tools))
        worker_engine = SenecaEngine(
            llama_url     = self._seneca.llama_url,
            model         = self._seneca.model,
            tool_executor = filtered_executor,
        )
        worker_engine._available = self._seneca._available

        # Build worker tool list
        tool_defs = [t for t in ANALYSIS_TOOLS if t["function"]["name"] in spec.tools]

        log.info("[Coordinator] Worker '%s' starting", spec.role)
        try:
            result = await worker_engine._run_loop(
                system = (
                    f"You are ARGOS Worker ({spec.role}). "
                    f"Investigate the threat using your assigned tools. "
                    f"Be thorough but concise. Return findings as plain text."
                ),
                messages = [{"role": "user", "content": spec.prompt}],
                tools    = tool_defs,
                max_iter = 5,
                timeout  = 90,
            )
            log.info("[Coordinator] Worker '%s' done", spec.role)
            return result
        except Exception as exc:
            log.error("[Coordinator] Worker '%s' failed: %s", spec.role, exc)
            return f"Worker failed: {exc}"

    def _build_synthesis_prompt(
        self,
        event: dict,
        workers: list[WorkerSpec],
        notifications: list[str],
    ) -> str:
        lines = [
            "All workers have completed. Synthesize findings into a final threat assessment.",
            "",
            f"Original threat: {event.get('threat_type')} | {event.get('severity')} | {event.get('source_ip')}",
            f"Description: {event.get('description', '')}",
            "",
            "Worker findings:",
            "",
        ]
        for notif in notifications:
            lines.append(notif)
            lines.append("")
        lines += [
            "Based on all worker findings, provide your final JSON assessment.",
        ]
        return "\n".join(lines)


# ─── FILTERED EXECUTOR ────────────────────────────────────────────────────────

class _FilteredExecutor(ToolExecutor):
    """ToolExecutor that restricts available tools to an allowed set."""

    def __init__(self, base: ToolExecutor, allowed: set[str]) -> None:
        # Copy all state from base
        super().__init__(
            db_path     = base.db_path,
            searxng_url = base.searxng_url,
            qdrant_url  = base.qdrant_url,
            llama_url   = base.llama_url,
        )
        self._allowed = allowed

    async def execute(self, name: str, args: dict) -> str:
        if name not in self._allowed:
            return f"[ERROR] Tool '{name}' not available to this worker"
        return await super().execute(name, args)
