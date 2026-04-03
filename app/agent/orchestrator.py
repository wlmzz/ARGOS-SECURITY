"""
ARGOS Subagent Orchestrator — parallel multi-agent execution.
Inspired by OpenClaw's subagent-registry + subagent-control architecture.

Instead of sequential tool calls, the orchestrator spawns N child agents
simultaneously (each with their own session and tool subset), collects all
results, and aggregates them for the parent agent.

Key use cases for cybersecurity:
  - Recon blast: nmap + Shodan + theHarvester + subdomain_enum in parallel
  - Threat hunt: analyze auth.log + nginx + syslog simultaneously
  - Attribution: build dossier + AbuseIPDB + WHOIS + Sherlock at the same time

Architecture (mirrors OpenClaw):
  Parent session
    ├── SubagentRun(id=x, task="port scan", session="child-x") → thread
    ├── SubagentRun(id=y, task="osint",     session="child-y") → thread
    └── SubagentRun(id=z, task="log scan",  session="child-z") → thread
  All threads run concurrently; parent waits for all, aggregates results.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("argos.orchestrator")

MAX_SUBAGENTS    = 8      # max parallel subagents
SUBAGENT_TIMEOUT = 300    # seconds before a subagent is killed
STATE_FILE       = Path("/opt/argos/logs/subagent_runs.json")


class SubagentStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    DONE     = "done"
    ERROR    = "error"
    KILLED   = "killed"


@dataclass
class SubagentRun:
    run_id:       str
    parent_id:    str
    task:         str
    label:        str
    session_id:   str
    status:       SubagentStatus = SubagentStatus.PENDING
    result:       str | None = None
    error:        str | None = None
    started_at:   float | None = None
    ended_at:     float | None = None
    tools_filter: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float | None:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 1)
        return None

    def to_dict(self) -> dict:
        return {
            "run_id":      self.run_id,
            "parent_id":   self.parent_id,
            "label":       self.label,
            "task":        self.task[:200],
            "status":      self.status.value,
            "result":      self.result[:1000] if self.result else None,
            "error":       self.error,
            "duration_s":  self.duration_s,
            "started_at":  datetime.fromtimestamp(self.started_at, tz=timezone.utc).isoformat() if self.started_at else None,
            "ended_at":    datetime.fromtimestamp(self.ended_at, tz=timezone.utc).isoformat() if self.ended_at else None,
        }


# In-memory registry (mirrors OpenClaw's subagentRuns Map)
_registry: dict[str, SubagentRun] = {}
_registry_lock = threading.Lock()

_executor = ThreadPoolExecutor(max_workers=MAX_SUBAGENTS, thread_name_prefix="subagent")
_futures: dict[str, Future] = {}


def _persist() -> None:
    """Persist registry to disk for recovery after restart."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        snapshot = {rid: run.to_dict() for rid, run in _registry.items()}
        STATE_FILE.write_text(json.dumps(snapshot, indent=2, default=str))
    except Exception as e:
        log.warning("Failed to persist subagent state: %s", e)


def _run_subagent_task(run: SubagentRun) -> str:
    """Execute a subagent task — runs in its own thread."""
    # Import here to avoid circular imports
    import agent as argos_agent
    from session import Session
    from tools import ALL_TOOLS

    with _registry_lock:
        run.status = SubagentStatus.RUNNING
        run.started_at = time.time()
        _persist()

    log.info("[subagent:%s] Starting — %s", run.label, run.task[:80])

    try:
        sess = Session(run.session_id)

        # If tools_filter specified, run with a subset of tools
        if run.tools_filter:
            # Temporarily patch ALL_TOOLS for this thread (thread-local would be cleaner,
            # but agent.run reads ALL_TOOLS at call time from the module)
            filtered = {k: v for k, v in ALL_TOOLS.items() if k in run.tools_filter}
            original = dict(ALL_TOOLS)
            ALL_TOOLS.clear()
            ALL_TOOLS.update(filtered)
            try:
                result = argos_agent.run(run.task, sess)
            finally:
                ALL_TOOLS.clear()
                ALL_TOOLS.update(original)
        else:
            result = argos_agent.run(run.task, sess)

        with _registry_lock:
            run.status = SubagentStatus.DONE
            run.result = result or "(no output)"
            run.ended_at = time.time()
            _persist()

        log.info("[subagent:%s] Done in %.1fs", run.label, run.duration_s or 0)
        return result or ""

    except Exception as e:
        with _registry_lock:
            run.status = SubagentStatus.ERROR
            run.error = str(e)
            run.ended_at = time.time()
            _persist()
        log.error("[subagent:%s] Error: %s", run.label, e)
        raise


def spawn_subagents(tasks: list[dict], parent_session_id: str = "orchestrator",
                    wait: bool = True, timeout: int = SUBAGENT_TIMEOUT) -> dict:
    """Spawn multiple subagents in parallel and optionally wait for results.

    tasks: list of dicts, each with:
      - "task": str  — the prompt/instruction for the subagent (required)
      - "label": str — short name for logging/identification (optional)
      - "tools": list[str] — restrict to these tools only (optional)

    wait: if True (default), block until all subagents finish and return results.
          if False, return run_ids immediately (use subagent_status to poll).

    Returns dict with run_ids, statuses, and aggregated results.

    Example:
        spawn_subagents([
            {"task": "Scan ports on 192.168.1.1", "label": "portscan", "tools": ["nmap_scan", "masscan_scan"]},
            {"task": "Get OSINT on 192.168.1.1",  "label": "osint",    "tools": ["shodan_host", "ipwhois_lookup"]},
            {"task": "Check CVE-2024-1234",        "label": "cve"},
        ])
    """
    if not tasks:
        return {"error": "No tasks provided"}
    if len(tasks) > MAX_SUBAGENTS:
        return {"error": f"Max {MAX_SUBAGENTS} subagents at once"}

    runs = []
    for i, task_def in enumerate(tasks):
        task_text = task_def.get("task", "")
        if not task_text:
            continue
        label = task_def.get("label") or f"sub-{i+1}"
        run_id = str(uuid.uuid4())[:8]
        run = SubagentRun(
            run_id=run_id,
            parent_id=parent_session_id,
            task=task_text,
            label=label,
            session_id=f"subagent-{run_id}",
            tools_filter=task_def.get("tools", []),
        )
        with _registry_lock:
            _registry[run_id] = run
        runs.append(run)

    # Submit all to thread pool
    futures_map: dict[str, Future] = {}
    for run in runs:
        f = _executor.submit(_run_subagent_task, run)
        futures_map[run.run_id] = f
        with _registry_lock:
            _futures[run.run_id] = f

    if not wait:
        return {
            "status": "spawned",
            "run_ids": [r.run_id for r in runs],
            "labels": [r.label for r in runs],
            "message": f"Spawned {len(runs)} subagents. Use subagent_status(run_ids) to check progress.",
        }

    # Wait for all with timeout
    results = {}
    errors = {}
    start = time.time()
    for run in runs:
        remaining = max(1, timeout - (time.time() - start))
        f = futures_map[run.run_id]
        try:
            result = f.result(timeout=remaining)
            results[run.label] = result
        except TimeoutError:
            with _registry_lock:
                run.status = SubagentStatus.KILLED
                run.error = f"Timeout after {timeout}s"
                run.ended_at = time.time()
            f.cancel()
            errors[run.label] = f"timeout after {timeout}s"
        except Exception as e:
            errors[run.label] = str(e)

    return {
        "status": "complete",
        "total": len(runs),
        "succeeded": len(results),
        "failed": len(errors),
        "results": results,
        "errors": errors if errors else None,
        "runs": [r.to_dict() for r in runs],
    }


def subagent_status(run_ids: list[str] | None = None,
                    parent_session_id: str | None = None) -> dict:
    """Check status of subagent runs.
    run_ids: specific run IDs to check (optional)
    parent_session_id: filter by parent session (optional)
    Returns list of run records with status, result, and duration.
    """
    with _registry_lock:
        if run_ids:
            runs = [_registry[rid] for rid in run_ids if rid in _registry]
        elif parent_session_id:
            runs = [r for r in _registry.values() if r.parent_id == parent_session_id]
        else:
            runs = list(_registry.values())

    active = [r for r in runs if r.status in (SubagentStatus.PENDING, SubagentStatus.RUNNING)]
    done   = [r for r in runs if r.status == SubagentStatus.DONE]
    failed = [r for r in runs if r.status in (SubagentStatus.ERROR, SubagentStatus.KILLED)]

    return {
        "total": len(runs),
        "active": len(active),
        "done": len(done),
        "failed": len(failed),
        "runs": [r.to_dict() for r in runs],
    }


def kill_subagent(run_id: str) -> dict:
    """Kill a running subagent by run_id."""
    with _registry_lock:
        run = _registry.get(run_id)
        if not run:
            return {"error": f"Run {run_id} not found"}
        if run.status not in (SubagentStatus.PENDING, SubagentStatus.RUNNING):
            return {"status": "already_ended", "run_id": run_id, "final_status": run.status.value}
        run.status = SubagentStatus.KILLED
        run.ended_at = time.time()
        run.error = "Killed by operator"
        _persist()

    f = _futures.get(run_id)
    if f:
        f.cancel()

    return {"status": "killed", "run_id": run_id, "label": run.label}


def kill_all_subagents(parent_session_id: str | None = None) -> dict:
    """Kill all active subagents, optionally filtered by parent session."""
    with _registry_lock:
        targets = [
            r for r in _registry.values()
            if r.status in (SubagentStatus.PENDING, SubagentStatus.RUNNING)
            and (parent_session_id is None or r.parent_id == parent_session_id)
        ]

    killed = []
    for run in targets:
        result = kill_subagent(run.run_id)
        if result.get("status") == "killed":
            killed.append(run.label)

    return {"killed": len(killed), "labels": killed}


# --- Tools exposed to the agent ---

TOOLS = {
    "spawn_subagents": {
        "fn": spawn_subagents,
        "description": (
            "Spawn multiple specialized subagents in parallel, each focused on a specific task. "
            "Much faster than sequential tool calls — all subagents run simultaneously. "
            "Each subagent gets its own session and optional tool subset. "
            "Example: run port scan + OSINT + log analysis all at once on a target. "
            "wait=true returns aggregated results when all finish; wait=false returns run_ids immediately."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "description": "List of subagent task definitions",
                    "items": {
                        "type": "object",
                        "properties": {
                            "task":  {"type": "string", "description": "Full prompt/instruction for this subagent"},
                            "label": {"type": "string", "description": "Short name for identification (e.g. 'portscan', 'osint')"},
                            "tools": {"type": "array", "items": {"type": "string"},
                                      "description": "Optional: restrict subagent to these tool names only"},
                        },
                        "required": ["task"]
                    }
                },
                "parent_session_id": {"type": "string", "description": "Parent session identifier"},
                "wait":    {"type": "boolean", "description": "Wait for all results (default: true)"},
                "timeout": {"type": "integer", "description": "Max seconds per subagent (default: 300)"},
            },
            "required": ["tasks"]
        }
    },
    "subagent_status": {
        "fn": subagent_status,
        "description": "Check status of running or completed subagents. Returns progress, results, and errors.",
        "parameters": {
            "type": "object",
            "properties": {
                "run_ids":           {"type": "array", "items": {"type": "string"}, "description": "Specific run IDs to check"},
                "parent_session_id": {"type": "string", "description": "Filter by parent session"},
            },
            "required": []
        }
    },
    "kill_subagent": {
        "fn": kill_subagent,
        "description": "Kill a specific running subagent by its run_id.",
        "parameters": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string", "description": "Run ID of the subagent to kill"}
            },
            "required": ["run_id"]
        }
    },
    "kill_all_subagents": {
        "fn": kill_all_subagents,
        "description": "Kill all currently active subagents.",
        "parameters": {
            "type": "object",
            "properties": {
                "parent_session_id": {"type": "string", "description": "Optional: only kill subagents from this parent session"}
            },
            "required": []
        }
    },
}
