"""
ARGOS — Dream System (Threat Intel Memory Consolidation)
Background consolidation of threat events into durable Qdrant knowledge.

Adapted from Claude Code's autoDream system (2/ directory, Anthropic Inc.):
  - 3-gate trigger: time elapsed + min events + consolidation lock
  - 4-phase process: Orient → Gather signal → Consolidate → Prune
  - Runs as a background asyncio task (not a forked subagent like in Claude Code)

In ARGOS context, "memory consolidation" means:
  - Read recent threat events from SQLite
  - Use Seneca to identify patterns, recurring attackers, new attack signatures
  - Store synthesized threat intel in Qdrant (argos_attacks, threat_intel collections)
  - Update /opt/argos/training/datasets/ for next training cycle
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

log = logging.getLogger("argos.dream")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

MIN_HOURS_BETWEEN_DREAMS = float(os.getenv("ARGOS_DREAM_MIN_HOURS", "24"))
MIN_EVENTS_BETWEEN_DREAMS = int(os.getenv("ARGOS_DREAM_MIN_EVENTS", "10"))

DREAM_STATE_FILE = Path(os.getenv("ARGOS_DREAM_STATE", "/opt/argos/dream_state.json"))
ARGOS_DB         = Path(os.getenv("ARGOS_DB_PATH", str(Path.home() / ".argos" / "threats.db")))
QDRANT_URL       = os.getenv("QDRANT_URL", "http://localhost:6333")
LLAMA_URL        = os.getenv("ARGOS_LLAMA_URL", "http://localhost:8080")
LLAMA_MODEL      = os.getenv("ARGOS_LLAMA_MODEL", "argos-current")

# Training dataset output path
TRAINING_DATASET_DIR = Path("/opt/argos/training/datasets/foundational")

# ─── LOCK ─────────────────────────────────────────────────────────────────────

_dream_lock = asyncio.Lock()
_dream_running = False


# ─── STATE ────────────────────────────────────────────────────────────────────

def _read_state() -> dict:
    try:
        if DREAM_STATE_FILE.exists():
            return json.loads(DREAM_STATE_FILE.read_text())
    except Exception:
        pass
    return {"last_dream_at": 0, "events_since_dream": 0, "dream_count": 0}


def _write_state(state: dict) -> None:
    try:
        DREAM_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        DREAM_STATE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as exc:
        log.warning("[Dream] Could not write state: %s", exc)


# ─── GATE CHECK ───────────────────────────────────────────────────────────────

def _should_dream(new_events: int) -> tuple[bool, str]:
    """
    3-gate trigger (cheapest first — same order as Claude Code autoDream):
      1. Time: >= MIN_HOURS_BETWEEN_DREAMS since last dream
      2. Events: >= MIN_EVENTS_BETWEEN_DREAMS since last dream
      3. Lock: no other dream in progress
    """
    global _dream_running
    if _dream_running:
        return False, "dream already running"

    state = _read_state()
    now   = time.time()

    hours_since = (now - state.get("last_dream_at", 0)) / 3600
    if hours_since < MIN_HOURS_BETWEEN_DREAMS:
        return False, f"only {hours_since:.1f}h since last dream (min {MIN_HOURS_BETWEEN_DREAMS}h)"

    total_events = state.get("events_since_dream", 0) + new_events
    if total_events < MIN_EVENTS_BETWEEN_DREAMS:
        return False, f"only {total_events} events (min {MIN_EVENTS_BETWEEN_DREAMS})"

    return True, f"triggering dream ({hours_since:.1f}h elapsed, {total_events} events)"


# ─── DREAM ENGINE ─────────────────────────────────────────────────────────────

class DreamEngine:
    """
    Background threat intel consolidation.

    Called after batches of threat events to decide if consolidation is needed,
    then runs the 4-phase consolidation process using Seneca-32B.
    """

    def __init__(self, llama_url: Optional[str] = None, model: Optional[str] = None) -> None:
        self.llama_url = llama_url or LLAMA_URL
        self.model     = model or LLAMA_MODEL

    def notify_events(self, count: int = 1) -> None:
        """Call this after new threat events are saved to update the event counter."""
        state = _read_state()
        state["events_since_dream"] = state.get("events_since_dream", 0) + count
        _write_state(state)

    async def maybe_dream(self, new_events: int = 0) -> bool:
        """
        Check gates and run dream if triggered.
        Returns True if a dream was run, False otherwise.
        """
        should, reason = _should_dream(new_events)
        if not should:
            log.debug("[Dream] Skipping: %s", reason)
            return False

        log.info("[Dream] Triggering: %s", reason)
        asyncio.create_task(self._run_dream())
        return True

    async def _run_dream(self) -> None:
        """
        4-phase consolidation (adapted from Claude Code consolidationPrompt.ts):
          Phase 1 — Orient: read recent threat summary
          Phase 2 — Gather signal: fetch events from SQLite
          Phase 3 — Consolidate: Seneca synthesizes patterns
          Phase 4 — Store: write to Qdrant + training dataset
        """
        global _dream_running
        async with _dream_lock:
            _dream_running = True
            t0 = time.monotonic()
            try:
                await self._dream_phases()
            except Exception as exc:
                log.error("[Dream] Failed: %s", exc, exc_info=True)
            finally:
                _dream_running = False
                log.info("[Dream] Completed in %.1fs", time.monotonic() - t0)

    async def _dream_phases(self) -> None:
        # Phase 1 — Orient
        log.info("[Dream] Phase 1: Orient")
        recent_events = await self._fetch_recent_events(limit=100)
        if not recent_events:
            log.info("[Dream] No recent events — nothing to consolidate")
            self._mark_dream_complete(0)
            return

        # Phase 2 — Gather signal
        log.info("[Dream] Phase 2: Gather signal (%d events)", len(recent_events))
        event_summary = self._build_event_summary(recent_events)

        # Phase 3 — Consolidate (Seneca synthesizes patterns)
        log.info("[Dream] Phase 3: Consolidate")
        insights = await self._consolidate_with_seneca(event_summary, recent_events)

        # Phase 4 — Store
        log.info("[Dream] Phase 4: Store")
        stored = 0
        stored += await self._store_in_qdrant(insights)
        stored += await self._append_training_dataset(recent_events, insights)

        self._mark_dream_complete(len(recent_events))
        log.info("[Dream] Stored %d insight(s) from %d events", stored, len(recent_events))

    # ── Phase helpers ─────────────────────────────────────────────────────────

    async def _fetch_recent_events(self, limit: int = 100) -> list[dict]:
        """Read recent threat events from SQLite since last dream."""
        if not ARGOS_DB.exists():
            return []
        try:
            import aiosqlite
            state     = _read_state()
            since_ts  = datetime.fromtimestamp(
                state.get("last_dream_at", 0), tz=timezone.utc
            ).isoformat()

            async with aiosqlite.connect(str(ARGOS_DB)) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    """SELECT * FROM threats
                       WHERE timestamp > ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (since_ts, limit),
                ) as cur:
                    rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            log.error("[Dream] DB fetch failed: %s", exc)
            return []

    def _build_event_summary(self, events: list[dict]) -> str:
        """Build concise event summary for Seneca."""
        by_type: dict[str, list] = {}
        by_ip:   dict[str, int]  = {}
        for e in events:
            t  = e.get("threat_type", "unknown")
            ip = e.get("source_ip", "unknown")
            by_type.setdefault(t, []).append(e)
            by_ip[ip] = by_ip.get(ip, 0) + 1

        lines = [
            f"Recent threat events ({len(events)} total):",
            "",
            "By type:",
        ]
        for t, evts in sorted(by_type.items(), key=lambda x: -len(x[1])):
            lines.append(f"  {t}: {len(evts)} events")

        lines += ["", "Top source IPs:"]
        for ip, cnt in sorted(by_ip.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {ip}: {cnt} attacks")

        lines += ["", "Sample events (most recent 10):"]
        for e in events[:10]:
            lines.append(
                f"  [{e.get('timestamp', '')[:19]}] "
                f"{e.get('severity', '').upper()} {e.get('threat_type')} "
                f"from {e.get('source_ip')} — {e.get('description', '')[:80]}"
            )
        return "\n".join(lines)

    async def _consolidate_with_seneca(
        self, summary: str, events: list[dict]
    ) -> list[dict]:
        """Use Seneca to identify patterns and generate threat intel entries."""
        prompt = f"""\
You are performing a threat intelligence consolidation — a reflective analysis of recent security events.

{summary}

Your task (following the Dream consolidation pattern):
1. Identify recurring attack patterns and threat actor behaviors
2. Extract actionable threat intelligence (TTPs, indicators, attack signatures)
3. Identify the top threat actors (by IP frequency + attack diversity)
4. Note any novel or escalating threats requiring attention

For each significant finding, output a JSON object in this format:
{{"type": "threat_intel|attack_pattern|ioc|summary",
 "title": "brief title",
 "content": "detailed description",
 "confidence": 0.0-1.0,
 "iocs": ["ip", "..."],
 "mitre_techniques": ["T1595", "..."],
 "severity": "low|medium|high|critical"}}

Output a JSON array of these objects. Include 3-10 insights.
Only output the JSON array, no other text."""

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    f"{self.llama_url}/v1/chat/completions",
                    json={
                        "model":       self.model,
                        "messages":    [
                            {"role": "system", "content": "You are ARGOS threat intelligence analyst."},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens":  2048,
                        "stream":      False,
                    },
                )
            if r.status_code == 200:
                content = r.json()["choices"][0]["message"]["content"].strip()
                # Strip markdown code fences
                content = content.lstrip("```json").lstrip("```").rstrip("```").strip()
                insights = json.loads(content)
                if isinstance(insights, list):
                    return insights
        except Exception as exc:
            log.error("[Dream] Seneca consolidation failed: %s", exc)

        # Fallback: basic statistical summary
        return self._statistical_insights(events)

    def _statistical_insights(self, events: list[dict]) -> list[dict]:
        """Rule-based fallback when Seneca is unavailable."""
        by_ip: dict[str, list] = {}
        for e in events:
            ip = e.get("source_ip", "unknown")
            by_ip.setdefault(ip, []).append(e)

        insights = []
        for ip, evts in sorted(by_ip.items(), key=lambda x: -len(x[1]))[:5]:
            types = list({e.get("threat_type") for e in evts})
            insights.append({
                "type":       "ioc",
                "title":      f"Recurring attacker: {ip}",
                "content":    f"IP {ip} conducted {len(evts)} attacks: {', '.join(types)}",
                "confidence": min(0.5 + len(evts) * 0.05, 0.95),
                "iocs":       [ip],
                "severity":   "high" if len(evts) >= 5 else "medium",
            })
        return insights

    async def _store_in_qdrant(self, insights: list[dict]) -> int:
        """Store threat intel insights in Qdrant."""
        if not insights:
            return 0
        stored = 0
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Check if collection exists
                r = await client.get(f"{QDRANT_URL}/collections/threat_intel")
                if r.status_code == 404:
                    log.info("[Dream] Qdrant threat_intel not set up — saving to file instead")
                    return await self._save_insights_to_file(insights)

                for insight in insights:
                    # Try to get embedding
                    try:
                        emb_r = await client.post(
                            f"{self.llama_url}/v1/embeddings",
                            json={"input": insight.get("content", ""), "model": self.model},
                            timeout=10,
                        )
                        if emb_r.status_code == 200:
                            vector = emb_r.json()["data"][0]["embedding"]
                        else:
                            continue  # Skip if no embedding
                    except Exception:
                        continue

                    point_id = abs(hash(insight.get("title", "") + str(time.time()))) % (10 ** 9)
                    upsert_r = await client.put(
                        f"{QDRANT_URL}/collections/threat_intel/points",
                        json={
                            "points": [{
                                "id":      point_id,
                                "vector":  vector,
                                "payload": {
                                    **insight,
                                    "stored_at": datetime.now().isoformat(),
                                    "source": "argos_dream",
                                },
                            }]
                        },
                    )
                    if upsert_r.status_code == 200:
                        stored += 1

        except httpx.ConnectError:
            log.info("[Dream] Qdrant offline — saving to file")
            return await self._save_insights_to_file(insights)
        except Exception as exc:
            log.error("[Dream] Qdrant store failed: %s", exc)

        return stored

    async def _save_insights_to_file(self, insights: list[dict]) -> int:
        """Fallback: save insights to JSONL file for later Qdrant import."""
        try:
            out_dir = Path("/opt/argos/training/datasets/foundational")
            out_dir.mkdir(parents=True, exist_ok=True)
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = out_dir / f"dream_{ts}.jsonl"
            with out_file.open("w") as f:
                for insight in insights:
                    # Convert to instruction-tuning format for training
                    f.write(json.dumps({
                        "messages": [
                            {"role": "user",      "content": f"What do you know about: {insight.get('title')}?"},
                            {"role": "assistant", "content": insight.get("content", "")},
                        ]
                    }) + "\n")
            log.info("[Dream] Saved %d insights to %s", len(insights), out_file)
            return len(insights)
        except Exception as exc:
            log.error("[Dream] File save failed: %s", exc)
            return 0

    async def _append_training_dataset(
        self, events: list[dict], insights: list[dict]
    ) -> int:
        """
        Generate training pairs from events+decisions for the next fine-tuning cycle.
        Appends to /opt/argos/training/datasets/foundational/ JSONL files.
        """
        try:
            from .prompts import build_training_pair

            out_dir = TRAINING_DATASET_DIR
            out_dir.mkdir(parents=True, exist_ok=True)
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = out_dir / f"dream_training_{ts}.jsonl"

            pairs_written = 0
            with out_file.open("w") as f:
                for event in events:
                    if not event.get("ai_analysis") or not event.get("action_taken"):
                        continue
                    # Build training pair from event + AI decision
                    decision = {
                        "action":    event.get("action_taken", "alert_human").split(":")[0],
                        "reasoning": event.get("ai_analysis", ""),
                        "confidence": 0.9,
                    }
                    try:
                        prompt, completion = build_training_pair(event, decision)
                        f.write(json.dumps({
                            "messages": [
                                {"role": "system",    "content": "You are ARGOS cybersecurity analyst."},
                                {"role": "user",      "content": prompt},
                                {"role": "assistant", "content": completion},
                            ]
                        }) + "\n")
                        pairs_written += 1
                    except Exception:
                        pass

            if pairs_written:
                log.info("[Dream] Wrote %d training pairs to %s", pairs_written, out_file)
            return pairs_written
        except Exception as exc:
            log.warning("[Dream] Training dataset generation failed: %s", exc)
            return 0

    def _mark_dream_complete(self, events_processed: int) -> None:
        state = _read_state()
        state["last_dream_at"]      = time.time()
        state["events_since_dream"] = 0
        state["dream_count"]        = state.get("dream_count", 0) + 1
        _write_state(state)
        log.info(
            "[Dream] State updated — dream #%d, processed %d events",
            state["dream_count"], events_processed,
        )


# ─── BACKGROUND TASK ──────────────────────────────────────────────────────────

async def run_dream_scheduler(dream_engine: DreamEngine, check_interval_minutes: int = 60) -> None:
    """
    Background task that periodically checks if a dream should run.
    Call from server lifespan: asyncio.create_task(run_dream_scheduler(dream_engine))
    """
    log.info("[Dream] Scheduler started (check every %dm)", check_interval_minutes)
    while True:
        await asyncio.sleep(check_interval_minutes * 60)
        await dream_engine.maybe_dream(new_events=0)
