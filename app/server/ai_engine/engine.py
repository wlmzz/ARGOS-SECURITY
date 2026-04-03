"""
ARGOS — AI Engine Orchestrator
4-layer threat analysis chain:
  Layer 1 — Seneca-32B via llama.cpp  (agentic, tool-augmented — PRIMARY)
  Layer 2 — Phi-4 14B via Ollama      (local LLM fallback)
  Layer 2b— LM Studio                 (OpenAI-compatible fallback)
  Layer 3 — Rule-based fallback       (deterministic, always available)
  Layer 4 — Claude API escalation     (optional, very-low-confidence only)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx

from .coordinator import CoordinatorEngine
from .dream import DreamEngine
from .escalation import ClaudeEscalation
from .fallback import RuleBasedEngine
from .prompts import SYSTEM_PROMPT, build_threat_prompt
from .seneca_engine import SenecaEngine
from .memory import ThreatMemoryExtractor, SessionMemory
from .services.hooks import (
    register_dream_hook,
    register_memory_extraction_hook,
    register_metrics_hook,
    register_session_memory_hook,
)
from .services.magic_docs import MagicDocsService
from .services.hooks_http import register_env_webhook
from .services.tool_persistence import ToolPersistence

log = logging.getLogger("argos.ai")

_CONFIDENCE_ESCALATION_THRESHOLD = 0.5
_DEFAULT_SESSION = "argos-main"


class AIEngine:
    """
    Orchestrates the 4-layer AI analysis pipeline.

    Usage
    -----
    engine = AIEngine()
    await engine.check_ollama()   # call once at startup (probes all layers)
    result = await engine.analyze(event_dict)
    """

    def __init__(
        self,
        ollama_url:     Optional[str] = None,
        model:          Optional[str] = None,
        claude_api_key: Optional[str] = None,
        llama_url:      Optional[str] = None,
    ) -> None:
        self.ollama_url   = ollama_url or os.getenv("OLLAMA_URL",    "http://localhost:11434")
        self.model        = model      or os.getenv("ARGOS_AI_MODEL", "phi4:14b")
        self.lmstudio_url = os.getenv("LMSTUDIO_URL", "http://localhost:1234")

        _llama_url = llama_url or os.getenv("ARGOS_LLAMA_URL", "http://localhost:8080")
        _llama_model = os.getenv("ARGOS_LLAMA_MODEL", "argos-current")

        # Memory subsystem
        self._session_memory = SessionMemory(
            session_id = _DEFAULT_SESSION,
            llama_url  = _llama_url,
            model      = _llama_model,
        )
        self._extractor = ThreatMemoryExtractor(
            llama_url  = _llama_url,
            model      = _llama_model,
        )
        self._magic_docs = MagicDocsService(
            llama_url = _llama_url,
            model     = _llama_model,
        )

        from .tools import ToolExecutor
        _persistence = ToolPersistence(session_id=_DEFAULT_SESSION)
        _executor = ToolExecutor(
            llama_url   = _llama_url,
            magic_docs  = self._magic_docs,
            persistence = _persistence,
        )

        self._fallback    = RuleBasedEngine()
        self._claude      = ClaudeEscalation(claude_api_key)
        self._seneca      = SenecaEngine(
            llama_url      = _llama_url,
            tool_executor  = _executor,
            session_memory = self._session_memory,
            session_id     = _DEFAULT_SESSION,
        )
        self._coordinator = CoordinatorEngine(self._seneca)
        self._dream       = DreamEngine(llama_url=_llama_url)

        self._ollama_available   = False
        self._lmstudio_available = False
        self._lmstudio_model     = ""

        # Register built-in post-sampling hooks (same order as Claude Code)
        register_memory_extraction_hook(self._extractor)
        register_session_memory_hook(self._session_memory)
        register_dream_hook(self._dream)

        # Auto-register HTTP webhook from env (if ARGOS_WEBHOOK_URL is set)
        register_env_webhook()

    # ── Availability probe ──────────────────────────────────────────────────────

    async def check_ollama(self) -> bool:
        """Probe all LLM backends and set availability flags."""
        # Layer 1: Seneca / llama.cpp
        await self._seneca.check_available()

        # Layer 2: Ollama
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.ollama_url}/api/tags")
                self._ollama_available = r.status_code == 200
        except Exception:
            self._ollama_available = False

        # Layer 2b: LM Studio
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.lmstudio_url}/v1/models")
                self._lmstudio_available = r.status_code == 200
                if self._lmstudio_available:
                    models = r.json().get("data", [])
                    if models:
                        self._lmstudio_model = models[0]["id"]
                        log.info("[AIEngine] LM Studio available: %s", self._lmstudio_model)
        except Exception:
            self._lmstudio_available = False

        active = []
        if self._seneca.available:         active.append("Seneca-32B")
        if self._ollama_available:         active.append(f"Ollama/{self.model}")
        if self._lmstudio_available:       active.append(f"LMStudio/{self._lmstudio_model}")
        active.append("RuleBased")
        log.info("[AIEngine] Active layers: %s", " → ".join(active))

        return True  # rule-based is always available

    # ── Public analysis entry-point ─────────────────────────────────────────────

    async def analyze(self, event: dict) -> dict:
        """
        Analyze a threat event through the 4-layer AI chain.

        Returns dict with: severity_confirmed, action, reasoning, confidence,
        escalate_to_human.
        """
        prompt = build_threat_prompt(event)

        # ── Layer 1a: Coordinator (parallel workers — high-severity threats) ──
        if self._seneca.available and self._coordinator.should_coordinate(event):
            result = await self._coordinator.investigate(event)
            if result is not None:
                log.info("[AIEngine] Coordinator: action=%s confidence=%.2f",
                         result.get("action"), result.get("confidence", 0))
                self._dream.notify_events(1)
                return result

        # ── Layer 1b: Seneca-32B (single agent — standard threats) ────────────
        if self._seneca.available:
            result = await self._seneca.analyze(event)
            if result is not None:
                log.info(
                    "[AIEngine] Seneca: action=%s confidence=%.2f",
                    result.get("action"), result.get("confidence", 0),
                )
                if (
                    result.get("confidence", 1.0) < _CONFIDENCE_ESCALATION_THRESHOLD
                    and self._claude.available
                ):
                    claude_result = await self._claude.analyze(event, SYSTEM_PROMPT, prompt)
                    if claude_result is not None:
                        log.info("[AIEngine] Claude escalation after Seneca (low confidence)")
                        return claude_result
                self._dream.notify_events(1)
                return result

        # ── Layer 2: Ollama → LM Studio ───────────────────────────────────────
        result = None
        if self._ollama_available:
            result = await self._analyze_ollama(prompt)
        if result is None and self._lmstudio_available:
            result = await self._analyze_lmstudio(prompt)

        if result is not None:
            if (
                result.get("confidence", 1.0) < _CONFIDENCE_ESCALATION_THRESHOLD
                and self._claude.available
            ):
                claude_result = await self._claude.analyze(event, SYSTEM_PROMPT, prompt)
                if claude_result is not None:
                    return claude_result
            return result

        # ── Layer 3: Rule-based fallback ───────────────────────────────────────
        result = self._fallback.analyze(event)
        log.debug(
            "[AIEngine] Rule-based: action=%s confidence=%.2f",
            result.get("action"), result.get("confidence", 0.0),
        )

        # ── Layer 4: Claude escalation for unknown / low-confidence ──────────
        if (
            result.get("confidence", 1.0) < _CONFIDENCE_ESCALATION_THRESHOLD
            and self._claude.available
        ):
            claude_result = await self._claude.analyze(event, SYSTEM_PROMPT, prompt)
            if claude_result is not None:
                log.info("[AIEngine] Claude escalation (rule-based confidence=%.2f)",
                         result.get("confidence", 0.0))
                return claude_result

        return result

    # ── Ollama call (Layer 2) ───────────────────────────────────────────────────

    async def _analyze_ollama(self, prompt: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": SYSTEM_PROMPT,
                        "stream": False,
                        "options": {"temperature": 0.1},
                    },
                )
                if r.status_code == 200:
                    return json.loads(r.json().get("response", "{}"))
                log.warning("[Ollama] Status %d", r.status_code)
        except json.JSONDecodeError as exc:
            log.warning("[Ollama] Invalid JSON: %s", exc)
        except Exception as exc:
            log.error("[Ollama] Error: %s", exc)
            self._ollama_available = False
        return None

    # ── LM Studio call (Layer 2b) ───────────────────────────────────────────────

    async def _analyze_lmstudio(self, prompt: str) -> Optional[dict]:
        model = self._lmstudio_model or "local-model"
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.lmstudio_url}/v1/chat/completions",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 512,
                        "stream": False,
                    },
                )
                if r.status_code == 200:
                    content = r.json()["choices"][0]["message"]["content"]
                    content = content.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
                    return json.loads(content)
                log.warning("[LMStudio] Status %d", r.status_code)
        except json.JSONDecodeError as exc:
            log.warning("[LMStudio] Invalid JSON: %s", exc)
        except Exception as exc:
            log.error("[LMStudio] Error: %s", exc)
            self._lmstudio_available = False
        return None

    # ── Seneca chat proxy (for ai_chat API endpoint) ────────────────────────────

    async def chat(self, messages: list[dict], system: Optional[str] = None) -> str:
        """Proxy to Seneca's interactive chat mode with full tool access."""
        if self._seneca.available:
            return await self._seneca.chat(messages, system=system)
        return "Seneca AI engine is not available. Check llama.cpp service status."
