"""
ARGOS — Claude API Escalation
Async escalation to Claude for unprecedented or low-confidence threats.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx

log = logging.getLogger("argos.escalation")


class ClaudeEscalation:
    """Claude API escalation for unprecedented threats."""

    API_URL = "https://api.anthropic.com/v1/messages"
    MODEL = "claude-opus-4-6"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.available = bool(self._api_key)

    async def analyze(
        self,
        event: dict,
        system_prompt: str,
        threat_prompt: str,
    ) -> Optional[dict]:
        """
        Send the threat prompt to Claude and return the parsed JSON response.
        Returns None if the API key is absent, the request fails, or the
        response cannot be parsed as valid JSON.
        """
        if not self.available:
            return None

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    self.API_URL,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self.MODEL,
                        "max_tokens": 300,
                        "system": system_prompt,
                        "messages": [{"role": "user", "content": threat_prompt}],
                    },
                )
                if r.status_code == 200:
                    content = r.json()["content"][0]["text"]
                    result = json.loads(content)
                    log.info(
                        "[Claude] Escalation result: %s (confidence=%.2f)",
                        result.get("action"),
                        result.get("confidence", 0.0),
                    )
                    return result
                else:
                    log.warning("[Claude] API returned status %d", r.status_code)
        except json.JSONDecodeError as exc:
            log.warning("[Claude] Response is not valid JSON: %s", exc)
        except Exception as exc:
            log.error("[Claude] Escalation failed: %s", exc)

        return None
