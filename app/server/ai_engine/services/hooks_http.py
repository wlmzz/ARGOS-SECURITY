"""
ARGOS — HTTP Webhook Hook Executor
Adapted from Claude Code utils/hooks/execHttpHook.ts (Anthropic Inc.)

Fires POST webhooks when threat decisions are made.
Integrates with SIEM, Splunk, PagerDuty, Slack, or any HTTP endpoint.

Security (same as Claude Code):
  - URL allowlist (ARGOS_WEBHOOK_ALLOWED_URLS env var)
  - SSRF guard: blocks private IP ranges unless loopback
  - Header env-var interpolation with explicit allowlist

Configuration via environment:
  ARGOS_WEBHOOK_URL          — default target URL
  ARGOS_WEBHOOK_TOKEN        — Bearer token (referenced as $ARGOS_WEBHOOK_TOKEN)
  ARGOS_WEBHOOK_ALLOWED_URLS — comma-separated URL patterns (* wildcard supported)

Usage:
    # Register at startup
    from .hooks_http import register_http_webhook_hook
    register_http_webhook_hook("https://siem.example.com/argos/events")

    # Or fire manually
    await exec_http_hook("https://...", payload_dict)
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
from typing import Optional

import httpx

from .hooks import HookContext, register_hook

log = logging.getLogger("argos.hooks.http")

# Default timeout: 30s (shorter than Claude Code's 10min — ARGOS is real-time)
DEFAULT_TIMEOUT_S = int(os.getenv("ARGOS_WEBHOOK_TIMEOUT", "30"))

# ─── SSRF GUARD ───────────────────────────────────────────────────────────────
# Adapted from Claude Code utils/hooks/ssrfGuard.ts

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is in a private/link-local range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return False   # loopback allowed (local dev)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _ssrf_check(url: str) -> Optional[str]:
    """
    Resolve the hostname and check for SSRF.
    Returns an error string if blocked, None if OK.
    """
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        ips  = socket.getaddrinfo(host, None)
        for item in ips:
            ip = item[4][0]
            if _is_private_ip(ip):
                return f"SSRF blocked: {url} resolves to private IP {ip}"
    except socket.gaierror as e:
        return f"DNS lookup failed for {url}: {e}"
    except Exception as e:
        return f"SSRF check error: {e}"
    return None


# ─── URL ALLOWLIST ────────────────────────────────────────────────────────────

def _url_matches_pattern(url: str, pattern: str) -> bool:
    """Simple glob match: * = any chars."""
    escaped  = re.escape(pattern).replace(r"\*", ".*")
    return bool(re.fullmatch(escaped, url))


def _get_allowed_urls() -> Optional[list[str]]:
    raw = os.getenv("ARGOS_WEBHOOK_ALLOWED_URLS", "")
    if not raw.strip():
        return None   # no restriction
    return [u.strip() for u in raw.split(",") if u.strip()]


def _check_allowed(url: str) -> Optional[str]:
    allowed = _get_allowed_urls()
    if allowed is None:
        return None   # unrestricted
    if not any(_url_matches_pattern(url, p) for p in allowed):
        return f"Webhook blocked: {url} not in ARGOS_WEBHOOK_ALLOWED_URLS"
    return None


# ─── HEADER ENV-VAR INTERPOLATION ────────────────────────────────────────────

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)")
_ALLOWED_VARS = {v.strip() for v in os.getenv("ARGOS_WEBHOOK_ENV_VARS", "ARGOS_WEBHOOK_TOKEN").split(",")}

def _interpolate_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Replace $VAR and ${VAR} in header values with env vars from the allowlist.
    Strips CR/LF/NUL to prevent header injection (same as Claude Code).
    """
    out: dict[str, str] = {}
    for name, value in headers.items():
        def _replace(m: re.Match) -> str:
            var = m.group(1) or m.group(2)
            if var in _ALLOWED_VARS:
                return os.getenv(var, "")
            log.debug("[HTTPHook] Env var $%s not in allowlist — skipping", var)
            return ""
        interpolated = _ENV_VAR_PATTERN.sub(_replace, value)
        out[name] = re.sub(r"[\r\n\x00]", "", interpolated)   # strip injection chars
    return out


# ─── CORE EXECUTOR ───────────────────────────────────────────────────────────

async def exec_http_hook(
    url:         str,
    payload:     dict,
    headers:     Optional[dict[str, str]] = None,
    timeout_s:   int = DEFAULT_TIMEOUT_S,
) -> dict:
    """
    POST payload as JSON to url.
    Returns {"ok": bool, "status_code": int|None, "body": str, "error": str|None}.

    Includes URL allowlist check + SSRF guard (same as Claude Code).
    """
    # 1. Allowlist check
    err = _check_allowed(url)
    if err:
        log.warning("[HTTPHook] %s", err)
        return {"ok": False, "status_code": None, "body": "", "error": err}

    # 2. SSRF guard
    err = _ssrf_check(url)
    if err:
        log.warning("[HTTPHook] %s", err)
        return {"ok": False, "status_code": None, "body": "", "error": err}

    # 3. Build headers
    base_headers: dict[str, str] = {"Content-Type": "application/json"}
    token = os.getenv("ARGOS_WEBHOOK_TOKEN")
    if token:
        base_headers["Authorization"] = f"Bearer {token}"
    if headers:
        base_headers.update(_interpolate_headers(headers))

    # 4. Fire POST
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=False) as client:
            r = await client.post(url, json=payload, headers=base_headers)
        ok = 200 <= r.status_code < 300
        log.debug("[HTTPHook] %s → %d (ok=%s)", url, r.status_code, ok)
        return {"ok": ok, "status_code": r.status_code, "body": r.text, "error": None}
    except httpx.TimeoutException:
        msg = f"HTTP hook timed out after {timeout_s}s"
        log.warning("[HTTPHook] %s → %s", url, msg)
        return {"ok": False, "status_code": None, "body": "", "error": msg}
    except Exception as exc:
        log.warning("[HTTPHook] %s → error: %s", url, exc)
        return {"ok": False, "status_code": None, "body": "", "error": str(exc)}


# ─── HOOK FACTORY ─────────────────────────────────────────────────────────────

def _build_webhook_payload(ctx: HookContext) -> dict:
    """Build the standardized payload sent to the webhook endpoint."""
    payload: dict = {
        "source":     "argos",
        "session_id": ctx.session_id,
    }
    if ctx.event:
        payload["event"] = {
            "id":          ctx.event.get("id"),
            "threat_type": ctx.event.get("threat_type"),
            "severity":    ctx.event.get("severity"),
            "source_ip":   ctx.event.get("source_ip"),
            "target_port": ctx.event.get("target_port"),
        }
    if ctx.decision:
        payload["decision"] = {
            "action":     ctx.decision.get("action"),
            "confidence": ctx.decision.get("confidence"),
            "reasoning":  ctx.decision.get("reasoning"),
        }
    payload["tool_call_count"] = ctx.tool_call_count
    payload["turn_duration_s"] = round(ctx.turn_duration_s, 2)
    return payload


def register_http_webhook_hook(
    url:           str,
    name:          str = "webhook",
    min_severity:  Optional[str] = None,
    min_confidence: float = 0.0,
    extra_headers: Optional[dict[str, str]] = None,
) -> None:
    """
    Register an HTTP webhook that fires after each threat analysis turn.

    Args:
        url:            Target URL (POST).
        name:           Hook name (allows multiple webhooks with different names).
        min_severity:   Only fire for "high"/"critical" if set.
        min_confidence: Only fire when decision confidence ≥ threshold.
        extra_headers:  Additional headers (env-var interpolation supported).
    """
    _SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_sev_rank   = _SEVERITY_RANK.get(min_severity or "", -1)

    async def _hook(ctx: HookContext) -> None:
        # Only fire when there's an actual threat decision
        if not ctx.event or not ctx.decision:
            return

        # Severity filter
        sev = (ctx.event.get("severity") or "").lower()
        if min_sev_rank >= 0 and _SEVERITY_RANK.get(sev, 0) < min_sev_rank:
            return

        # Confidence filter
        if ctx.decision.get("confidence", 0) < min_confidence:
            return

        payload = _build_webhook_payload(ctx)
        await exec_http_hook(url, payload, headers=extra_headers)

    register_hook(name, _hook)
    log.info("[HTTPHook] Registered webhook '%s' → %s", name, url)


# ─── CONVENIENCE: register from env ──────────────────────────────────────────

def register_env_webhook() -> bool:
    """
    Register a webhook from ARGOS_WEBHOOK_URL env var (if set).
    Returns True if registered.
    """
    url = os.getenv("ARGOS_WEBHOOK_URL", "").strip()
    if not url:
        return False
    min_sev  = os.getenv("ARGOS_WEBHOOK_MIN_SEVERITY", "").strip() or None
    min_conf = float(os.getenv("ARGOS_WEBHOOK_MIN_CONFIDENCE", "0"))
    register_http_webhook_hook(url, name="env_webhook", min_severity=min_sev, min_confidence=min_conf)
    return True
