"""
ARGOS Plugin — Wazuh SIEM Integration
Communicates with the Wazuh REST API using JWT authentication.
Only stdlib + subprocess. Timeout = 120 s per request.
"""

import json
import os
import urllib.request
import urllib.error
import urllib.parse
import base64
import ssl
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "wazuh-siem",
    "name": "Wazuh SIEM",
    "description": (
        "Full integration with Wazuh SIEM: alerts, agents, vulnerabilities, "
        "Security Configuration Assessment, and real-time threat hunting."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Configuration (read from environment at import time)
# ---------------------------------------------------------------------------
_HOST = os.environ.get("WAZUH_HOST", "localhost")
_PORT = os.environ.get("WAZUH_PORT", "55000")
_USER = os.environ.get("WAZUH_USER", "wazuh-wui")
_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _base_url() -> str:
    return "https://{}:{}".format(_HOST, _PORT)


def _insecure_context() -> ssl.SSLContext:
    """Return an SSL context that skips certificate verification (self-signed certs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get_jwt_token() -> str:
    """
    Authenticate against POST /security/user/authenticate and return a JWT token.
    Raises RuntimeError on failure.
    """
    if not _PASSWORD:
        raise RuntimeError(
            "WAZUH_PASSWORD environment variable is not set. "
            "Set it before using the Wazuh plugin."
        )
    url = "{}/security/user/authenticate".format(_base_url())
    credentials = "{}:{}".format(_USER, _PASSWORD)
    encoded = base64.b64encode(credentials.encode()).decode()
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Authorization": "Basic {}".format(encoded),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=_insecure_context(), timeout=30) as resp:
            body = json.loads(resp.read().decode())
            token = body.get("data", {}).get("token", "")
            if not token:
                raise RuntimeError("JWT token not found in authentication response.")
            return token
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            "Wazuh auth failed — HTTP {}: {}".format(exc.code, exc.reason)
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Cannot reach Wazuh at {} — {}".format(_base_url(), exc.reason)
        ) from exc


def _api_get(path: str, params: dict | None = None, timeout: int = 120) -> dict:
    """Perform an authenticated GET request to the Wazuh API."""
    token = _get_jwt_token()
    url = "{}{}".format(_base_url(), path)
    if params:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "", 0)})
        if query:
            url = "{}?{}".format(url, query)
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=_insecure_context(), timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": "HTTP {} — {}".format(exc.code, body)}
    except urllib.error.URLError as exc:
        return {"error": "Connection error — {}".format(exc.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _api_post(path: str, payload: dict, timeout: int = 120) -> dict:
    """Perform an authenticated POST request to the Wazuh API."""
    token = _get_jwt_token()
    url = "{}{}".format(_base_url(), path)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=_insecure_context(), timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": "HTTP {} — {}".format(exc.code, body)}
    except urllib.error.URLError as exc:
        return {"error": "Connection error — {}".format(exc.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _time_range_to_offset(time_range: str) -> str:
    """Convert a human time range string to a Wazuh API 'older_than' / timestamp."""
    _MAP = {"1h": "1h", "6h": "6h", "24h": "24h", "7d": "7d"}
    return _MAP.get(time_range, "1h")


def _wazuh_unavailable_error() -> dict:
    return {
        "error": (
            "Cannot connect to Wazuh. "
            "Ensure WAZUH_HOST, WAZUH_PORT, WAZUH_USER, and WAZUH_PASSWORD "
            "environment variables are set and Wazuh is running."
        )
    }


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def wazuh_status() -> dict:
    """
    Retrieve the Wazuh manager daemon status.
    Calls GET /manager/status and returns daemon states.
    """
    try:
        resp = _api_get("/manager/status")
    except RuntimeError as exc:
        return {"error": str(exc)}

    if "error" in resp:
        return resp

    data = resp.get("data", {})
    affected = data.get("affected_items", [{}])
    statuses = affected[0] if affected else {}

    # Summarise which daemons are running / stopped
    running = [d for d, s in statuses.items() if s == "running"]
    stopped = [d for d, s in statuses.items() if s != "running"]

    return {
        "manager": _HOST,
        "overall": "healthy" if not stopped else "degraded",
        "daemons": statuses,
        "running": running,
        "stopped": stopped,
        "raw": data,
    }


def wazuh_alerts(
    limit: int = 100,
    level: int = 0,
    agent_id: str = "",
    rule_id: str = "",
    time_range: str = "1h",
) -> dict:
    """
    Retrieve Wazuh alerts with optional filters.

    Parameters
    ----------
    limit : int
        Maximum number of alerts to return (default 100).
    level : int
        Minimum rule level (0 = no filter, 1–15).
    agent_id : str
        Filter by specific agent ID (e.g. "001").
    rule_id : str
        Filter by specific rule ID.
    time_range : str
        Time window: "1h", "6h", "24h", "7d".
    """
    params: dict[str, Any] = {"limit": limit, "sort": "-timestamp"}
    if level > 0:
        params["level"] = "{}:15".format(level)
    if agent_id:
        params["agents_list"] = agent_id
    if rule_id:
        params["rule.id"] = rule_id

    try:
        resp = _api_get("/alerts", params=params)
    except RuntimeError as exc:
        return {"error": str(exc)}

    if "error" in resp:
        return resp

    data = resp.get("data", {})
    items = data.get("affected_items", [])

    by_level: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for alert in items:
        lvl = str(alert.get("rule", {}).get("level", "unknown"))
        rid = str(alert.get("rule", {}).get("id", "unknown"))
        by_level[lvl] = by_level.get(lvl, 0) + 1
        by_rule[rid] = by_rule.get(rid, 0) + 1

    return {
        "alerts": items,
        "total": data.get("total_affected_items", len(items)),
        "returned": len(items),
        "time_range": time_range,
        "filters": {
            "level": level,
            "agent_id": agent_id,
            "rule_id": rule_id,
        },
        "by_level": by_level,
        "by_rule": by_rule,
    }


def wazuh_agents() -> dict:
    """
    List all Wazuh agents with their connection status, OS, and last keep-alive.
    Calls GET /agents.
    """
    try:
        resp = _api_get("/agents", params={"limit": 500, "sort": "+name"})
    except RuntimeError as exc:
        return {"error": str(exc)}

    if "error" in resp:
        return resp

    data = resp.get("data", {})
    items = data.get("affected_items", [])

    by_status: dict[str, list] = {}
    for agent in items:
        status = agent.get("status", "unknown")
        by_status.setdefault(status, []).append(agent.get("name", ""))

    return {
        "agents": items,
        "total": data.get("total_affected_items", len(items)),
        "by_status": by_status,
        "connected": len(by_status.get("active", [])),
        "disconnected": len(by_status.get("disconnected", [])),
        "never_connected": len(by_status.get("never_connected", [])),
    }


def wazuh_vulnerabilities(agent_id: str = "all", severity: str = "critical") -> dict:
    """
    Retrieve CVE vulnerabilities detected on one or all agents.

    Parameters
    ----------
    agent_id : str
        Agent ID (e.g. "001") or "all" for every agent.
    severity : str
        Minimum severity to include: critical, high, medium, low.
    """
    _SEV_ORDER = ["critical", "high", "medium", "low", "none"]
    severity = severity.lower()
    if severity not in _SEV_ORDER:
        severity = "critical"

    try:
        if agent_id == "all":
            agents_resp = _api_get("/agents", params={"status": "active", "limit": 500})
            agent_ids = [
                a["id"]
                for a in agents_resp.get("data", {}).get("affected_items", [])
                if a.get("id") != "000"
            ]
        else:
            agent_ids = [agent_id]
    except RuntimeError as exc:
        return {"error": str(exc)}

    all_vulns: list[dict] = []
    by_severity: dict[str, int] = {}
    by_cve: dict[str, int] = {}
    errors: list[str] = []

    for aid in agent_ids:
        try:
            resp = _api_get(
                "/vulnerability/{}".format(aid),
                params={"limit": 500, "severity": severity},
            )
        except RuntimeError as exc:
            errors.append(str(exc))
            continue

        if "error" in resp:
            errors.append("Agent {}: {}".format(aid, resp["error"]))
            continue

        items = resp.get("data", {}).get("affected_items", [])
        for v in items:
            sev = v.get("severity", "unknown").lower()
            cve = v.get("cve", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_cve[cve] = by_cve.get(cve, 0) + 1
            v["_agent_id"] = aid
        all_vulns.extend(items)

    # Sort by severity order
    all_vulns.sort(key=lambda v: _SEV_ORDER.index(v.get("severity", "none").lower())
                   if v.get("severity", "none").lower() in _SEV_ORDER else 99)

    return {
        "vulnerabilities": all_vulns,
        "total": len(all_vulns),
        "severity_filter": severity,
        "agents_queried": len(agent_ids),
        "by_severity": by_severity,
        "by_cve": dict(sorted(by_cve.items(), key=lambda x: x[1], reverse=True)[:20]),
        "errors": errors,
    }


def wazuh_sca(agent_id: str) -> dict:
    """
    Retrieve Security Configuration Assessment results for an agent.
    Calls GET /sca/{agent_id}.

    Parameters
    ----------
    agent_id : str
        Agent ID (e.g. "001").
    """
    try:
        resp = _api_get("/sca/{}".format(agent_id))
    except RuntimeError as exc:
        return {"error": str(exc)}

    if "error" in resp:
        return resp

    data = resp.get("data", {})
    items = data.get("affected_items", [])

    total_pass = sum(i.get("pass", 0) for i in items)
    total_fail = sum(i.get("fail", 0) for i in items)
    total_na = sum(i.get("invalid", 0) for i in items)
    total_checks = total_pass + total_fail + total_na
    score_pct = round((total_pass / total_checks * 100), 2) if total_checks > 0 else 0

    policies = []
    for item in items:
        policies.append({
            "policy_id": item.get("policy_id", ""),
            "name": item.get("name", ""),
            "description": item.get("description", ""),
            "pass": item.get("pass", 0),
            "fail": item.get("fail", 0),
            "invalid": item.get("invalid", 0),
            "score": item.get("score", 0),
            "end_scan": item.get("end_scan", ""),
        })

    return {
        "agent_id": agent_id,
        "policies": policies,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total_na": total_na,
        "score_percent": score_pct,
        "grade": (
            "A" if score_pct >= 90 else
            "B" if score_pct >= 75 else
            "C" if score_pct >= 50 else
            "D" if score_pct >= 25 else "F"
        ),
    }


def wazuh_search_alerts(query: str, limit: int = 50) -> dict:
    """
    Search Wazuh alerts by keyword/phrase using the full-text query parameter.

    Parameters
    ----------
    query : str
        Search string (e.g. "sshd failed", "sudo", "CVE-2024").
    limit : int
        Maximum number of matching alerts to return (default 50).
    """
    params: dict[str, Any] = {
        "limit": min(limit, 500),
        "q": "rule.description~{}".format(query),
        "sort": "-timestamp",
    }
    try:
        resp = _api_get("/alerts", params=params)
    except RuntimeError as exc:
        return {"error": str(exc)}

    if "error" in resp:
        # Try alternate search via 'search' param if 'q' is not supported
        try:
            params2: dict[str, Any] = {
                "limit": min(limit, 500),
                "search": query,
                "sort": "-timestamp",
            }
            resp = _api_get("/alerts", params=params2)
        except RuntimeError as exc2:
            return {"error": str(exc2)}

    data = resp.get("data", {})
    items = data.get("affected_items", [])

    # Secondary client-side filter for accuracy
    filtered = [
        a for a in items
        if query.lower() in json.dumps(a).lower()
    ]

    by_agent: dict[str, int] = {}
    for alert in filtered:
        agent_name = alert.get("agent", {}).get("name", "unknown")
        by_agent[agent_name] = by_agent.get(agent_name, 0) + 1

    return {
        "query": query,
        "alerts": filtered,
        "total": len(filtered),
        "api_total": data.get("total_affected_items", 0),
        "by_agent": by_agent,
    }


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------
TOOLS = {
    "wazuh_status": {
        "fn": wazuh_status,
        "description": (
            "Check the Wazuh manager status. Returns daemon states "
            "(running/stopped) and overall health."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "wazuh_alerts": {
        "fn": wazuh_alerts,
        "description": (
            "Retrieve Wazuh SIEM alerts with optional filters by severity level, "
            "agent, rule ID, and time range. Returns alerts grouped by level and rule."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum alerts to return (default 100).",
                    "default": 100,
                },
                "level": {
                    "type": "integer",
                    "description": "Minimum rule level 0–15 (0 = no filter).",
                    "default": 0,
                },
                "agent_id": {
                    "type": "string",
                    "description": "Filter by agent ID (e.g. '001'). Empty = all agents.",
                    "default": "",
                },
                "rule_id": {
                    "type": "string",
                    "description": "Filter by specific Wazuh rule ID.",
                    "default": "",
                },
                "time_range": {
                    "type": "string",
                    "description": "Time window: '1h', '6h', '24h', '7d'.",
                    "default": "1h",
                    "enum": ["1h", "6h", "24h", "7d"],
                },
            },
            "required": [],
        },
    },
    "wazuh_agents": {
        "fn": wazuh_agents,
        "description": (
            "List all registered Wazuh agents with their connection status, "
            "OS information, IP address, and last keep-alive timestamp."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "wazuh_vulnerabilities": {
        "fn": wazuh_vulnerabilities,
        "description": (
            "Retrieve CVE vulnerabilities detected by Wazuh on one or all agents. "
            "Returns findings grouped by severity and CVE identifier."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent ID (e.g. '001') or 'all' for every agent.",
                    "default": "all",
                },
                "severity": {
                    "type": "string",
                    "description": "Minimum severity: critical, high, medium, low.",
                    "default": "critical",
                    "enum": ["critical", "high", "medium", "low"],
                },
            },
            "required": [],
        },
    },
    "wazuh_sca": {
        "fn": wazuh_sca,
        "description": (
            "Retrieve Security Configuration Assessment (SCA) results for a Wazuh agent. "
            "Returns pass/fail counts per policy and an overall compliance grade."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent ID to assess (e.g. '001').",
                },
            },
            "required": ["agent_id"],
        },
    },
    "wazuh_search_alerts": {
        "fn": wazuh_search_alerts,
        "description": (
            "Search Wazuh alerts by keyword or phrase (e.g. 'sshd failed', 'CVE-2024'). "
            "Returns matching alerts grouped by agent."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search keyword or phrase to match against alert descriptions.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum alerts to return (default 50).",
                    "default": 50,
                },
            },
            "required": ["query"],
        },
    },
}
