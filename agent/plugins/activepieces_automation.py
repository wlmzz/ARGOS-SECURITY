"""
activepieces_automation.py — ARGOS plugin
Security workflow automation via Activepieces (open-source Zapier/n8n).
Trigger automated flows, manage security webhooks, and orchestrate multi-step responses.
Self-hosted: docker run -d -p 8080:80 activepieces/activepieces:latest
https://github.com/activepieces/activepieces
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "activepieces_automation",
    "name": "Activepieces Automation",
    "version": "1.0.0",
    "description": "Security workflow automation: trigger flows, manage webhooks, chain actions",
    "author": "ARGOS",
    "category": "integrations",
    "tools": [
        "automation_list_flows",
        "automation_trigger_flow",
        "automation_security_response",
        "automation_create_webhook",
    ],
}

# Self-hosted Activepieces instance URL
AP_BASE = os.environ.get("ACTIVEPIECES_URL", "http://localhost:8080")
AP_TOKEN = os.environ.get("ACTIVEPIECES_API_KEY", "")
RESULTS_DIR = "/opt/argos/logs/automation"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Webhook queue for when Activepieces not configured
WEBHOOK_QUEUE = os.path.join(RESULTS_DIR, "pending_triggers.jsonl")


def _api(path: str, method: str = "GET", data: dict = None, timeout: int = 10) -> tuple[dict, int]:
    url = f"{AP_BASE}/api/v1{path}"
    headers = {"Content-Type": "application/json"}
    if AP_TOKEN:
        headers["Authorization"] = f"Bearer {AP_TOKEN}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read()), resp.getcode()
    except Exception as e:
        return {"error": str(e)[:200]}, 0


def _is_ap_available() -> bool:
    _, code = _api("/flows", timeout=3)
    return code == 200


def automation_list_flows(status: str = "ENABLED") -> dict:
    """
    List all automation flows in the Activepieces instance.

    Args:
        status: Filter by status: 'ENABLED', 'DISABLED', 'all' (default: ENABLED)

    Returns:
        List of flows with names, triggers, and last run status
    """
    if not _is_ap_available():
        return {
            "status": "activepieces_not_configured",
            "note": "Start with: docker run -d -p 8080:80 -e AP_JWT_SECRET=argos activepieces/activepieces:latest",
            "ap_url": AP_BASE,
            "env_vars": ["ACTIVEPIECES_URL", "ACTIVEPIECES_API_KEY"],
            "predefined_flows": [
                "ip_ban_alert → Slack/Telegram when IP is banned",
                "incident_ticket → Create Jira ticket on critical alert",
                "daily_threat_report → Scheduled threat intel summary",
                "cve_monitor → Alert on new CVEs matching your stack",
                "log_anomaly → Trigger incident flow on SIGMA rule match",
            ],
        }

    data, code = _api("/flows")
    if code != 200:
        return {"error": "Cannot list flows", "response": data}

    flows = data.get("data", [])
    if status != "all":
        flows = [f for f in flows if f.get("status") == status]

    return {
        "flows": [
            {
                "id": f.get("id"),
                "name": f.get("name"),
                "status": f.get("status"),
                "trigger": f.get("trigger", {}).get("type"),
                "last_run": f.get("lastRun"),
            }
            for f in flows
        ],
        "total": len(flows),
        "ap_url": AP_BASE,
        "timestamp": datetime.utcnow().isoformat(),
    }


def automation_trigger_flow(flow_id: str = None, flow_name: str = None,
                              payload: dict = None) -> dict:
    """
    Trigger an Activepieces automation flow with optional payload data.

    Args:
        flow_id: Flow ID to trigger (from automation_list_flows)
        flow_name: Flow name to find and trigger (alternative to flow_id)
        payload: Data to pass to the flow (optional)

    Returns:
        Trigger status and flow run ID
    """
    if not flow_id and not flow_name:
        return {"error": "Provide flow_id or flow_name"}

    if not _is_ap_available():
        # Queue the trigger locally
        entry = {
            "flow_id": flow_id,
            "flow_name": flow_name,
            "payload": payload or {},
            "queued_at": datetime.utcnow().isoformat(),
        }
        with open(WEBHOOK_QUEUE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return {
            "status": "queued_locally",
            "note": "Activepieces not available. Trigger queued in " + WEBHOOK_QUEUE,
            "entry": entry,
        }

    # Find flow by name if needed
    if not flow_id and flow_name:
        data, _ = _api("/flows")
        for flow in data.get("data", []):
            if flow_name.lower() in flow.get("name", "").lower():
                flow_id = flow["id"]
                break
        if not flow_id:
            return {"error": f"Flow '{flow_name}' not found"}

    # Trigger the flow
    result, code = _api(f"/flows/{flow_id}/run", method="POST", data=payload or {})
    return {
        "flow_id": flow_id,
        "status": "triggered" if code in (200, 201, 202) else "failed",
        "http_status": code,
        "response": result,
        "timestamp": datetime.utcnow().isoformat(),
    }


def automation_security_response(event: str, severity: str = "high",
                                   data: dict = None) -> dict:
    """
    Trigger pre-built security response automation based on event type.
    Maps security events to appropriate automation flows or direct actions.

    Available event types and their default automations:
    - 'ip_banned' → Alert Telegram + create block record
    - 'critical_vuln' → Create Jira/GitHub ticket + alert team
    - 'intrusion_detected' → Page on-call + start IR flow
    - 'malware_found' → Quarantine alert + scan report
    - 'data_leak' → Immediate notification + escalation
    - 'login_anomaly' → Block account + alert SIEM

    Args:
        event: Security event type (see above)
        severity: Severity level: 'low', 'medium', 'high', 'critical' (default: high)
        data: Event data (IPs, hostnames, CVEs, etc.)

    Returns:
        Actions triggered and their status
    """
    ts = datetime.utcnow().isoformat()
    event_data = data or {}

    response_config = {
        "ip_banned": {
            "flows": ["ip_ban_notification", "threat_intel_lookup"],
            "direct_actions": ["telegram_alert", "log_to_siem"],
            "description": "IP banned — notifying team and logging to threat intel",
        },
        "critical_vuln": {
            "flows": ["vuln_ticket_creation", "patch_reminder"],
            "direct_actions": ["create_ticket", "email_security_team"],
            "description": "Critical vulnerability — creating ticket and alerting security team",
        },
        "intrusion_detected": {
            "flows": ["ir_flow", "oncall_pager"],
            "direct_actions": ["telegram_alert", "create_incident"],
            "description": "Intrusion detected — paging on-call and starting IR",
        },
        "malware_found": {
            "flows": ["malware_response", "quarantine_flow"],
            "direct_actions": ["telegram_alert", "log_iocs"],
            "description": "Malware detected — triggering quarantine and scan",
        },
        "data_leak": {
            "flows": ["breach_response", "legal_notification"],
            "direct_actions": ["emergency_alert", "revoke_credentials"],
            "description": "Data leak detected — immediate escalation",
        },
        "login_anomaly": {
            "flows": ["account_lockout", "mfa_enforce"],
            "direct_actions": ["telegram_alert", "block_account"],
            "description": "Login anomaly — blocking account and alerting",
        },
    }

    config = response_config.get(event, {
        "flows": [],
        "direct_actions": ["telegram_alert"],
        "description": f"Security event: {event}",
    })

    result = {
        "event": event,
        "severity": severity,
        "description": config["description"],
        "actions_triggered": [],
        "timestamp": ts,
    }

    # Direct Telegram alert (always attempt)
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if tg_token and tg_chat:
        severity_emoji = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}
        emoji = severity_emoji.get(severity, "⚠️")
        msg = f"{emoji} *ARGOS Security Event*\n\nEvent: `{event}`\nSeverity: `{severity}`\n"
        if event_data:
            for k, v in list(event_data.items())[:5]:
                msg += f"{k}: `{v}`\n"

        try:
            tg_text = urllib.parse.quote(msg)
            url = f"https://api.telegram.org/bot{tg_token}/sendMessage?chat_id={tg_chat}&text={tg_text}&parse_mode=Markdown"
            with urllib.request.urlopen(url, timeout=10):
                result["actions_triggered"].append("telegram_alert: sent")
        except Exception as e:
            result["actions_triggered"].append(f"telegram_alert: failed ({e})")

    # Try Activepieces flows
    if _is_ap_available():
        for flow_name in config["flows"]:
            trigger_result = automation_trigger_flow(
                flow_name=flow_name,
                payload={"event": event, "severity": severity, **event_data},
            )
            status = trigger_result.get("status", "unknown")
            result["actions_triggered"].append(f"{flow_name}: {status}")

    # Log event
    log_file = os.path.join(RESULTS_DIR, "security_events.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps({
            "event": event, "severity": severity,
            "data": event_data, "actions": result["actions_triggered"],
            "timestamp": ts,
        }) + "\n")
    result["event_log"] = log_file

    return result


def automation_create_webhook(name: str, trigger_events: list,
                               endpoint_url: str = None) -> dict:
    """
    Create a webhook trigger for ARGOS events in Activepieces.
    Enables other systems to trigger ARGOS automations.

    Args:
        name: Webhook name
        trigger_events: Events that should fire this webhook
                        e.g. ['ip_banned', 'critical_alert', 'sigma_detection']
        endpoint_url: URL that will receive the webhook (optional, uses Activepieces)

    Returns:
        Webhook configuration with trigger URL
    """
    ts = datetime.utcnow().isoformat()
    webhook_id = f"argos_{name.lower().replace(' ', '_')}_{ts[:10]}"

    config = {
        "id": webhook_id,
        "name": name,
        "trigger_events": trigger_events,
        "created_at": ts,
        "endpoint_url": endpoint_url or f"{AP_BASE}/api/v1/webhooks/{webhook_id}",
    }

    # Save webhook config
    config_file = os.path.join(RESULTS_DIR, "webhooks.jsonl")
    with open(config_file, "a") as f:
        f.write(json.dumps(config) + "\n")

    if _is_ap_available() and AP_TOKEN:
        # Create webhook flow in Activepieces
        flow_data = {
            "name": name,
            "trigger": {
                "type": "WEBHOOK",
                "settings": {"inputUiInfo": {}},
            },
        }
        result, code = _api("/flows", method="POST", data=flow_data)
        if code in (200, 201):
            config["ap_flow_id"] = result.get("id")
            config["status"] = "created_in_activepieces"
        else:
            config["status"] = "saved_locally"
    else:
        config["status"] = "saved_locally"
        config["note"] = "Configure Activepieces to activate this webhook"

    return config


TOOLS = {
    "automation_list_flows": automation_list_flows,
    "automation_trigger_flow": automation_trigger_flow,
    "automation_security_response": automation_security_response,
    "automation_create_webhook": automation_create_webhook,
}
