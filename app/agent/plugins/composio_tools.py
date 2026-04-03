"""
composio_tools.py — ARGOS plugin
Connect ARGOS to 250+ external services via Composio.
Enables ARGOS agents to act on findings: create JIRA tickets, send Slack alerts,
open GitHub issues, trigger webhooks, and more.
https://github.com/ComposioHQ/composio
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "composio_tools",
    "name": "Composio Integrations",
    "version": "1.0.0",
    "description": "Connect ARGOS to 250+ services: Slack, JIRA, GitHub, PagerDuty, email",
    "author": "ARGOS",
    "category": "integrations",
    "tools": [
        "composio_list_apps",
        "composio_send_alert",
        "composio_create_ticket",
        "composio_trigger_action",
        "composio_webhook",
    ],
}

RESULTS_DIR = "/opt/argos/logs/composio"
os.makedirs(RESULTS_DIR, exist_ok=True)

COMPOSIO_API_KEY = os.environ.get("COMPOSIO_API_KEY", "")


def _ensure_composio() -> tuple[bool, str]:
    try:
        import composio
        return True, ""
    except ImportError:
        import subprocess
        rc, _, err = subprocess.run(
            ["pip3", "install", "composio-core", "--break-system-packages", "-q"],
            capture_output=True, text=True, timeout=120,
        ).returncode, "", ""
        try:
            import composio
            return True, ""
        except ImportError:
            return False, "pip3 install composio-core && composio login"


def _fetch_json(url: str, method: str = "GET", data: dict = None,
                 headers: dict = None, timeout: int = 15) -> tuple[dict, int]:
    req_headers = {"Content-Type": "application/json"}
    if COMPOSIO_API_KEY:
        req_headers["x-api-key"] = COMPOSIO_API_KEY
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read()), resp.getcode()
    except Exception as e:
        return {"error": str(e)}, 0


def composio_list_apps(category: str = "security") -> dict:
    """
    List available Composio app integrations.
    Shows all connectable services organized by category.

    Args:
        category: Filter by category: 'security', 'communication', 'ticketing',
                  'cloud', 'devops', 'all' (default: security)

    Returns:
        Available integrations with connection status
    """
    # Built-in registry of security-relevant apps
    app_registry = {
        "security": [
            {"name": "VirusTotal", "id": "virustotal", "desc": "File/URL/IP scanning"},
            {"name": "Shodan", "id": "shodan", "desc": "Internet device search"},
            {"name": "Have I Been Pwned", "id": "hibp", "desc": "Breach checking"},
            {"name": "AbuseIPDB", "id": "abuseipdb", "desc": "IP reputation"},
            {"name": "AlienVault OTX", "id": "otx", "desc": "Threat intelligence"},
        ],
        "communication": [
            {"name": "Slack", "id": "slack", "desc": "Team messaging and alerts"},
            {"name": "Discord", "id": "discord", "desc": "Server notifications"},
            {"name": "Telegram", "id": "telegram", "desc": "Bot messaging"},
            {"name": "Microsoft Teams", "id": "teams", "desc": "Enterprise messaging"},
            {"name": "Email/SMTP", "id": "gmail", "desc": "Email notifications"},
        ],
        "ticketing": [
            {"name": "Jira", "id": "jira", "desc": "Issue tracking"},
            {"name": "GitHub", "id": "github", "desc": "Issues and PRs"},
            {"name": "GitLab", "id": "gitlab", "desc": "Issues and MRs"},
            {"name": "ServiceNow", "id": "servicenow", "desc": "ITSM platform"},
            {"name": "Linear", "id": "linear", "desc": "Project management"},
            {"name": "Notion", "id": "notion", "desc": "Documentation"},
        ],
        "cloud": [
            {"name": "AWS", "id": "aws", "desc": "Amazon Web Services"},
            {"name": "GCP", "id": "gcp", "desc": "Google Cloud Platform"},
            {"name": "Azure", "id": "azure", "desc": "Microsoft Azure"},
            {"name": "Cloudflare", "id": "cloudflare", "desc": "CDN and security"},
            {"name": "Vercel", "id": "vercel", "desc": "Deployment platform"},
        ],
        "devops": [
            {"name": "GitHub Actions", "id": "github_actions", "desc": "CI/CD workflows"},
            {"name": "PagerDuty", "id": "pagerduty", "desc": "On-call alerting"},
            {"name": "Grafana", "id": "grafana", "desc": "Monitoring dashboards"},
            {"name": "Datadog", "id": "datadog", "desc": "Observability"},
            {"name": "OpsGenie", "id": "opsgenie", "desc": "Alert management"},
        ],
    }

    ok, err = _ensure_composio()

    if ok and COMPOSIO_API_KEY:
        # Try live API
        data, code = _fetch_json("https://backend.composio.dev/api/v1/apps")
        if code == 200 and "items" in data:
            apps = data["items"]
            if category != "all":
                apps = [a for a in apps if category.lower() in
                        str(a.get("categories", [])).lower()]
            return {
                "source": "composio_api",
                "category": category,
                "apps": apps[:50],
                "total": len(apps),
            }

    # Return registry
    if category == "all":
        all_apps = []
        for cat_apps in app_registry.values():
            all_apps.extend(cat_apps)
        return {"source": "local_registry", "category": "all",
                "apps": all_apps, "total": len(all_apps)}

    apps = app_registry.get(category, app_registry["security"])
    return {
        "source": "local_registry",
        "category": category,
        "apps": apps,
        "total": len(apps),
        "note": "Set COMPOSIO_API_KEY for live 250+ app catalog",
    }


def composio_send_alert(message: str, severity: str = "high",
                         channels: list = None, title: str = None) -> dict:
    """
    Send a security alert to configured notification channels.
    Supports Slack, Discord, Telegram, email, and PagerDuty via Composio.
    Falls back to ARGOS Telegram bot if Composio not configured.

    Args:
        message: Alert message content (markdown supported)
        severity: 'info', 'low', 'medium', 'high', 'critical' (default: high)
        channels: List of channels to alert: ['slack', 'telegram', 'email'] (default: all configured)
        title: Alert title (default: auto-generated from severity)

    Returns:
        Delivery status for each channel
    """
    auto_title = title or f"[{severity.upper()}] ARGOS Security Alert"

    severity_emoji = {
        "critical": "🚨", "high": "⚠️", "medium": "🔶",
        "low": "🔷", "info": "ℹ️",
    }
    emoji = severity_emoji.get(severity, "⚠️")
    formatted_message = f"{emoji} **{auto_title}**\n\n{message}"

    result = {
        "title": auto_title,
        "severity": severity,
        "channels_attempted": [],
        "channels_sent": [],
        "timestamp": datetime.utcnow().isoformat(),
    }

    channels = channels or ["telegram", "slack", "email"]

    # Try Composio SDK
    ok, err = _ensure_composio()
    if ok and COMPOSIO_API_KEY:
        try:
            from composio import Composio, Action
            client = Composio(api_key=COMPOSIO_API_KEY)

            if "slack" in channels:
                result["channels_attempted"].append("slack")
                slack_channel = os.environ.get("SLACK_CHANNEL", "#security-alerts")
                try:
                    client.actions.execute(
                        action=Action.SLACK_SENDS_A_MESSAGE_TO_A_SLACK_CHANNEL,
                        params={"channel": slack_channel, "text": formatted_message},
                    )
                    result["channels_sent"].append("slack")
                except Exception as e:
                    result[f"slack_error"] = str(e)[:200]

            if "github" in channels:
                result["channels_attempted"].append("github")
                repo = os.environ.get("GITHUB_SECURITY_REPO", "")
                if repo:
                    try:
                        client.actions.execute(
                            action=Action.GITHUB_CREATE_AN_ISSUE,
                            params={
                                "owner": repo.split("/")[0],
                                "repo": repo.split("/")[1],
                                "title": auto_title,
                                "body": message,
                                "labels": ["security", severity],
                            },
                        )
                        result["channels_sent"].append("github")
                    except Exception as e:
                        result["github_error"] = str(e)[:200]

        except Exception as e:
            result["composio_error"] = str(e)[:300]

    # Telegram fallback (ARGOS native)
    if "telegram" in channels:
        result["channels_attempted"].append("telegram")
        tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        if tg_token and tg_chat:
            try:
                tg_text = urllib.parse.quote(formatted_message)
                url = f"https://api.telegram.org/bot{tg_token}/sendMessage?chat_id={tg_chat}&text={tg_text}&parse_mode=Markdown"
                with urllib.request.urlopen(url, timeout=10) as resp:
                    if resp.getcode() == 200:
                        result["channels_sent"].append("telegram")
            except Exception as e:
                result["telegram_error"] = str(e)[:200]

    # Log alert locally
    log_file = os.path.join(RESULTS_DIR, "alerts.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps({
            "title": auto_title, "severity": severity,
            "message": message, "sent_to": result["channels_sent"],
            "timestamp": result["timestamp"],
        }) + "\n")
    result["logged_to"] = log_file

    return result


def composio_create_ticket(title: str, description: str,
                            platform: str = "github", severity: str = "high",
                            labels: list = None) -> dict:
    """
    Create a security incident ticket in project management systems.
    Supports GitHub Issues, JIRA, GitLab, Linear, Notion.

    Args:
        title: Ticket title
        description: Full ticket description (markdown)
        platform: 'github', 'jira', 'gitlab', 'linear', 'notion' (default: github)
        severity: Severity level for labeling (default: high)
        labels: Additional labels to apply

    Returns:
        Created ticket URL and ID
    """
    all_labels = labels or []
    all_labels = list(set(all_labels + ["security", severity, "argos"]))

    result = {
        "title": title,
        "platform": platform,
        "severity": severity,
        "labels": all_labels,
        "timestamp": datetime.utcnow().isoformat(),
    }

    ok, err = _ensure_composio()
    if ok and COMPOSIO_API_KEY:
        try:
            from composio import Composio, Action
            client = Composio(api_key=COMPOSIO_API_KEY)

            if platform == "github":
                owner = os.environ.get("GITHUB_OWNER", "")
                repo = os.environ.get("GITHUB_REPO", "")
                if owner and repo:
                    response = client.actions.execute(
                        action=Action.GITHUB_CREATE_AN_ISSUE,
                        params={
                            "owner": owner,
                            "repo": repo,
                            "title": title,
                            "body": description,
                            "labels": all_labels,
                        },
                    )
                    result["ticket_url"] = response.get("html_url", "")
                    result["ticket_id"] = response.get("number", "")
                    result["status"] = "created"
                    return result

            elif platform == "jira":
                project = os.environ.get("JIRA_PROJECT", "SEC")
                response = client.actions.execute(
                    action=Action.JIRA_CREATE_AN_ISSUE,
                    params={
                        "project": {"key": project},
                        "summary": title,
                        "description": description,
                        "issuetype": {"name": "Bug"},
                        "priority": {"name": severity.capitalize()},
                    },
                )
                result["ticket_id"] = response.get("key", "")
                result["status"] = "created"
                return result

        except Exception as e:
            result["composio_error"] = str(e)[:300]

    # Fallback: log locally with instructions
    log_file = os.path.join(RESULTS_DIR, "pending_tickets.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps({
            "title": title, "description": description,
            "platform": platform, "labels": all_labels,
            "timestamp": result["timestamp"],
        }) + "\n")

    result["status"] = "logged_locally"
    result["local_file"] = log_file
    result["note"] = f"Set COMPOSIO_API_KEY to auto-create tickets. Saved locally."

    if platform == "github":
        owner = os.environ.get("GITHUB_OWNER", "")
        repo = os.environ.get("GITHUB_REPO", "")
        if owner and repo:
            result["manual_url"] = f"https://github.com/{owner}/{repo}/issues/new"

    return result


def composio_trigger_action(app: str, action: str, params: dict = None) -> dict:
    """
    Trigger any Composio action on any connected app.
    Full access to 250+ integrations with 1000+ actions.

    Args:
        app: App name (e.g. 'slack', 'github', 'jira', 'pagerduty', 'datadog')
        action: Action to perform (e.g. 'send_message', 'create_issue', 'trigger_incident')
        params: Action parameters (dict)

    Returns:
        Action execution result

    Examples:
        composio_trigger_action("pagerduty", "create_incident", {"title": "ARGOS Alert", "severity": "critical"})
        composio_trigger_action("datadog", "post_event", {"title": "Threat Detected", "text": "..."})
    """
    if not COMPOSIO_API_KEY:
        return {
            "error": "COMPOSIO_API_KEY not set",
            "setup": "1. pip3 install composio-core  2. composio login  3. composio add " + app,
            "app": app,
            "action": action,
        }

    ok, err = _ensure_composio()
    if not ok:
        return {"error": err, "app": app, "action": action}

    try:
        from composio import Composio
        client = Composio(api_key=COMPOSIO_API_KEY)

        # Build action enum name
        action_name = f"{app.upper()}_{action.upper().replace('-', '_')}"

        response = client.actions.execute(
            action=action_name,
            params=params or {},
        )

        return {
            "app": app,
            "action": action,
            "status": "executed",
            "response": response,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        return {
            "app": app,
            "action": action,
            "error": str(e)[:500],
            "timestamp": datetime.utcnow().isoformat(),
        }


def composio_webhook(event_type: str, payload: dict,
                      webhook_url: str = None) -> dict:
    """
    Send a security event to a webhook endpoint.
    Useful for integrating ARGOS with SIEM, SOAR, or custom automation platforms.

    Args:
        event_type: Event type (e.g. 'threat_detected', 'ip_banned', 'incident_created')
        payload: Event data to send
        webhook_url: Webhook URL (uses env ARGOS_WEBHOOK_URL if not provided)

    Returns:
        Delivery status and response
    """
    url = webhook_url or os.environ.get("ARGOS_WEBHOOK_URL", "")

    event = {
        "source": "argos",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "payload": payload,
    }

    if not url:
        log_file = os.path.join(RESULTS_DIR, "webhook_queue.jsonl")
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")
        return {
            "status": "queued_locally",
            "event_type": event_type,
            "log_file": log_file,
            "note": "Set ARGOS_WEBHOOK_URL to enable live webhook delivery",
        }

    body = json.dumps(event).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ARGOS-Security-Platform/1.0",
            "X-ARGOS-Event": event_type,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status_code = resp.getcode()
            response_body = resp.read().decode("utf-8", errors="ignore")[:500]
        return {
            "status": "delivered",
            "event_type": event_type,
            "webhook_url": url,
            "http_status": status_code,
            "response": response_body,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "status": "failed",
            "event_type": event_type,
            "error": str(e)[:300],
            "timestamp": datetime.utcnow().isoformat(),
        }


TOOLS = {
    "composio_list_apps": composio_list_apps,
    "composio_send_alert": composio_send_alert,
    "composio_create_ticket": composio_create_ticket,
    "composio_trigger_action": composio_trigger_action,
    "composio_webhook": composio_webhook,
}
