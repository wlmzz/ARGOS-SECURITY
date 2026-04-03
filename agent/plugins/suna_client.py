"""
suna_client.py — ARGOS plugin
REST API client for Kortix Suna: open-source generalist AI agent.
Suna uses computer use, browser automation, file management, and web search.
Self-hosted: docker compose up -d (backend :8000, frontend :3000)
https://github.com/kortix-ai/suna
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "suna_client",
    "name": "Suna AI Agent",
    "version": "1.0.0",
    "description": "Suna generalist agent: browser automation, file ops, web research, code execution",
    "author": "ARGOS",
    "category": "ai_agents",
    "tools": [
        "suna_run_task",
        "suna_web_research",
        "suna_security_scan",
        "suna_status",
    ],
}

RESULTS_DIR = "/opt/argos/logs/suna"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Suna backend URL
SUNA_BASE = os.environ.get("SUNA_URL", "http://localhost:8000")
SUNA_API_KEY = os.environ.get("SUNA_API_KEY", "")


def _api(path: str, method: str = "GET", data: dict = None, timeout: int = 15) -> tuple[dict, int]:
    url = f"{SUNA_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if SUNA_API_KEY:
        headers["Authorization"] = f"Bearer {SUNA_API_KEY}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read()), resp.getcode()
    except Exception as e:
        return {"error": str(e)[:200]}, 0


def _is_suna_up() -> bool:
    for path in ["/health", "/api/health", "/api/v1/health", "/"]:
        _, code = _api(path, timeout=3)
        if code == 200:
            return True
    return False


def _poll_task(task_id: str, max_wait: int = 300) -> dict:
    """Poll Suna task endpoint until completion."""
    import time
    start = time.time()
    while time.time() - start < max_wait:
        data, code = _api(f"/api/tasks/{task_id}")
        if code != 200:
            return {"error": f"Poll failed (HTTP {code})", "task_id": task_id}

        status = data.get("status", "")
        if status in ("completed", "done", "finished", "success"):
            return {"output": data.get("result") or data.get("output") or str(data),
                    "success": True, "task_id": task_id}
        if status in ("failed", "error"):
            return {"error": data.get("error", "Task failed"),
                    "success": False, "task_id": task_id}
        time.sleep(3)

    return {"error": f"Timed out waiting for task {task_id}", "success": False, "task_id": task_id}


def suna_status() -> dict:
    """
    Check Suna server status and configuration.

    Returns:
        Server status and setup instructions if not running
    """
    if not _is_suna_up():
        return {
            "status": "not_running",
            "suna_url": SUNA_BASE,
            "setup": [
                "git clone https://github.com/kortix-ai/suna",
                "cd suna && cp .env.example .env",
                "# Edit .env: set LLM provider (can use local Seneca-32B)",
                "docker compose up -d",
                "# Backend: localhost:8000, Frontend: localhost:3000",
            ],
            "env_vars": ["SUNA_URL", "SUNA_API_KEY"],
        }

    data, _ = _api("/health")
    return {
        "status": "running",
        "suna_url": SUNA_BASE,
        "health": data,
        "timestamp": datetime.utcnow().isoformat(),
    }


def suna_run_task(task: str, agent_type: str = "default",
                   save_output: bool = True) -> dict:
    """
    Run a task using the Suna generalist AI agent.
    Suna can browse the web, execute code, manage files, and use computer tools autonomously.

    Args:
        task: Natural language task description
        agent_type: Agent type hint: 'default', 'research', 'code', 'browser' (default: default)
        save_output: Save results to /opt/argos/logs/suna/ (default: True)

    Returns:
        Task result with agent output and execution trace
    """
    if not task or len(task.strip()) < 5:
        return {"error": "Task too short"}

    if not _is_suna_up():
        return {
            "status": "suna_not_configured",
            "task": task,
            "note": f"Suna not available at {SUNA_BASE}",
            "setup": "See suna_status() for setup instructions",
        }

    payload = {
        "task": task,
        "agent_type": agent_type,
    }

    # Try async task submission
    data, code = _api("/api/tasks", method="POST", data=payload)
    if code not in (200, 201, 202):
        # Try sync endpoint
        data, code = _api("/api/run", method="POST", data=payload, timeout=120)
        if code not in (200, 201, 202):
            return {"error": f"Suna API error (HTTP {code})", "response": data}

        result = {
            "output": data.get("result") or data.get("output") or str(data),
            "success": True,
        }
    else:
        task_id = data.get("task_id") or data.get("id")
        if task_id:
            result = _poll_task(task_id)
        else:
            result = {"output": str(data), "success": True}

    if result.get("success") and save_output:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(RESULTS_DIR, f"task_{ts}.txt")
        with open(outfile, "w") as f:
            f.write(f"Task: {task}\n\n{result.get('output', '')}")
        result["output_file"] = outfile

    result["task"] = task
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def suna_web_research(topic: str, depth: str = "standard",
                       structured_output: bool = True) -> dict:
    """
    Use Suna to research a topic via web browsing and search.
    Suna can access live web content, follow links, and synthesize information.

    Args:
        topic: Research topic (e.g. 'recent zero-days in Apache HTTP Server')
        depth: 'quick' (1-2 sources), 'standard' (5+ sources), 'deep' (comprehensive)
        structured_output: Request structured Markdown report (default: True)

    Returns:
        Research findings with sources and synthesis
    """
    depth_map = {
        "quick": "Quickly research and summarize (1-2 sources):",
        "standard": "Research from multiple sources and synthesize:",
        "deep": "Conduct comprehensive research, verify across sources, and produce a detailed report on:",
    }
    prefix = depth_map.get(depth, depth_map["standard"])

    format_clause = (
        " Format as a structured Markdown report with: Executive Summary, Key Findings, "
        "Sources, and Recommendations."
        if structured_output else ""
    )

    task = f"{prefix} {topic}.{format_clause}"
    return suna_run_task(task, agent_type="research")


def suna_security_scan(target: str, scan_type: str = "web") -> dict:
    """
    Use Suna to perform a security scan with browser-based enumeration.
    Suna can navigate web interfaces, analyze responses, and identify exposures.

    Args:
        target: Target URL or hostname to scan
        scan_type: 'web' (web app scan), 'osint' (public info gathering), 'headers' (HTTP security)

    Returns:
        Security findings with risk assessment
    """
    if not target:
        return {"error": "Provide a target URL or hostname"}

    scan_tasks = {
        "web": (
            f"Perform a web security scan of {target}. "
            f"Check: HTTP security headers, exposed sensitive paths (/.env, /.git, /admin, /phpinfo.php), "
            f"JavaScript files for API keys or secrets, robots.txt and sitemap.xml, "
            f"SSL/TLS configuration, and any visible misconfigurations. "
            f"Compile findings with severity ratings."
        ),
        "osint": (
            f"Gather OSINT on {target}. "
            f"Check: WHOIS registration, DNS records, subdomains, "
            f"technology stack (headers, HTML, meta tags), social media presence, "
            f"indexed pages and cached content, and any public breach data mentions. "
            f"Compile a structured intelligence report."
        ),
        "headers": (
            f"Analyze the HTTP security headers of {target}. "
            f"Check for presence and correctness of: Content-Security-Policy, "
            f"X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, "
            f"Referrer-Policy, Permissions-Policy, and CORS configuration. "
            f"Rate each header as Present/Missing/Misconfigured with recommendations."
        ),
    }

    task = scan_tasks.get(scan_type, scan_tasks["web"])
    return suna_run_task(task, agent_type="browser")


TOOLS = {
    "suna_status": suna_status,
    "suna_run_task": suna_run_task,
    "suna_web_research": suna_web_research,
    "suna_security_scan": suna_security_scan,
}
