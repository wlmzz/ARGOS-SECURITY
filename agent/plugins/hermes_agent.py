"""
hermes_agent.py — ARGOS plugin
CLI wrapper for hermes-agent: autonomous AI agent with terminal, file ops, web, and code tools.
hermes-agent provides a standalone agentic loop with 40+ built-in tools.
https://github.com/dannyYassine/hermes-agent
"""

import json
import os
import subprocess
import shutil
from datetime import datetime

MANIFEST = {
    "id": "hermes_agent",
    "name": "Hermes Agent",
    "version": "1.0.0",
    "description": "Hermes autonomous agent: terminal execution, file ops, web research, code analysis",
    "author": "ARGOS",
    "category": "ai_agents",
    "tools": [
        "hermes_run_task",
        "hermes_security_audit",
        "hermes_investigate_host",
        "hermes_analyze_code",
    ],
}

RESULTS_DIR = "/opt/argos/logs/hermes"
os.makedirs(RESULTS_DIR, exist_ok=True)

# hermes-agent binary location
HERMES_BIN = shutil.which("hermes") or shutil.which("hermes-agent") or "/usr/local/bin/hermes"
HERMES_CONFIG = os.path.join(RESULTS_DIR, "hermes_config.json")

# Default LLM (local Seneca-32B via OpenAI-compatible endpoint)
DEFAULT_MODEL = os.environ.get("HERMES_MODEL", "seneca-32b")
DEFAULT_BASE_URL = os.environ.get("SENECA_URL", "http://127.0.0.1:8080/v1")
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "argos-local")


def _ensure_hermes() -> tuple[bool, str]:
    """Check if hermes-agent is available, attempt npm install if not."""
    if os.path.exists(HERMES_BIN) or shutil.which("hermes") or shutil.which("hermes-agent"):
        return True, ""

    # Try npm global install
    npm = shutil.which("npm")
    if npm:
        try:
            result = subprocess.run(
                [npm, "install", "-g", "hermes-agent"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and shutil.which("hermes-agent"):
                return True, ""
        except Exception:
            pass

    return False, "hermes-agent not found. Install: npm install -g hermes-agent"


def _run_hermes(task: str, timeout: int = 120) -> dict:
    """Run hermes-agent with a task and capture output."""
    ok, err = _ensure_hermes()
    if not ok:
        # Fallback: simulate with subprocess + Python
        return {"error": err, "success": False, "fallback_note": "Use praison_security_agent for similar capability"}

    bin_path = shutil.which("hermes") or shutil.which("hermes-agent") or HERMES_BIN

    env = os.environ.copy()
    env["OPENAI_API_KEY"] = DEFAULT_API_KEY
    env["OPENAI_BASE_URL"] = DEFAULT_BASE_URL
    env["OPENAI_MODEL"] = DEFAULT_MODEL

    try:
        result = subprocess.run(
            [bin_path, "--task", task],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        output = result.stdout + result.stderr
        return {
            "output": output.strip()[:10000],
            "success": result.returncode == 0,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Hermes task timed out after {timeout}s", "success": False}
    except Exception as e:
        return {"error": str(e)[:500], "success": False}


def _run_hermes_python(task: str, timeout: int = 120) -> dict:
    """Run hermes-agent via Python SDK if available."""
    try:
        # Try Python SDK (hermes_agent package)
        import hermes_agent as ha

        env_bak = {}
        for k, v in [("OPENAI_API_KEY", DEFAULT_API_KEY),
                      ("OPENAI_BASE_URL", DEFAULT_BASE_URL),
                      ("OPENAI_MODEL", DEFAULT_MODEL)]:
            env_bak[k] = os.environ.get(k)
            os.environ[k] = v

        try:
            agent = ha.Agent()
            result = agent.run(task)
            output = str(result)
        finally:
            for k, v in env_bak.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        return {"output": output[:10000], "success": True}
    except ImportError:
        return _run_hermes(task, timeout)
    except Exception as e:
        return _run_hermes(task, timeout)


def hermes_run_task(task: str, save_output: bool = True) -> dict:
    """
    Run any task using the Hermes autonomous agent.
    Hermes has access to terminal commands, file operations, web browsing, and code execution.

    Args:
        task: Natural language task for the agent (e.g. "check what ports are open on localhost")
        save_output: Save results to /opt/argos/logs/hermes/ (default: True)

    Returns:
        Agent output and execution status
    """
    if not task or len(task.strip()) < 5:
        return {"error": "Task too short"}

    result = _run_hermes_python(task)

    if result.get("success") and save_output:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(RESULTS_DIR, f"task_{ts}.txt")
        with open(outfile, "w") as f:
            f.write(f"Task: {task}\n\n{result.get('output', '')}")
        result["output_file"] = outfile

    result["task"] = task
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def hermes_security_audit(target: str, checks: list = None) -> dict:
    """
    Run a security audit on a target system using Hermes agent's terminal and file tools.
    The agent autonomously runs security checks and compiles findings.

    Args:
        target: Target to audit: 'localhost', IP, hostname, or 'self' for ARGOS server
        checks: Specific checks to run (default: all)
                Options: 'ports', 'services', 'users', 'cron', 'suid', 'network', 'processes'

    Returns:
        Security audit findings with risk assessment
    """
    if target in ("self", "argos", "localhost", "127.0.0.1"):
        target_desc = "the local system"
    else:
        target_desc = target

    check_list = checks or ["ports", "services", "users", "cron", "suid", "network", "processes"]
    checks_str = ", ".join(check_list)

    task = (
        f"Perform a security audit of {target_desc}. Check the following: {checks_str}. "
        f"For each check: run the appropriate command, analyze the output, "
        f"identify security issues or misconfigurations, and rate risk (Critical/High/Medium/Low). "
        f"Compile all findings into a structured security audit report."
    )

    return hermes_run_task(task)


def hermes_investigate_host(hostname: str, depth: str = "standard") -> dict:
    """
    Investigate a host using Hermes agent: network recon, service enumeration, web analysis.
    The agent autonomously runs recon tools and synthesizes findings.

    Args:
        hostname: Target hostname or IP to investigate
        depth: 'quick' (ping + ports), 'standard' (nmap + headers), 'deep' (full recon)

    Returns:
        Host investigation report with services, technologies, and potential vulnerabilities
    """
    if not hostname:
        return {"error": "Provide a hostname or IP"}

    depth_instructions = {
        "quick": f"Quick check: ping {hostname}, run a fast port scan, check if web server is up.",
        "standard": (
            f"Investigate host {hostname}: port scan, grab service banners, "
            f"check web server headers and technologies, look for exposed paths."
        ),
        "deep": (
            f"Full investigation of {hostname}: comprehensive port scan, service version detection, "
            f"web crawling, technology fingerprinting, check for common vulnerabilities, "
            f"look for admin panels, exposed files, and security misconfigurations."
        ),
    }

    task = depth_instructions.get(depth, depth_instructions["standard"])
    task += " Present findings in a structured format with risk ratings."

    return hermes_run_task(task)


def hermes_analyze_code(code: str = None, file_path: str = None,
                          focus: str = "security") -> dict:
    """
    Use Hermes agent to analyze code for security issues, logic flaws, or quality problems.

    Args:
        code: Code string to analyze (inline)
        file_path: Path to code file (alternative to code param)
        focus: Analysis focus: 'security' (vulnerabilities), 'quality' (code review),
               'secrets' (hardcoded credentials), 'all' (default: security)

    Returns:
        Code analysis with findings, severity ratings, and fix recommendations
    """
    if not code and not file_path:
        return {"error": "Provide code or file_path"}

    if file_path:
        task = (
            f"Read the file at {file_path} and analyze it for {focus} issues. "
            f"List all findings with: issue type, severity (Critical/High/Medium/Low/Info), "
            f"affected line numbers, explanation, and recommended fix."
        )
    else:
        task = (
            f"Analyze this code for {focus} issues:\n\n```\n{code[:8000]}\n```\n\n"
            f"List all findings with: issue type, severity (Critical/High/Medium/Low/Info), "
            f"affected line or pattern, explanation, and recommended fix."
        )

    return hermes_run_task(task)


TOOLS = {
    "hermes_run_task": hermes_run_task,
    "hermes_security_audit": hermes_security_audit,
    "hermes_investigate_host": hermes_investigate_host,
    "hermes_analyze_code": hermes_analyze_code,
}
