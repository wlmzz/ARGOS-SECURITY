"""
ARGOS Plugin: Nebula — AI-Powered Pentesting Assistant
berylliumsec/nebula: AI agent for offensive security tasks.
Supports local models via Ollama or OpenAI-compatible APIs.
Prefix commands with '!' to trigger AI execution mode.

Install: pip install nebula-ai
Requires: Python 3.10–3.13, Ollama (for local models) or OpenAI API key

Repo: https://github.com/berylliumsec/nebula
Docker: docker run --rm -it berylliumsec/nebula:latest
"""
from __future__ import annotations
import os, subprocess, shutil
from pathlib import Path

MANIFEST = {
    "id":          "nebula",
    "name":        "Nebula AI Pentesting Assistant",
    "description": "AI-powered security assistant: runs pentesting tasks via natural language. Supports Ollama (local) or OpenAI. berylliumsec/nebula.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TIMEOUT = 120


def _ensure_nebula() -> bool:
    """Install nebula-ai via pip if not present."""
    if shutil.which("nebula"):
        return True
    r = subprocess.run(
        ["pip3", "install", "-q", "--break-system-packages", "nebula-ai"],
        capture_output=True, timeout=180
    )
    return r.returncode == 0 or shutil.which("nebula") is not None


def nebula_query(command: str, model: str = "",
                 openai_key: str = "", timeout: int = _TIMEOUT) -> dict:
    """Run a security task using Nebula AI assistant.
    Nebula interprets natural language commands and executes pentesting tasks.
    Prefix your command with '!' to trigger AI execution mode.

    Examples:
      "! scan 192.168.1.1 for open ports"
      "! check if example.com is vulnerable to XSS"
      "! enumerate subdomains of target.com"
      "! perform a basic web recon on https://example.com"

    command:     natural language security task (prefix with ! for AI execution)
    model:       Ollama model name (default: reads NEBULA_MODEL env var)
    openai_key:  OpenAI API key (default: reads OPENAI_API_KEY env var)
    """
    if not _ensure_nebula():
        return {
            "error": "nebula-ai not installed. Run: pip install nebula-ai",
            "install": "pip install nebula-ai",
            "docker":  "docker run --rm -it berylliumsec/nebula:latest",
        }

    env = os.environ.copy()
    if openai_key:
        env["OPENAI_API_KEY"] = openai_key
    elif os.getenv("OPENAI_API_KEY"):
        pass  # already set
    elif os.getenv("ARGOS_LLM_KEY"):
        env["OPENAI_API_KEY"] = os.getenv("ARGOS_LLM_KEY", "")

    if model:
        env["NEBULA_MODEL"] = model
    elif os.getenv("NEBULA_MODEL"):
        pass

    # Ensure command uses ! prefix for AI mode
    cmd_input = command if command.startswith("!") else f"! {command}"

    try:
        proc = subprocess.run(
            ["nebula"],
            input=cmd_input + "\nexit\n",
            capture_output=True, text=True,
            timeout=timeout, env=env
        )
        output = (proc.stdout + proc.stderr)[-5000:]
        return {
            "tool":    "nebula",
            "command": cmd_input,
            "output":  output,
            "source":  "ARGOS Nebula AI",
        }
    except FileNotFoundError:
        return {
            "error":   "nebula binary not found after install",
            "install": "pip install nebula-ai",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Nebula timed out after {timeout}s", "command": command}
    except Exception as e:
        return {"error": str(e)}


def nebula_docker(command: str, timeout: int = _TIMEOUT) -> dict:
    """Run Nebula via Docker (no local install required).
    Uses berylliumsec/nebula:latest Docker image.

    command: natural language security task
    """
    if not shutil.which("docker"):
        return {"error": "Docker not found. Install Docker or use nebula_query() with pip install."}

    cmd_input = command if command.startswith("!") else f"! {command}"

    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i", "berylliumsec/nebula:latest"],
            input=cmd_input + "\nexit\n",
            capture_output=True, text=True, timeout=timeout
        )
        output = (proc.stdout + proc.stderr)[-5000:]
        return {
            "tool":    "nebula (docker)",
            "command": cmd_input,
            "output":  output,
            "source":  "ARGOS Nebula AI",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Nebula Docker timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def nebula_list_capabilities() -> dict:
    """List Nebula AI capabilities and example commands."""
    return {
        "tool":    "nebula",
        "source":  "berylliumsec/nebula",
        "install": "pip install nebula-ai",
        "models": {
            "local":  "Ollama models (llama3, mistral, codellama, etc.) — set NEBULA_MODEL",
            "cloud":  "OpenAI GPT-4/GPT-3.5 — set OPENAI_API_KEY",
            "argos":  "ARGOS local LLM — set ARGOS_LLM_KEY and NEBULA_MODEL",
        },
        "example_commands": [
            "! scan 192.168.1.1 for open ports and services",
            "! check if https://example.com is vulnerable to SQL injection",
            "! enumerate subdomains for target.com",
            "! perform banner grabbing on 10.0.0.1:22",
            "! generate a Python reverse shell for 192.168.1.100:4444",
            "! check SSL/TLS configuration of example.com",
            "! find admin panels on https://target.com",
            "! run a basic recon workflow on target.com",
        ],
        "usage": "nebula_query(command='! scan 10.0.0.1 for open ports')",
    }


TOOLS = {
    "nebula_query": {
        "fn": nebula_query,
        "description": (
            "AI-powered pentesting assistant (Nebula). Interprets natural language commands "
            "and executes security tasks. Supports Ollama local models or OpenAI. "
            "Example: nebula_query('! scan 192.168.1.1 for open ports and services')"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command":    {"type": "string",  "description": "Natural language security task (prefix with ! for AI execution)"},
                "model":      {"type": "string",  "description": "Ollama model name (e.g. llama3, mistral)"},
                "openai_key": {"type": "string",  "description": "OpenAI API key (optional, uses env var if not set)"},
                "timeout":    {"type": "integer", "description": "Max seconds (default: 120)"},
            },
            "required": ["command"]
        }
    },
    "nebula_docker": {
        "fn": nebula_docker,
        "description": (
            "Run Nebula AI via Docker (no local install). "
            "Uses berylliumsec/nebula:latest. Natural language pentesting commands."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string",  "description": "Natural language security task"},
                "timeout": {"type": "integer", "description": "Max seconds (default: 120)"},
            },
            "required": ["command"]
        }
    },
    "nebula_list_capabilities": {
        "fn": nebula_list_capabilities,
        "description": "List Nebula AI capabilities, supported models, and example commands.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
}
