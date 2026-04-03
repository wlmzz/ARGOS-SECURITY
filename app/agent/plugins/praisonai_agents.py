"""
praisonai_agents.py — ARGOS plugin
Multi-agent security workflows using PraisonAI.
Simpler and faster than CrewAI for quick single-agent and small-crew tasks.
Supports 100+ LLM providers including local Ollama/llama.cpp (Seneca-32B).
https://github.com/MervinPraison/PraisonAI
"""

import json
import os
import subprocess
import shutil
from datetime import datetime

MANIFEST = {
    "id": "praisonai_agents",
    "name": "PraisonAI Agents",
    "version": "1.0.0",
    "description": "PraisonAI: fast single/multi-agent security tasks with 100+ LLM providers",
    "author": "ARGOS",
    "category": "ai_agents",
    "tools": [
        "praison_security_agent",
        "praison_threat_analyzer",
        "praison_code_auditor",
        "praison_osint_agent",
    ],
}

RESULTS_DIR = "/opt/argos/logs/praisonai"
os.makedirs(RESULTS_DIR, exist_ok=True)

DEFAULT_MODEL = os.environ.get("PRAISON_MODEL", "openai/seneca-32b")
DEFAULT_BASE_URL = os.environ.get("SENECA_URL", "http://127.0.0.1:8080/v1")
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "argos-local")


def _ensure_praison() -> tuple[bool, str]:
    try:
        import praisonaiagents
        return True, ""
    except ImportError:
        rc, _, err = subprocess.run(
            ["pip3", "install", "praisonaiagents", "--break-system-packages", "-q"],
            capture_output=True, text=True, timeout=120,
        ).returncode, "", ""
        try:
            import praisonaiagents
            return True, ""
        except ImportError:
            return False, "pip3 install praisonaiagents"


def _run_praison_agent(instructions: str, task: str, tools: list = None,
                        model: str = None, verbose: bool = False) -> dict:
    """Run a single PraisonAI agent with given instructions and task."""
    ok, err = _ensure_praison()
    if not ok:
        return {"error": f"PraisonAI not available: {err}"}

    try:
        from praisonaiagents import Agent

        # Configure to use local Seneca-32B
        os.environ.setdefault("OPENAI_API_KEY", DEFAULT_API_KEY)
        os.environ.setdefault("OPENAI_BASE_URL", DEFAULT_BASE_URL)

        agent = Agent(
            instructions=instructions,
            model=model or DEFAULT_MODEL,
            verbose=verbose,
        )

        result = agent.start(task)
        return {"output": str(result), "success": True}

    except Exception as e:
        return {"error": str(e)[:1000], "success": False}


def _run_praison_crew(agents_config: list, verbose: bool = False) -> dict:
    """Run multiple PraisonAI agents as a crew."""
    ok, err = _ensure_praison()
    if not ok:
        return {"error": f"PraisonAI not available: {err}"}

    try:
        from praisonaiagents import Agent, Agents

        os.environ.setdefault("OPENAI_API_KEY", DEFAULT_API_KEY)
        os.environ.setdefault("OPENAI_BASE_URL", DEFAULT_BASE_URL)

        agents = []
        for cfg in agents_config:
            agents.append(Agent(
                name=cfg.get("name", "Agent"),
                instructions=cfg["instructions"],
                model=cfg.get("model", DEFAULT_MODEL),
                verbose=verbose,
            ))

        crew = Agents(agents=agents, verbose=verbose)
        result = crew.start()
        return {"output": str(result), "success": True}

    except Exception as e:
        return {"error": str(e)[:1000], "success": False}


def praison_security_agent(task: str, context: str = None,
                             model: str = None) -> dict:
    """
    Run a general-purpose cybersecurity AI agent using PraisonAI.
    Good for quick security analysis, advisory questions, and threat assessment.
    Uses local Seneca-32B by default.

    Args:
        task: Security task to perform (e.g. "analyze this log for threats", "review this config")
        context: Additional context to provide (optional)
        model: LLM model override (default: local Seneca-32B)

    Returns:
        Agent analysis and recommendations
    """
    full_task = f"{context}\n\n{task}" if context else task

    result = _run_praison_agent(
        instructions=(
            "You are an expert cybersecurity analyst and penetration tester. "
            "You have deep knowledge of OWASP Top 10, MITRE ATT&CK, CVEs, network security, "
            "malware analysis, incident response, and security hardening. "
            "Provide precise, actionable security analysis."
        ),
        task=full_task,
        model=model,
    )

    # Save output
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(RESULTS_DIR, f"security_agent_{ts}.txt")
    if result.get("success"):
        with open(outfile, "w") as f:
            f.write(f"Task: {task}\n\n{result['output']}")
        result["output_file"] = outfile

    result["task"] = task
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def praison_threat_analyzer(threat_data: str, format: str = "auto",
                              model: str = None) -> dict:
    """
    Analyze threat data (IOCs, logs, alerts, malware samples) with a specialized agent.
    Provides threat classification, severity assessment, and attribution hints.

    Args:
        threat_data: IOCs, log excerpts, alert data, or malware indicators to analyze
        format: Data format hint: 'ioc', 'log', 'alert', 'malware', 'auto' (default: auto)
        model: LLM model override

    Returns:
        Threat analysis with classification, severity, MITRE ATT&CK, and recommendations
    """
    result = _run_praison_agent(
        instructions=(
            "You are a threat intelligence analyst with expertise in malware analysis, "
            "IOC correlation, threat actor attribution, and MITRE ATT&CK mapping. "
            "Analyze threat data and provide: "
            "1) Threat classification and family "
            "2) Severity (Critical/High/Medium/Low) with justification "
            "3) MITRE ATT&CK TTP mapping "
            "4) Threat actor attribution hints "
            "5) Immediate containment steps "
            "6) Long-term remediation "
            "Be specific and reference real-world threat groups when applicable."
        ),
        task=f"Analyze this {format} threat data:\n\n{threat_data[:8000]}",
        model=model,
    )

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if result.get("success"):
        outfile = os.path.join(RESULTS_DIR, f"threat_analysis_{ts}.txt")
        with open(outfile, "w") as f:
            f.write(result["output"])
        result["output_file"] = outfile

    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def praison_code_auditor(code: str, language: str = "auto",
                          focus: str = "all", model: str = None) -> dict:
    """
    AI-powered source code security audit using PraisonAI.
    Finds vulnerabilities, insecure patterns, hardcoded secrets, and injection vectors.

    Args:
        code: Source code to audit
        language: Programming language (default: auto-detect)
        focus: Audit focus: 'all', 'injections', 'auth', 'crypto', 'secrets' (default: all)
        model: LLM model override

    Returns:
        Security findings with severity, line references, and fix suggestions
    """
    focus_prompts = {
        "injections": "Focus on SQL injection, command injection, XSS, XXE, SSTI, path traversal.",
        "auth": "Focus on authentication flaws, session management, JWT issues, broken access control.",
        "crypto": "Focus on cryptographic weaknesses, weak algorithms, improper key management.",
        "secrets": "Focus on hardcoded credentials, API keys, tokens, and sensitive data exposure.",
        "all": "Check for ALL OWASP Top 10 categories plus logic flaws and business logic issues.",
    }

    focus_instruction = focus_prompts.get(focus, focus_prompts["all"])
    lang_hint = f"The code is written in {language}." if language != "auto" else ""

    result = _run_praison_agent(
        instructions=(
            f"You are a security code auditor specializing in finding vulnerabilities. {lang_hint} "
            f"{focus_instruction} "
            "For each finding provide: "
            "1) Vulnerability type and CWE ID "
            "2) Severity (Critical/High/Medium/Low/Info) "
            "3) Specific line or code snippet "
            "4) Exploitation scenario "
            "5) Fix recommendation with secure code example"
        ),
        task=f"Audit this code for security vulnerabilities:\n\n```\n{code[:10000]}\n```",
        model=model,
    )

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if result.get("success"):
        outfile = os.path.join(RESULTS_DIR, f"code_audit_{ts}.txt")
        with open(outfile, "w") as f:
            f.write(result["output"])
        result["output_file"] = outfile

    result["language"] = language
    result["focus"] = focus
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def praison_osint_agent(target: str, objective: str = "full_profile",
                         model: str = None) -> dict:
    """
    OSINT intelligence gathering agent using PraisonAI.
    Builds target profiles from public information: individuals, organizations, or infrastructure.

    Args:
        target: Target to investigate (person name, company, domain, IP, username)
        objective: 'full_profile', 'social_media', 'infrastructure', 'breach_history' (default: full_profile)
        model: LLM model override

    Returns:
        OSINT profile with intelligence sources and findings
    """
    objectives = {
        "full_profile": "Build a complete intelligence profile covering: background, online presence, infrastructure, associated entities, potential vulnerabilities.",
        "social_media": "Focus on social media presence: platforms, usernames, posted content, connections, behavioral patterns.",
        "infrastructure": "Focus on technical infrastructure: domains, IPs, hosting, technologies, exposed services, historical data.",
        "breach_history": "Focus on data breach history: leaked credentials, exposed PII, breach dates, affected services.",
    }

    obj_text = objectives.get(objective, objectives["full_profile"])

    result = _run_praison_agent(
        instructions=(
            "You are an expert OSINT analyst. Provide structured intelligence reports "
            "based on publicly available information. "
            "Always cite potential sources (without actually querying them). "
            "Maintain ethical boundaries — only public information. "
            f"Objective: {obj_text}"
        ),
        task=(
            f"Build an OSINT intelligence report on target: {target}\n\n"
            "Structure your report with: Executive Summary, Key Findings, "
            "Intelligence Sources to Check, Risk Assessment, and Recommended Next Steps."
        ),
        model=model,
    )

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if result.get("success"):
        outfile = os.path.join(RESULTS_DIR, f"osint_{ts}.txt")
        with open(outfile, "w") as f:
            f.write(f"Target: {target}\nObjective: {objective}\n\n{result['output']}")
        result["output_file"] = outfile

    result["target"] = target
    result["objective"] = objective
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


TOOLS = {
    "praison_security_agent": praison_security_agent,
    "praison_threat_analyzer": praison_threat_analyzer,
    "praison_code_auditor": praison_code_auditor,
    "praison_osint_agent": praison_osint_agent,
}
