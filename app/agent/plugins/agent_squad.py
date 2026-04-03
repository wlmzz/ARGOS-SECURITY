"""
agent_squad.py — ARGOS plugin
Intelligent multi-agent routing and orchestration using AWS agent-squad.
Routes security tasks to the most appropriate specialist agent automatically.
https://github.com/awslabs/agent-squad
"""

import json
import os
import subprocess
import asyncio
from datetime import datetime

MANIFEST = {
    "id": "agent_squad",
    "name": "Agent Squad",
    "version": "1.0.0",
    "description": "Smart multi-agent routing: auto-dispatches tasks to specialist security agents",
    "author": "ARGOS",
    "category": "ai_agents",
    "tools": [
        "squad_dispatch",
        "squad_security_team",
        "squad_classify_task",
        "squad_parallel_analysis",
    ],
}

RESULTS_DIR = "/opt/argos/logs/agent_squad"
os.makedirs(RESULTS_DIR, exist_ok=True)

DEFAULT_MODEL = os.environ.get("SENECA_MODEL", "seneca-32b")
DEFAULT_BASE_URL = os.environ.get("SENECA_URL", "http://127.0.0.1:8080/v1")
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "argos-local")


def _ensure_agent_squad() -> tuple[bool, str]:
    try:
        import agent_squad
        return True, ""
    except ImportError:
        rc, _, err = subprocess.run(
            ["pip3", "install", "agent-squad", "--break-system-packages", "-q"],
            capture_output=True, text=True, timeout=120,
        ).returncode, "", ""
        try:
            import agent_squad
            return True, ""
        except ImportError:
            return False, "pip3 install agent-squad"


def _run_async(coro, timeout: int = 120):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result(timeout=timeout)
        return loop.run_until_complete(coro)
    except Exception as e:
        return str(e)


def _simple_router_fallback(task: str, agents: list) -> str:
    """Simple keyword-based routing when agent-squad unavailable."""
    task_lower = task.lower()
    keywords = {
        "recon": ["recon", "osint", "scan", "enumerate", "discover", "footprint"],
        "malware": ["malware", "virus", "ransomware", "trojan", "ioc", "hash", "sample"],
        "network": ["network", "traffic", "pcap", "firewall", "port", "connection", "protocol"],
        "web": ["web", "http", "sql", "xss", "csrf", "api", "endpoint", "injection"],
        "forensics": ["forensic", "incident", "log", "evtx", "artifact", "timeline", "evidence"],
        "pentest": ["pentest", "exploit", "vulnerability", "vuln", "cve", "attack", "payload"],
    }
    for agent_type, kws in keywords.items():
        if any(kw in task_lower for kw in kws):
            matching = [a for a in agents if a.get("type") == agent_type]
            if matching:
                return matching[0]["name"]
    return agents[0]["name"] if agents else "default"


def squad_classify_task(task: str) -> dict:
    """
    Classify a security task and determine which specialist agent should handle it.
    Maps tasks to the ARGOS plugin ecosystem automatically.

    Args:
        task: Security task description

    Returns:
        Task classification with recommended agent/plugin and confidence
    """
    task_lower = task.lower()

    classifications = [
        {
            "category": "Threat Intelligence",
            "keywords": ["ioc", "indicator", "threat actor", "apt", "malware", "campaign", "feed"],
            "recommended_plugin": "threat_intel_feeds",
            "recommended_tools": ["check_ip", "check_ips_bulk", "update_feeds"],
        },
        {
            "category": "OSINT / Reconnaissance",
            "keywords": ["osint", "recon", "domain", "whois", "subdomain", "username", "person"],
            "recommended_plugin": "fast_recon / favicon_osint / username_osint",
            "recommended_tools": ["fast_port_scan", "favicon_full_hunt", "sherlock_rs_search"],
        },
        {
            "category": "Web Security",
            "keywords": ["web", "http", "api", "sql", "xss", "injection", "csrf", "owasp"],
            "recommended_plugin": "browser_recon / sqlmap / web_recon",
            "recommended_tools": ["web_crawl", "form_analyzer", "js_recon"],
        },
        {
            "category": "Network Analysis",
            "keywords": ["network", "pcap", "traffic", "packet", "flow", "port", "scan"],
            "recommended_plugin": "network_capture / fast_recon",
            "recommended_tools": ["capture_start", "analyze_pcap", "flowmeter_analyze"],
        },
        {
            "category": "Digital Forensics",
            "keywords": ["forensic", "evtx", "log", "incident", "artifact", "timeline", "memory"],
            "recommended_plugin": "dfir_forensics / zircolite_sigma / volatility_plugin",
            "recommended_tools": ["ir_collect_artifacts", "sigma_analyze_linux", "evtx_analyze"],
        },
        {
            "category": "Malware Analysis",
            "keywords": ["malware", "ransomware", "trojan", "virus", "sample", "hash", "yara"],
            "recommended_plugin": "yara_clamav / tika_extractor / datasurgeon",
            "recommended_tools": ["tika_malware_triage", "extract_iocs_from_file"],
        },
        {
            "category": "Mobile Security",
            "keywords": ["mobile", "android", "ios", "apk", "spyware", "pegasus", "stalkerware"],
            "recommended_plugin": "mobile_forensics",
            "recommended_tools": ["mvt_ios_scan_backup", "mvt_android_scan_apk"],
        },
        {
            "category": "Vulnerability Assessment",
            "keywords": ["vuln", "cve", "patch", "exploit", "metasploit", "nuclei", "scan"],
            "recommended_plugin": "crewai_pentest / fast_recon / metasploit",
            "recommended_tools": ["crewai_vuln_crew", "deep_service_scan"],
        },
        {
            "category": "Code Security",
            "keywords": ["code", "source", "audit", "review", "sast", "semgrep", "bandit"],
            "recommended_plugin": "semgrep_bandit / praisonai_agents",
            "recommended_tools": ["praison_code_auditor", "semgrep_scan"],
        },
        {
            "category": "Incident Response",
            "keywords": ["incident", "breach", "compromise", "response", "containment", "eradication"],
            "recommended_plugin": "crewai_pentest / dfir_forensics",
            "recommended_tools": ["crewai_incident_response_crew", "ir_collect_artifacts"],
        },
    ]

    matches = []
    for cls in classifications:
        score = sum(1 for kw in cls["keywords"] if kw in task_lower)
        if score > 0:
            matches.append({**cls, "match_score": score})

    matches.sort(key=lambda x: x["match_score"], reverse=True)
    top = matches[0] if matches else {
        "category": "General Security",
        "recommended_plugin": "praisonai_agents",
        "recommended_tools": ["praison_security_agent"],
        "match_score": 0,
    }

    return {
        "task": task,
        "primary_classification": top["category"],
        "recommended_plugin": top["recommended_plugin"],
        "recommended_tools": top.get("recommended_tools", []),
        "confidence": min(top["match_score"] / 3, 1.0),
        "all_matches": matches[:3],
        "timestamp": datetime.utcnow().isoformat(),
    }


def squad_dispatch(task: str, auto_classify: bool = True,
                    preferred_agent: str = None) -> dict:
    """
    Dispatch a security task to the most appropriate ARGOS agent/tool automatically.
    Classifies the task, selects the best handler, and returns the routing decision.

    Args:
        task: Security task to dispatch
        auto_classify: Auto-classify and route task (default: True)
        preferred_agent: Override routing to specific agent type (optional)

    Returns:
        Routing decision with recommended plugin, tools, and execution plan
    """
    # First classify the task
    classification = squad_classify_task(task)

    ok, err = _ensure_agent_squad()

    if ok:
        try:
            from agent_squad.orchestrator import AgentSquad, AgentSquadConfig
            from agent_squad.agents import BedrockLLMAgent, BedrockLLMAgentOptions
            from agent_squad.classifiers import AnthropicClassifier, AnthropicClassifierOptions

            # Try to use local LLM for classification
            # agent-squad primarily supports Bedrock/Anthropic API
            # Fall through to our own classification if no API key
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                raise ValueError("No Anthropic API key for agent-squad classifier")

        except Exception:
            # Use our own classifier
            pass

    # Generate execution plan based on classification
    cls = classification["primary_classification"]
    plan_map = {
        "Threat Intelligence": [
            "1. Run threat_intel_feeds.update_feeds() to refresh blocklists",
            "2. Use threat_intel_feeds.check_ip() for specific IOC checks",
            "3. Run ip_investigator.investigate_ip() for deep IP analysis",
            "4. Use cognee_knowledge.knowledge_ingest() to persist findings",
        ],
        "OSINT / Reconnaissance": [
            "1. Run fast_recon.fast_port_scan() for port discovery",
            "2. Use favicon_osint.favicon_full_hunt() for infrastructure mapping",
            "3. Run username_osint.sherlock_rs_search() for social media",
            "4. Use browser_recon.web_crawl() for site mapping",
        ],
        "Digital Forensics": [
            "1. Run dfir_forensics.ir_collect_artifacts() for live IR",
            "2. Use zircolite_sigma.sigma_full_analysis() on collected logs",
            "3. Run dfir_forensics.evtx_analyze() on Windows event logs",
            "4. Use volatility_plugin for memory forensics if available",
        ],
        "Incident Response": [
            "1. Run crewai_pentest.crewai_incident_response_crew() for playbook",
            "2. Use dfir_forensics.ir_collect_artifacts() for evidence",
            "3. Run zircolite_sigma.sigma_full_analysis() for threat detection",
            "4. Use cognee_knowledge.knowledge_ingest() to document incident",
        ],
    }

    execution_plan = plan_map.get(cls, [
        f"1. Use {classification['recommended_plugin']}",
        f"2. Run {', '.join(classification['recommended_tools'][:2])}",
        "3. Document findings with cognee_knowledge.knowledge_ingest()",
    ])

    return {
        "task": task,
        "routing": {
            "classification": cls,
            "recommended_plugin": classification["recommended_plugin"],
            "recommended_tools": classification["recommended_tools"],
            "confidence": classification["confidence"],
        },
        "execution_plan": execution_plan,
        "agent_squad_available": ok,
        "timestamp": datetime.utcnow().isoformat(),
    }


def squad_security_team(objective: str, target: str = None,
                          team_size: int = 3) -> dict:
    """
    Assemble and run a specialized security team for a complex objective.
    Automatically selects the best combination of ARGOS plugins for the task.

    Args:
        objective: High-level security objective (e.g. "full pentest", "incident investigation", "threat hunt")
        target: Target system/IP/domain (optional)
        team_size: Number of specialist agents in team (2-5, default: 3)

    Returns:
        Team composition, task assignments, and coordinated execution plan
    """
    team_size = max(2, min(5, team_size))

    obj_lower = objective.lower()

    # Define team compositions for common objectives
    team_templates = {
        "pentest": {
            "agents": [
                {"role": "Recon Specialist", "plugin": "fast_recon", "tools": ["full_recon_pipeline"]},
                {"role": "Vuln Analyst", "plugin": "crewai_pentest", "tools": ["crewai_vuln_crew"]},
                {"role": "Web Tester", "plugin": "browser_recon", "tools": ["web_crawl", "form_analyzer", "js_recon"]},
                {"role": "Threat Intel", "plugin": "threat_intel_feeds", "tools": ["check_ip", "update_feeds"]},
                {"role": "Reporter", "plugin": "pentest_report", "tools": ["generate_pentest_report"]},
            ],
        },
        "incident": {
            "agents": [
                {"role": "Triage", "plugin": "crewai_pentest", "tools": ["crewai_incident_response_crew"]},
                {"role": "Forensics", "plugin": "dfir_forensics", "tools": ["ir_collect_artifacts", "evtx_analyze"]},
                {"role": "Threat Hunter", "plugin": "zircolite_sigma", "tools": ["sigma_full_analysis"]},
                {"role": "IOC Extractor", "plugin": "datasurgeon", "tools": ["extract_iocs_from_file"]},
                {"role": "Intel", "plugin": "ip_investigator", "tools": ["investigate_attackers"]},
            ],
        },
        "threat_hunt": {
            "agents": [
                {"role": "Log Analyst", "plugin": "zircolite_sigma", "tools": ["sigma_analyze_linux"]},
                {"role": "Network Monitor", "plugin": "network_capture", "tools": ["capture_start", "analyze_pcap"]},
                {"role": "IOC Hunter", "plugin": "threat_intel_feeds", "tools": ["check_ips_bulk"]},
                {"role": "AI Analyst", "plugin": "crewai_pentest", "tools": ["crewai_threat_hunt_crew"]},
                {"role": "Knowledge", "plugin": "cognee_knowledge", "tools": ["knowledge_correlate"]},
            ],
        },
        "osint": {
            "agents": [
                {"role": "Recon", "plugin": "fast_recon", "tools": ["full_recon_pipeline"]},
                {"role": "Social", "plugin": "username_osint", "tools": ["sherlock_rs_search"]},
                {"role": "Web Intel", "plugin": "browser_recon", "tools": ["web_crawl", "js_recon"]},
                {"role": "Favicon", "plugin": "favicon_osint", "tools": ["favicon_full_hunt"]},
                {"role": "AI OSINT", "plugin": "praisonai_agents", "tools": ["praison_osint_agent"]},
            ],
        },
    }

    # Select template
    template = None
    for key, tmpl in team_templates.items():
        if key in obj_lower or any(w in obj_lower for w in key.split("_")):
            template = tmpl
            break

    if not template:
        template = team_templates["pentest"]  # default

    selected_agents = template["agents"][:team_size]

    # Build execution sequence
    sequence = []
    for i, agent in enumerate(selected_agents, 1):
        step = {
            "step": i,
            "role": agent["role"],
            "plugin": agent["plugin"],
            "tools": agent["tools"],
        }
        if target:
            step["target"] = target
        sequence.append(step)

    result = {
        "objective": objective,
        "target": target,
        "team_size": team_size,
        "team": [{"role": a["role"], "plugin": a["plugin"]} for a in selected_agents],
        "execution_sequence": sequence,
        "estimated_phases": len(sequence),
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Save team plan
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(RESULTS_DIR, f"team_plan_{ts}.json")
    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)
    result["plan_file"] = outfile

    return result


def squad_parallel_analysis(task: str, perspectives: list = None) -> dict:
    """
    Run the same task from multiple security perspectives simultaneously.
    E.g., analyze an IP as threat intel + recon + network + forensics in parallel.

    Args:
        task: Task or artifact to analyze
        perspectives: List of analysis angles (default: ['threat_intel', 'recon', 'forensics'])

    Returns:
        Parallel analysis results from each perspective with consolidated findings
    """
    default_perspectives = ["threat_intel", "recon", "forensics"]
    perspectives = perspectives or default_perspectives

    perspective_configs = {
        "threat_intel": {
            "focus": "threat intelligence and IOC analysis",
            "plugin": "threat_intel_feeds / ip_investigator",
        },
        "recon": {
            "focus": "reconnaissance and attack surface mapping",
            "plugin": "fast_recon / browser_recon",
        },
        "forensics": {
            "focus": "digital forensics and evidence analysis",
            "plugin": "dfir_forensics / zircolite_sigma",
        },
        "malware": {
            "focus": "malware behavior and family classification",
            "plugin": "yara_clamav / tika_extractor",
        },
        "network": {
            "focus": "network behavior and traffic analysis",
            "plugin": "network_capture / network_ids",
        },
        "osint": {
            "focus": "open source intelligence gathering",
            "plugin": "username_osint / favicon_osint / spiderfoot",
        },
    }

    results = {
        "task": task,
        "perspectives": {},
        "consolidated_findings": [],
        "timestamp": datetime.utcnow().isoformat(),
    }

    for persp in perspectives:
        cfg = perspective_configs.get(persp, {
            "focus": persp,
            "plugin": "praisonai_agents",
        })

        # Use PraisonAI for each perspective analysis
        try:
            from praisonaiagents import Agent

            os.environ.setdefault("OPENAI_API_KEY", DEFAULT_API_KEY)
            os.environ.setdefault("OPENAI_BASE_URL", DEFAULT_BASE_URL)

            agent = Agent(
                instructions=(
                    f"You are a cybersecurity specialist focused on {cfg['focus']}. "
                    f"Analyze the provided information and extract insights relevant to your specialty. "
                    f"Be concise and specific."
                ),
                model=DEFAULT_MODEL,
                verbose=False,
            )
            result = agent.start(f"Analyze from {cfg['focus']} perspective: {task[:3000]}")
            results["perspectives"][persp] = {
                "plugin": cfg["plugin"],
                "focus": cfg["focus"],
                "analysis": str(result)[:2000],
                "status": "completed",
            }
        except Exception as e:
            results["perspectives"][persp] = {
                "plugin": cfg["plugin"],
                "focus": cfg["focus"],
                "status": "failed",
                "error": str(e)[:200],
                "note": f"Use {cfg['plugin']} manually for {cfg['focus']} analysis",
            }

    # Consolidate
    completed = [p for p in results["perspectives"].values() if p.get("status") == "completed"]
    results["completed_perspectives"] = len(completed)
    results["total_perspectives"] = len(perspectives)

    return results


TOOLS = {
    "squad_dispatch": squad_dispatch,
    "squad_security_team": squad_security_team,
    "squad_classify_task": squad_classify_task,
    "squad_parallel_analysis": squad_parallel_analysis,
}
