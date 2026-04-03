"""
deer_flow_client.py — ARGOS plugin
REST API client for DeerFlow (ByteDance open-source deep research agent).
DeerFlow orchestrates web search, code execution, and report generation for security research.
Self-hosted: docker compose up -d (ports 2024/8001)
https://github.com/bytedance/deer-flow
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "deer_flow_client",
    "name": "DeerFlow Research Agent",
    "version": "1.0.0",
    "description": "DeerFlow deep research: web search + code execution + structured reports for security topics",
    "author": "ARGOS",
    "category": "ai_agents",
    "tools": [
        "deerflow_research",
        "deerflow_threat_report",
        "deerflow_cve_research",
        "deerflow_status",
    ],
}

RESULTS_DIR = "/opt/argos/logs/deerflow"
os.makedirs(RESULTS_DIR, exist_ok=True)

# DeerFlow server URL — default ports 2024 (API) or 8001 (alt)
DF_BASE = os.environ.get("DEERFLOW_URL", "http://localhost:2024")
DF_ALT = os.environ.get("DEERFLOW_ALT_URL", "http://localhost:8001")


def _api(path: str, method: str = "GET", data: dict = None, timeout: int = 15,
         base: str = None) -> tuple[dict, int]:
    url = f"{base or DF_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read()), resp.getcode()
    except Exception as e:
        return {"error": str(e)[:200]}, 0


def _find_server() -> tuple[str | None, str]:
    """Try both default ports to find active DeerFlow instance."""
    for base in [DF_BASE, DF_ALT]:
        _, code = _api("/api/health", base=base)
        if code == 200:
            return base, ""
        # Also try /health
        _, code = _api("/health", base=base)
        if code == 200:
            return base, ""
    return None, f"DeerFlow not found on {DF_BASE} or {DF_ALT}. Start with: docker compose up -d"


def _stream_research(query: str, base: str, timeout: int = 300) -> dict:
    """Send research request and collect streamed response."""
    payload = {
        "messages": [{"role": "user", "content": query}],
        "stream": True,
    }

    # Try /api/chat/stream endpoint
    endpoints = ["/api/chat/stream", "/api/chat", "/chat"]
    for endpoint in endpoints:
        url = f"{base}{endpoint}"
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                # Parse SSE or JSON
                content = ""
                if "data:" in raw:
                    for line in raw.split("\n"):
                        if line.startswith("data:") and line.strip() != "data: [DONE]":
                            try:
                                chunk = json.loads(line[5:].strip())
                                delta = (chunk.get("choices", [{}])[0]
                                         .get("delta", {}).get("content", ""))
                                content += delta
                            except Exception:
                                content += line[5:].strip() + "\n"
                else:
                    try:
                        data = json.loads(raw)
                        content = (data.get("choices", [{}])[0]
                                   .get("message", {}).get("content", raw))
                    except Exception:
                        content = raw[:5000]
                return {"output": content.strip(), "success": True}
        except Exception:
            continue

    return {"error": f"All DeerFlow endpoints failed", "success": False}


def deerflow_status() -> dict:
    """
    Check DeerFlow server status and available capabilities.

    Returns:
        Server status, version, and setup instructions if not running
    """
    base, err = _find_server()
    if not base:
        return {
            "status": "not_running",
            "error": err,
            "setup": [
                "git clone https://github.com/bytedance/deer-flow",
                "cd deer-flow && cp .env.example .env",
                "# Edit .env: set OPENAI_BASE_URL=http://127.0.0.1:8080/v1 for local Seneca-32B",
                "docker compose up -d",
            ],
            "default_ports": ["2024", "8001"],
            "env_vars": ["DEERFLOW_URL", "DEERFLOW_ALT_URL"],
        }

    data, _ = _api("/api/health", base=base)
    return {
        "status": "running",
        "base_url": base,
        "health": data,
        "timestamp": datetime.utcnow().isoformat(),
    }


def deerflow_research(query: str, depth: str = "standard",
                       save_report: bool = True) -> dict:
    """
    Run a deep research task using DeerFlow's multi-agent pipeline.
    DeerFlow combines web search, code execution, and LLM synthesis for comprehensive reports.

    Args:
        query: Research question or topic (e.g. "analyze APT28 tactics and recent campaigns")
        depth: Research depth: 'quick' (single pass), 'standard' (multi-step), 'deep' (full)
        save_report: Save output to /opt/argos/logs/deerflow/ (default: True)

    Returns:
        Research report with findings, sources, and analysis
    """
    if not query or len(query.strip()) < 5:
        return {"error": "Query too short"}

    base, err = _find_server()
    if not base:
        return {
            "status": "deerflow_not_configured",
            "query": query,
            "note": err,
            "setup": "See deerflow_status() for setup instructions",
        }

    depth_prefixes = {
        "quick": "Briefly research: ",
        "standard": "Research and analyze: ",
        "deep": (
            "Conduct comprehensive deep research on the following topic. "
            "Search multiple sources, analyze findings, cross-reference data, "
            "and produce a detailed structured report: "
        ),
    }
    full_query = depth_prefixes.get(depth, depth_prefixes["standard"]) + query

    result = _stream_research(full_query, base)

    if result.get("success") and save_report:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(RESULTS_DIR, f"research_{ts}.md")
        with open(outfile, "w") as f:
            f.write(f"# DeerFlow Research Report\n\n")
            f.write(f"**Query**: {query}\n**Depth**: {depth}\n**Timestamp**: {ts}\n\n---\n\n")
            f.write(result["output"])
        result["output_file"] = outfile

    result["query"] = query
    result["depth"] = depth
    result["deerflow_url"] = base
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


def deerflow_threat_report(threat_actor: str = None, campaign: str = None,
                             malware_family: str = None) -> dict:
    """
    Generate a structured threat intelligence report on a threat actor, campaign, or malware.
    DeerFlow searches open-source threat intel to compile comprehensive TTPs, IOCs, and history.

    Args:
        threat_actor: Threat actor name (e.g. 'APT28', 'Lazarus Group', 'LockBit')
        campaign: Campaign name or code (e.g. 'SolarWinds', 'NotPetya')
        malware_family: Malware family (e.g. 'Emotet', 'Cobalt Strike', 'Mimikatz')

    Returns:
        Structured threat report: TTPs, IOCs, attribution, timeline, mitigations
    """
    if not any([threat_actor, campaign, malware_family]):
        return {"error": "Provide threat_actor, campaign, or malware_family"}

    subject = threat_actor or campaign or malware_family
    subject_type = (
        "threat actor/APT group" if threat_actor else
        "attack campaign" if campaign else
        "malware family"
    )

    query = (
        f"Generate a comprehensive threat intelligence report on the {subject_type}: {subject}. "
        f"Include: 1) Overview and attribution 2) Known TTPs mapped to MITRE ATT&CK "
        f"3) Known IOCs (IPs, domains, hashes) 4) Target sectors and geographies "
        f"5) Attack timeline and major incidents 6) Detection signatures "
        f"7) Defensive mitigations and hunting queries"
    )

    return deerflow_research(query, depth="deep")


def deerflow_cve_research(cve_id: str, include_exploits: bool = True) -> dict:
    """
    Research a CVE: technical details, affected software, exploit availability, and patches.

    Args:
        cve_id: CVE identifier (e.g. 'CVE-2024-3400', 'CVE-2021-44228')
        include_exploits: Include known exploit information (default: True)

    Returns:
        CVE report: CVSS, affected versions, PoC status, patches, and detection
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return {"error": "Provide a valid CVE ID (e.g. CVE-2024-1234)"}

    exploit_clause = (
        "5) Known PoC exploits and exploit availability " if include_exploits
        else "5) Defensive mitigation priority "
    )

    query = (
        f"Research {cve_id.upper()} in detail. Include: "
        f"1) Vulnerability description and affected software versions "
        f"2) CVSS score and impact (CIA triad) "
        f"3) Technical exploitation mechanism "
        f"4) Patch/fix information and affected versions "
        + exploit_clause +
        f"6) Detection rules (SIGMA, Snort, Yara) "
        f"7) In-the-wild exploitation evidence"
    )

    return deerflow_research(query, depth="deep")


TOOLS = {
    "deerflow_status": deerflow_status,
    "deerflow_research": deerflow_research,
    "deerflow_threat_report": deerflow_threat_report,
    "deerflow_cve_research": deerflow_cve_research,
}
