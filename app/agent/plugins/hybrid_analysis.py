"""
ARGOS Plugin: Hybrid Analysis (Falcon Sandbox)
Free malware sandbox by CrowdStrike — submit files/URLs and get full behavioral analysis.
Free API key at: hybrid-analysis.com/apikeys/info (register free account)
Set HYBRID_ANALYSIS_API_KEY env var.
Rate limit: 5 requests/min, 200/day on free tier.
"""
from __future__ import annotations
import json, os, re, time, urllib.request, urllib.error, urllib.parse

MANIFEST = {
    "id":          "hybrid_analysis",
    "name":        "Hybrid Analysis",
    "description": "CrowdStrike Falcon Sandbox: search malware reports, submit URLs/hashes for behavioral analysis.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://www.hybrid-analysis.com/api/v2"


def _ha_request(method: str, path: str, data: dict | None = None) -> dict:
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
    if not api_key:
        return {"error": "HYBRID_ANALYSIS_API_KEY not set. Get free key at hybrid-analysis.com/apikeys/info"}

    headers = {
        "api-key":    api_key,
        "User-Agent": "Falcon Sandbox",
        "Accept":     "application/json",
    }

    url = f"{_BASE}{path}"
    body = None
    if data:
        if method == "GET":
            url += "?" + urllib.parse.urlencode(data)
        else:
            encoded = urllib.parse.urlencode(data).encode()
            body = encoded
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def ha_hash_search(file_hash: str) -> dict:
    """Search Hybrid Analysis for existing reports on a file hash (MD5/SHA1/SHA256).
    Returns threat score, AV detections, MITRE ATT&CK techniques, malware family, network IOCs."""
    h = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", h):
        return {"error": "Invalid hash format (MD5=32, SHA1=40, SHA256=64 hex)"}

    data = _ha_request("GET", "/search/hash", {"hash": h})
    if "error" in data:
        return data

    results = data if isinstance(data, list) else data.get("result", [])
    if not results:
        return {
            "hash":    h,
            "source":  "Hybrid Analysis",
            "found":   False,
            "verdict": "NOT_FOUND — no sandbox report available",
        }

    # Take the most recent/highest-score result
    best = max(results, key=lambda r: r.get("threat_score", 0) or 0) if results else {}
    mitre = best.get("mitre_attcks", []) or []

    return {
        "hash":          h,
        "source":        "Hybrid Analysis",
        "found":         True,
        "threat_score":  best.get("threat_score", 0),
        "verdict":       best.get("verdict", "unknown"),
        "av_detect":     best.get("av_detect", 0),
        "vx_family":     best.get("vx_family", ""),
        "type":          best.get("type", ""),
        "size":          best.get("size", 0),
        "sha256":        best.get("sha256", ""),
        "md5":           best.get("md5", ""),
        "submit_name":   best.get("submit_name", ""),
        "analysis_start": best.get("analysis_start_time", ""),
        "environment":   best.get("environment_description", ""),
        "classification": best.get("classification_tags", [])[:10],
        "mitre_techniques": [
            {
                "technique": m.get("technique", ""),
                "id":        m.get("attck_id", ""),
                "tactic":    m.get("tactic", ""),
            }
            for m in mitre[:15]
        ],
        "domains":       best.get("domains", [])[:20],
        "hosts":         best.get("hosts", [])[:20],
        "compromised_hosts": best.get("compromised_hosts", [])[:10],
        "total_reports": len(results),
    }


def ha_url_submit(url: str, environment_id: int = 120) -> dict:
    """Submit a URL to Hybrid Analysis sandbox for behavioral analysis.
    Returns job_id to poll for results.
    Environment IDs: 100=Win7 32bit, 110=Win7 64bit, 120=Win10 64bit (default), 300=Linux."""
    data = _ha_request("POST", "/submit/url", {"url": url, "environment_id": environment_id})
    if "error" in data:
        return data

    job_id = data.get("job_id", "")
    return {
        "url":         url,
        "source":      "Hybrid Analysis",
        "job_id":      job_id,
        "sha256":      data.get("sha256", ""),
        "environment": environment_id,
        "status":      "submitted",
        "message":     f"URL submitted. Use ha_get_report(job_id='{job_id}') to retrieve results in ~2 minutes.",
        "report_url":  f"https://www.hybrid-analysis.com/sample/{data.get('sha256', '')}",
    }


def ha_get_report(job_id: str) -> dict:
    """Retrieve a completed Hybrid Analysis sandbox report by job_id."""
    data = _ha_request("GET", f"/report/{job_id}/summary")
    if "error" in data:
        return data

    mitre = data.get("mitre_attcks", []) or []
    return {
        "job_id":        job_id,
        "source":        "Hybrid Analysis",
        "threat_score":  data.get("threat_score", 0),
        "verdict":       data.get("verdict", "unknown"),
        "vx_family":     data.get("vx_family", ""),
        "classification": data.get("classification_tags", []),
        "mitre_techniques": [
            {"technique": m.get("technique", ""), "id": m.get("attck_id", ""), "tactic": m.get("tactic", "")}
            for m in mitre[:15]
        ],
        "domains":        data.get("domains", [])[:20],
        "hosts":          data.get("hosts", [])[:20],
        "processes":      [
            {"name": p.get("name", ""), "pid": p.get("pid", ""), "cmd": p.get("command_line", "")}
            for p in (data.get("processes", []) or [])[:10]
        ],
        "signatures":     [
            {"name": s.get("name", ""), "severity": s.get("threat_level_human", "")}
            for s in (data.get("signatures", []) or [])[:15]
        ],
    }


TOOLS = {
    "ha_hash_search": {
        "fn": ha_hash_search,
        "description": (
            "Search Hybrid Analysis Falcon Sandbox for existing malware reports on a file hash (MD5/SHA1/SHA256). "
            "Returns threat score (0-100), AV detection rate, malware family, MITRE ATT&CK techniques, "
            "network IOCs (domains/IPs contacted). Requires HYBRID_ANALYSIS_API_KEY (free at hybrid-analysis.com)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "MD5, SHA1, or SHA256 hash to look up"}
            },
            "required": ["file_hash"]
        }
    },
    "ha_url_submit": {
        "fn": ha_url_submit,
        "description": (
            "Submit a suspicious URL to Hybrid Analysis Falcon Sandbox for dynamic behavioral analysis. "
            "Returns a job_id — use ha_get_report to retrieve results after ~2 minutes. "
            "Requires HYBRID_ANALYSIS_API_KEY (free at hybrid-analysis.com)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url":            {"type": "string",  "description": "URL to submit for analysis"},
                "environment_id": {"type": "integer", "description": "Sandbox environment: 100=Win7-32, 110=Win7-64, 120=Win10-64 (default), 300=Linux"},
            },
            "required": ["url"]
        }
    },
    "ha_get_report": {
        "fn": ha_get_report,
        "description": "Retrieve a completed Hybrid Analysis sandbox report by job_id. Returns verdict, MITRE techniques, network IOCs, process list.",
        "parameters": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID returned by ha_url_submit"}
            },
            "required": ["job_id"]
        }
    },
}
