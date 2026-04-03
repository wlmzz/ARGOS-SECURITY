"""
ARGOS Plugin: SpiderFoot — OSINT Automation Platform
400+ intelligence modules targeting IPs, domains, emails, names, phones, usernames.
Integrates with Shodan, VirusTotal, HaveIBeenPwned, Censys, GreyNoise, PassiveTotal, etc.

Run modes:
  1. CLI (no server): python3 sf.py -s <target> -t <modules> -o json -q
  2. REST API (if server running): http://localhost:5001/api/v1/scan

Auto-installs to /opt/argos/tools/spiderfoot/
Env vars:
  SPIDERFOOT_URL   = http://localhost:5001  (if running as server)
  SPIDERFOOT_KEY   = API key (if configured)

Repo: https://github.com/smicallef/spiderfoot (wlmzz/spiderfoot)
"""
from __future__ import annotations
import os, subprocess, json, time, urllib.request, urllib.error
from pathlib import Path

MANIFEST = {
    "id":          "spiderfoot",
    "name":        "SpiderFoot OSINT Platform",
    "description": "400+ OSINT modules: IPs, domains, emails, usernames, phones. Shodan/VT/HaveIBeenPwned/Censys integration.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_SF_DIR  = Path("/opt/argos/tools/spiderfoot")
_TIMEOUT = 300


def _ensure_spiderfoot() -> bool:
    if (_SF_DIR / "sf.py").exists():
        return True
    _SF_DIR.parent.mkdir(parents=True, exist_ok=True)
    for repo in ["wlmzz/spiderfoot", "smicallef/spiderfoot"]:
        r = subprocess.run(
            ["git", "clone", "--depth=1", "-q",
             f"https://github.com/{repo}.git", str(_SF_DIR)],
            capture_output=True, timeout=180
        )
        if r.returncode == 0:
            req = _SF_DIR / "requirements.txt"
            if req.exists():
                subprocess.run(
                    ["pip3", "install", "-q", "--break-system-packages", "-r", str(req)],
                    capture_output=True, timeout=180
                )
            return (_SF_DIR / "sf.py").exists()
    return False


def _sf_base() -> str:
    return os.getenv("SPIDERFOOT_URL", "http://localhost:5001").rstrip("/")


def _sf_api_get(path: str) -> dict:
    key = os.getenv("SPIDERFOOT_KEY", "")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(f"{_sf_base()}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def _sf_api_post(path: str, data: dict) -> dict:
    key = os.getenv("SPIDERFOOT_KEY", "")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    from urllib.parse import urlencode
    body = urlencode(data).encode()
    req = urllib.request.Request(f"{_sf_base()}{path}", data=body,
                                  headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def spiderfoot_scan(target: str, modules: str = "ALL",
                     output_format: str = "json",
                     timeout: int = _TIMEOUT) -> dict:
    """Run a SpiderFoot OSINT scan against a target.
    Uses CLI mode (no server needed) or REST API if SPIDERFOOT_URL is set.

    target:        IP, domain, email, username, phone, or person name
    modules:       'ALL' or comma-separated module types:
                   DOMAIN, IP, EMAIL, PHONE, USERNAME, PERSON, NETBLOCK, etc.
    output_format: 'json' | 'csv' (default: json)
    """
    # Try REST API first if configured
    api_url = os.getenv("SPIDERFOOT_URL", "")
    if api_url and api_url != "http://localhost:5001":
        result = _sf_api_post("/api/v1/scan", {
            "scanname": f"ARGOS-{target[:20]}",
            "scantarget": target,
            "modulelist": modules,
            "typelist": "",
            "usecase": "all",
        })
        if "id" in result or "scanId" in result:
            scan_id = result.get("id", result.get("scanId", ""))
            return {
                "target":   target,
                "scan_id":  scan_id,
                "source":   "SpiderFoot API",
                "status":   "running",
                "message":  f"Use spiderfoot_scan_results(scan_id='{scan_id}') to get results",
            }

    # CLI mode
    if not _ensure_spiderfoot():
        return {"error": "Failed to install SpiderFoot"}

    output_file = f"/tmp/sf_{target.replace('/', '_').replace(':', '_')}.json"

    # Map module types to SpiderFoot module groups
    module_flag = []
    if modules.upper() == "ALL":
        module_flag = ["-t", "ALL"]
    else:
        module_flag = ["-t", modules]

    cmd = [
        "python3", str(_SF_DIR / "sf.py"),
        "-s", target,
    ] + module_flag + [
        "-o", output_format,
        "-q",  # quiet mode
        "-l", output_file,
    ]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(_SF_DIR)
        )
        output = (r.stdout + r.stderr)[-2000:]

        result = {
            "target":  target,
            "source":  "SpiderFoot CLI",
            "modules": modules,
            "output":  output,
        }

        # Try to parse JSON output
        if Path(output_file).exists():
            try:
                data = json.loads(Path(output_file).read_text())
                if isinstance(data, list):
                    result["findings_count"] = len(data)
                    result["findings"] = data[:50]
                else:
                    result["raw"] = data
            except Exception:
                pass

        return result

    except subprocess.TimeoutExpired:
        return {"error": f"SpiderFoot scan timed out after {timeout}s", "target": target}
    except Exception as e:
        return {"error": str(e)}


def spiderfoot_scan_results(scan_id: str) -> dict:
    """Get results from a running or completed SpiderFoot API scan.

    scan_id: scan ID from spiderfoot_scan() when using API mode
    """
    status = _sf_api_get(f"/api/v1/scan/{scan_id}/status")
    results = _sf_api_get(f"/api/v1/scan/{scan_id}/results")

    findings = results if isinstance(results, list) else results.get("data", [])

    return {
        "scan_id":        scan_id,
        "source":         "SpiderFoot API",
        "status":         status.get("status", "unknown") if isinstance(status, dict) else status,
        "findings_count": len(findings),
        "findings":       findings[:50],
    }


def spiderfoot_list_modules() -> dict:
    """List all available SpiderFoot intelligence modules."""
    if not _ensure_spiderfoot():
        return {"error": "Failed to install SpiderFoot"}

    try:
        r = subprocess.run(
            ["python3", str(_SF_DIR / "sf.py"), "-M"],
            capture_output=True, text=True, timeout=30,
            cwd=str(_SF_DIR)
        )
        return {
            "source":  "SpiderFoot",
            "modules": (r.stdout + r.stderr)[:5000],
            "usage":   "Pass module names to spiderfoot_scan(modules='sfp_shodan,sfp_virustotal')",
        }
    except Exception as e:
        return {"error": str(e)}


TOOLS = {
    "spiderfoot_scan": {
        "fn": spiderfoot_scan,
        "description": (
            "SpiderFoot OSINT scan: 400+ modules for IPs, domains, emails, usernames, phones. "
            "Integrates Shodan, VirusTotal, HaveIBeenPwned, Censys, GreyNoise. "
            "CLI mode (no server) or REST API (set SPIDERFOOT_URL)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":  {"type": "string",  "description": "IP, domain, email, username, phone, or person name"},
                "modules": {"type": "string",  "description": "'ALL' or module names (sfp_shodan, sfp_virustotal, etc.)"},
                "timeout": {"type": "integer", "description": "Max seconds (default: 300)"},
            },
            "required": ["target"]
        }
    },
    "spiderfoot_scan_results": {
        "fn": spiderfoot_scan_results,
        "description": "Get results from a SpiderFoot API scan by scan ID.",
        "parameters": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID from spiderfoot_scan()"},
            },
            "required": ["scan_id"]
        }
    },
    "spiderfoot_list_modules": {
        "fn": spiderfoot_list_modules,
        "description": "List all available SpiderFoot intelligence modules.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
}
