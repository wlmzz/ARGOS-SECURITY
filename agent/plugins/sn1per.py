"""
ARGOS Plugin: Sn1per
Automated attack surface management and recon framework by 1N3.
Wraps the `sniper` CLI — install first:
  bash <(curl -sL https://raw.githubusercontent.com/1N3/Sn1per/master/install.sh)
Results are saved to /usr/share/sniper/loot/<workspace>/

Repo: https://github.com/1N3/Sn1per
"""
from __future__ import annotations
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

MANIFEST = {
    "id":          "sn1per",
    "name":        "Sn1per",
    "description": "Automated attack surface management: recon, port scan, web scan, subdomain enum, vuln detection. Requires sniper CLI.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_LOOT_DIR = Path("/usr/share/sniper/loot")


def _check_sniper() -> bool:
    return subprocess.run(["which", "sniper"], capture_output=True).returncode == 0


def _read_loot(workspace: str) -> dict:
    """Read key output files from the sniper loot directory."""
    loot_path = _LOOT_DIR / workspace
    if not loot_path.exists():
        return {}

    results: dict = {}

    # Read ports file
    for fname in ["ports.txt", "open_ports.txt"]:
        p = loot_path / fname
        if p.exists():
            results["ports"] = p.read_text(errors="replace")[:3000]
            break

    # Read web findings
    for fname in ["web.txt", "http.txt"]:
        p = loot_path / fname
        if p.exists():
            results["web"] = p.read_text(errors="replace")[:3000]
            break

    # Read subdomains
    for fname in ["subdomains.txt", "dns.txt"]:
        p = loot_path / fname
        if p.exists():
            content = p.read_text(errors="replace")
            results["subdomains"] = [ln.strip() for ln in content.splitlines() if ln.strip()][:50]
            break

    # Read vulnerabilities/findings
    for fname in ["vuln.txt", "findings.txt", "nuclei.txt"]:
        p = loot_path / fname
        if p.exists():
            results["findings"] = p.read_text(errors="replace")[:5000]
            break

    # Read all .txt files summary
    txt_files = list(loot_path.glob("*.txt"))
    results["files_found"] = [f.name for f in txt_files]

    return results


def sn1per_scan(target: str, mode: str = "normal", workspace: str = "", timeout: int = 600) -> dict:
    """Run a Sn1per automated recon/attack surface scan on a target.
    AUTHORIZED TARGETS ONLY — only use on systems you own or have explicit written permission to test.

    Modes:
      normal   — standard port scan + service fingerprint (default)
      stealth  — passive, avoids triggering IDS/WAF
      web      — HTTP/HTTPS web app scan only
      discover — CIDR network discovery (use target=192.168.0.0/24)
      fullportonly — full 65535-port scan

    workspace: short alias for results (auto-generated if empty)
    timeout: max seconds to wait (default 600)
    """
    if not _check_sniper():
        return {
            "error": (
                "sniper not found. Install with: "
                "bash <(curl -sL https://raw.githubusercontent.com/1N3/Sn1per/master/install.sh)"
            )
        }

    valid_modes = {"normal", "stealth", "web", "discover", "fullportonly", "webscan"}
    if mode not in valid_modes:
        return {"error": f"Invalid mode. Choose from: {sorted(valid_modes)}"}

    # Sanitize inputs
    if not re.match(r"^[a-zA-Z0-9.\-/]+$", target):
        return {"error": "Invalid target format"}
    if not workspace:
        workspace = f"argos_{int(time.time())}"
    workspace = re.sub(r"[^a-zA-Z0-9_\-]", "_", workspace)

    cmd = ["sniper", "-t", target, "-m", mode, "-w", workspace]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        stdout = proc.stdout[-5000:] if proc.stdout else ""
        stderr = proc.stderr[-2000:] if proc.stderr else ""
    except subprocess.TimeoutExpired:
        return {
            "target":    target,
            "mode":      mode,
            "workspace": workspace,
            "status":    "timeout",
            "message":   f"Scan timed out after {timeout}s. Partial results may be in loot dir.",
            "loot_path": str(_LOOT_DIR / workspace),
        }
    except Exception as e:
        return {"error": str(e)}

    loot = _read_loot(workspace)

    return {
        "target":       target,
        "mode":         mode,
        "workspace":    workspace,
        "source":       "Sn1per",
        "exit_code":    proc.returncode,
        "loot_path":    str(_LOOT_DIR / workspace),
        "output_tail":  stdout,
        **loot,
    }


TOOLS = {
    "sn1per_scan": {
        "fn": sn1per_scan,
        "description": (
            "Run Sn1per automated recon and attack surface scan on a target. "
            "Combines nmap, whatweb, nikto, nuclei, subdomain enum, and more. "
            "Modes: normal, stealth, web, discover (CIDR), fullportonly. "
            "AUTHORIZED TARGETS ONLY. Requires sniper CLI installed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":    {"type": "string",  "description": "Target IP, hostname, or CIDR (e.g. '10.0.0.1' or '10.0.0.0/24')"},
                "mode":      {"type": "string",  "description": "Scan mode: normal (default), stealth, web, discover, fullportonly"},
                "workspace": {"type": "string",  "description": "Workspace name for organizing results (auto-generated if empty)"},
                "timeout":   {"type": "integer", "description": "Max seconds to wait for scan completion (default: 600)"},
            },
            "required": ["target"]
        }
    },
}
