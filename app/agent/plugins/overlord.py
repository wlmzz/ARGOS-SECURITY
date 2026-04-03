"""
ARGOS Plugin: overlord — Red Team Infrastructure Automation
Automated provisioning and management of red team infrastructure using
Terraform + Ansible. Deploy redirectors, C2 servers, phishing infrastructure,
and attack boxes with a single command.

⚠️  AUTHORIZED RED TEAM / PENETRATION TESTING ONLY.

Install:
  git clone https://github.com/calebstewart/overlord
  pip install -r requirements.txt
  # Requires: Terraform, Ansible, cloud provider credentials (AWS/DO/GCP)

Auto-installs to /opt/argos/tools/overlord/
Repo: https://github.com/qsecure-labs/overlord
"""
from __future__ import annotations
import os, subprocess, json, re
from pathlib import Path

MANIFEST = {
    "id":          "overlord",
    "name":        "overlord (Red Team Infra)",
    "description": "Red team infrastructure automation: deploy C2 servers, redirectors, phishing infra via Terraform+Ansible. PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_OVERLORD_DIR = Path("/opt/argos/tools/overlord")
_TIMEOUT      = 300


def _ensure_overlord() -> bool:
    if _OVERLORD_DIR.exists() and (_OVERLORD_DIR / "overlord.py").exists():
        return True
    _OVERLORD_DIR.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         "https://github.com/qsecure-labs/overlord.git", str(_OVERLORD_DIR)],
        capture_output=True, timeout=120
    )
    if r.returncode == 0 and (_OVERLORD_DIR / "requirements.txt").exists():
        subprocess.run(
            ["pip3", "install", "-q", "--break-system-packages",
             "-r", str(_OVERLORD_DIR / "requirements.txt")],
            capture_output=True, timeout=120
        )
    return r.returncode == 0


def _run_overlord(cmd_args: list, timeout: int = _TIMEOUT,
                   input_str: str = "") -> dict:
    if not _ensure_overlord():
        return {"error": "Failed to install overlord"}

    script = _OVERLORD_DIR / "overlord.py"
    if not script.exists():
        return {"error": "overlord.py not found in cloned repo"}

    try:
        r = subprocess.run(
            ["python3", str(script)] + cmd_args,
            input=input_str if input_str else None,
            capture_output=True, text=True, timeout=timeout,
            cwd=str(_OVERLORD_DIR)
        )
        return {
            "returncode": r.returncode,
            "output":     (r.stdout + r.stderr)[-5000:],
        }
    except subprocess.TimeoutExpired:
        return {"error": f"overlord timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def overlord_list_modules() -> dict:
    """List available overlord red team infrastructure modules.
    Shows available deployment templates (C2, redirectors, phishing, etc.)
    ⚠️  AUTHORIZED RED TEAM ONLY.
    """
    result = _run_overlord(["--help"], timeout=30)
    result["source"] = "overlord"
    result["note"]   = "AUTHORIZED RED TEAM ONLY"

    # Known modules from overlord docs
    result["known_modules"] = [
        "c2           — Deploy C2 server (Cobalt Strike, Metasploit, etc.)",
        "redirector   — HTTP/HTTPS redirector with mod_rewrite",
        "phishing     — Phishing infrastructure (Gophish, Evilginx2)",
        "attack_box   — Kali/ParrotOS attack box on cloud",
        "smtp_relay   — SMTP relay for phishing campaigns",
        "ssl_cert     — Let's Encrypt SSL certificate automation",
        "dns_c2       — DNS-based C2 channel infrastructure",
    ]
    return result


def overlord_deploy(module: str, provider: str = "digitalocean",
                    region: str = "nyc1",
                    extra_vars: dict = None,
                    dry_run: bool = True) -> dict:
    """Deploy red team infrastructure using overlord.
    ⚠️  AUTHORIZED RED TEAM ONLY — deploys real cloud resources.

    module:    infrastructure type: c2, redirector, phishing, attack_box
    provider:  cloud provider: digitalocean, aws, gcp (default: digitalocean)
    region:    deployment region (default: nyc1)
    extra_vars: additional Terraform/Ansible variables
    dry_run:   show plan without deploying (default: true — set false to actually deploy)
    """
    if extra_vars is None:
        extra_vars = {}

    args = [
        "--module", module,
        "--provider", provider,
        "--region", region,
    ]

    if dry_run:
        args.append("--plan")

    for k, v in extra_vars.items():
        args += ["--var", f"{k}={v}"]

    result = _run_overlord(args, timeout=_TIMEOUT)
    result["module"]   = module
    result["provider"] = provider
    result["region"]   = region
    result["dry_run"]  = dry_run
    result["source"]   = "overlord"
    result["note"]     = "AUTHORIZED RED TEAM ONLY"

    if dry_run:
        result["warning"] = "dry_run=True — set dry_run=False to actually deploy cloud resources"

    return result


def overlord_destroy(module: str, provider: str = "digitalocean",
                      region: str = "nyc1") -> dict:
    """Destroy overlord-deployed infrastructure (cleanup after engagement).
    ⚠️  AUTHORIZED RED TEAM ONLY.

    module:   the module that was deployed
    provider: cloud provider
    region:   deployment region
    """
    result = _run_overlord([
        "--module", module,
        "--provider", provider,
        "--region",  region,
        "--destroy",
    ], timeout=_TIMEOUT)
    result["action"]   = "destroy"
    result["module"]   = module
    result["provider"] = provider
    result["source"]   = "overlord"
    result["note"]     = "AUTHORIZED RED TEAM ONLY"
    return result


def overlord_status() -> dict:
    """Check status of deployed overlord infrastructure.
    ⚠️  AUTHORIZED RED TEAM ONLY.
    """
    result = _run_overlord(["--status"], timeout=60)
    result["source"] = "overlord"
    result["note"]   = "AUTHORIZED RED TEAM ONLY"
    return result


TOOLS = {
    "overlord_list_modules": {
        "fn": overlord_list_modules,
        "description": (
            "List overlord red team infrastructure modules: C2 servers, redirectors, "
            "phishing infra, attack boxes. ⚠️ AUTHORIZED RED TEAM ONLY."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "overlord_deploy": {
        "fn": overlord_deploy,
        "description": (
            "Deploy red team infrastructure (C2, redirector, phishing, attack box) "
            "via Terraform+Ansible. Use dry_run=True (default) to see plan first. "
            "⚠️ AUTHORIZED RED TEAM ONLY — deploys real cloud resources."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "module":     {"type": "string",  "description": "Module: c2, redirector, phishing, attack_box, smtp_relay"},
                "provider":   {"type": "string",  "description": "Cloud provider: digitalocean, aws, gcp (default: digitalocean)"},
                "region":     {"type": "string",  "description": "Cloud region (default: nyc1)"},
                "extra_vars": {"type": "object",  "description": "Additional Terraform/Ansible variables"},
                "dry_run":    {"type": "boolean", "description": "Show plan only, don't deploy (default: true)"},
            },
            "required": ["module"]
        }
    },
    "overlord_destroy": {
        "fn": overlord_destroy,
        "description": (
            "Destroy overlord-deployed infrastructure. Clean up cloud resources after engagement. "
            "⚠️ AUTHORIZED RED TEAM ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "module":   {"type": "string", "description": "Module that was deployed"},
                "provider": {"type": "string", "description": "Cloud provider (default: digitalocean)"},
                "region":   {"type": "string", "description": "Region (default: nyc1)"},
            },
            "required": ["module"]
        }
    },
    "overlord_status": {
        "fn": overlord_status,
        "description": "Check status of deployed overlord red team infrastructure. ⚠️ AUTHORIZED RED TEAM ONLY.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
}
