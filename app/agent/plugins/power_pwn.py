"""
ARGOS Plugin: power-pwn — Microsoft 365 / Power Platform Pentesting
Authorized offensive security testing against M365 tenants.
Tests Power Platform, Copilot Studio, connectors, and LLM integrations.

Install:
  pip install power-pwn
  or: pip install git+https://github.com/mbrg/power-pwn

Requires: Azure AD tenant access (delegated or app-only credentials).
Set env var POWERPWN_AUTH_TOKEN or use --auth-token flag.

Repo: https://github.com/mbrg/power-pwn
"""
from __future__ import annotations
import os, subprocess, json, re
from pathlib import Path

MANIFEST = {
    "id":          "power_pwn",
    "name":        "power-pwn (M365/Power Platform Pentest)",
    "description": "Authorized pentesting of Microsoft 365, Power Platform, Copilot Studio, and LLM integrations.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TIMEOUT = 300


def _ensure_power_pwn() -> bool:
    r = subprocess.run(["powerpwn", "--help"], capture_output=True, timeout=10)
    if r.returncode == 0 or b"Usage" in r.stdout + r.stderr:
        return True
    # Try install
    inst = subprocess.run(
        ["pip3", "install", "-q", "--break-system-packages", "power-pwn"],
        capture_output=True, timeout=120
    )
    return inst.returncode == 0


def _run_powerpwn(args: list[str], timeout: int = _TIMEOUT) -> dict:
    if not _ensure_power_pwn():
        return {"error": "power-pwn not installed. Run: pip install power-pwn"}
    try:
        r = subprocess.run(
            ["powerpwn"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        output = (r.stdout + r.stderr)[-6000:]
        return {
            "returncode": r.returncode,
            "output":     output,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "powerpwn not found in PATH. Run: pip install power-pwn"}
    except Exception as e:
        return {"error": str(e)}


def power_pwn_recon(tenant: str, token: str = "") -> dict:
    """Recon a Microsoft 365 / Power Platform tenant.
    Enumerates Power Apps, Power Automate flows, connectors, and exposed resources.
    ⚠️  AUTHORIZED TESTING ONLY — requires valid tenant access.

    tenant: Azure AD tenant ID or domain (e.g. contoso.com or 00000000-0000-...)
    token: bearer token (or set POWERPWN_AUTH_TOKEN env var)
    """
    args = ["recon", "--tenant", tenant]
    if token:
        args += ["--auth-token", token]
    elif os.getenv("POWERPWN_AUTH_TOKEN"):
        args += ["--auth-token", os.getenv("POWERPWN_AUTH_TOKEN")]

    result = _run_powerpwn(args)
    result["tenant"] = tenant
    result["source"] = "power-pwn recon"
    result["note"]   = "AUTHORIZED M365 PENTEST ONLY"
    return result


def power_pwn_dump_resources(tenant: str, token: str = "") -> dict:
    """Dump all accessible Power Platform resources from a tenant.
    Extracts Power Apps, flows, connections, environment variables, and secrets.
    ⚠️  AUTHORIZED TESTING ONLY.

    tenant: Azure AD tenant ID or domain
    token: bearer token (or set POWERPWN_AUTH_TOKEN env var)
    """
    args = ["dump-resources", "--tenant", tenant]
    if token:
        args += ["--auth-token", token]
    elif os.getenv("POWERPWN_AUTH_TOKEN"):
        args += ["--auth-token", os.getenv("POWERPWN_AUTH_TOKEN")]

    result = _run_powerpwn(args)
    result["tenant"] = tenant
    result["source"] = "power-pwn dump-resources"
    result["note"]   = "AUTHORIZED M365 PENTEST ONLY"
    return result


def power_pwn_copilot_hunter(tenant: str, token: str = "") -> dict:
    """Hunt for exposed Microsoft Copilot Studio bots in a tenant.
    Finds publicly accessible bots, unauthenticated endpoints, and data leakage.
    ⚠️  AUTHORIZED TESTING ONLY.

    tenant: Azure AD tenant ID or domain
    token: bearer token (or set POWERPWN_AUTH_TOKEN env var)
    """
    args = ["copilot-studio-hunter", "--tenant", tenant]
    if token:
        args += ["--auth-token", token]
    elif os.getenv("POWERPWN_AUTH_TOKEN"):
        args += ["--auth-token", os.getenv("POWERPWN_AUTH_TOKEN")]

    result = _run_powerpwn(args)
    result["tenant"] = tenant
    result["source"] = "power-pwn copilot-studio-hunter"
    result["note"]   = "AUTHORIZED COPILOT SECURITY ASSESSMENT ONLY"
    return result


def power_pwn_llm_hound(tenant: str, token: str = "") -> dict:
    """Test LLM integrations and AI assistants in a Power Platform tenant.
    Checks for prompt injection, data exfiltration, and LLM security misconfigurations.
    ⚠️  AUTHORIZED TESTING ONLY.

    tenant: Azure AD tenant ID or domain
    token: bearer token (or set POWERPWN_AUTH_TOKEN env var)
    """
    args = ["llm-hound", "--tenant", tenant]
    if token:
        args += ["--auth-token", token]
    elif os.getenv("POWERPWN_AUTH_TOKEN"):
        args += ["--auth-token", os.getenv("POWERPWN_AUTH_TOKEN")]

    result = _run_powerpwn(args)
    result["tenant"] = tenant
    result["source"] = "power-pwn llm-hound"
    result["note"]   = "AUTHORIZED LLM SECURITY TESTING ONLY"
    return result


def power_pwn_tenant_mcp_recon(tenant: str, token: str = "") -> dict:
    """Enumerate MCP (Model Context Protocol) servers in a tenant.
    Finds MCP integrations, exposed tools, and AI pipeline attack surface.
    ⚠️  AUTHORIZED TESTING ONLY.

    tenant: Azure AD tenant ID or domain
    token: bearer token (or set POWERPWN_AUTH_TOKEN env var)
    """
    args = ["tenant-mcp-recon", "--tenant", tenant]
    if token:
        args += ["--auth-token", token]
    elif os.getenv("POWERPWN_AUTH_TOKEN"):
        args += ["--auth-token", os.getenv("POWERPWN_AUTH_TOKEN")]

    result = _run_powerpwn(args)
    result["tenant"] = tenant
    result["source"] = "power-pwn tenant-mcp-recon"
    result["note"]   = "AUTHORIZED MCP SECURITY ASSESSMENT ONLY"
    return result


def power_pwn_full_assessment(tenant: str, token: str = "") -> dict:
    """Full Power Platform security assessment: recon + copilot hunt + LLM testing.
    ⚠️  AUTHORIZED PENTESTING ONLY.

    Runs: recon → copilot-studio-hunter → llm-hound
    Returns aggregated findings.
    """
    results = {}
    results["recon"]          = power_pwn_recon(tenant, token)
    results["copilot_hunter"] = power_pwn_copilot_hunter(tenant, token)
    results["llm_hound"]      = power_pwn_llm_hound(tenant, token)

    errors = [k for k, v in results.items() if "error" in v]
    return {
        "tenant":    tenant,
        "source":    "power-pwn Full Assessment",
        "tests_run": len(results),
        "errors":    errors,
        "results":   results,
        "note":      "AUTHORIZED M365/POWER PLATFORM PENTEST ONLY",
    }


TOOLS = {
    "power_pwn_recon": {
        "fn": power_pwn_recon,
        "description": (
            "Recon a Microsoft 365 / Power Platform tenant. "
            "Enumerates Power Apps, flows, connectors, and exposed resources. "
            "⚠️ AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain (e.g. contoso.com)"},
                "token":  {"type": "string", "description": "Bearer token (or set POWERPWN_AUTH_TOKEN env var)"},
            },
            "required": ["tenant"]
        }
    },
    "power_pwn_dump_resources": {
        "fn": power_pwn_dump_resources,
        "description": (
            "Dump all accessible Power Platform resources: Power Apps, flows, connections, secrets. "
            "⚠️ AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain"},
                "token":  {"type": "string", "description": "Bearer token"},
            },
            "required": ["tenant"]
        }
    },
    "power_pwn_copilot_hunter": {
        "fn": power_pwn_copilot_hunter,
        "description": (
            "Hunt for exposed Microsoft Copilot Studio bots: unauthenticated endpoints, data leakage. "
            "⚠️ AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain"},
                "token":  {"type": "string", "description": "Bearer token"},
            },
            "required": ["tenant"]
        }
    },
    "power_pwn_llm_hound": {
        "fn": power_pwn_llm_hound,
        "description": (
            "Test LLM integrations in Power Platform: prompt injection, data exfiltration, AI misconfigs. "
            "⚠️ AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain"},
                "token":  {"type": "string", "description": "Bearer token"},
            },
            "required": ["tenant"]
        }
    },
    "power_pwn_tenant_mcp_recon": {
        "fn": power_pwn_tenant_mcp_recon,
        "description": (
            "Enumerate MCP (Model Context Protocol) servers in a tenant. "
            "Finds AI pipeline attack surface and exposed tools. "
            "⚠️ AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain"},
                "token":  {"type": "string", "description": "Bearer token"},
            },
            "required": ["tenant"]
        }
    },
    "power_pwn_full_assessment": {
        "fn": power_pwn_full_assessment,
        "description": (
            "Full Power Platform security assessment: recon + copilot-studio-hunter + llm-hound. "
            "Returns aggregated findings for M365/Power Platform pentesting. "
            "⚠️ AUTHORIZED PENTESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tenant": {"type": "string", "description": "Azure AD tenant ID or domain"},
                "token":  {"type": "string", "description": "Bearer token"},
            },
            "required": ["tenant"]
        }
    },
}
