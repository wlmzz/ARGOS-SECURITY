"""
ARGOS Plugin — Nikto Web Vulnerability Scanner
Wraps the `nikto` CLI tool and parses its JSON output.
Only stdlib + subprocess. Timeout = 120 s per scan.
"""

import subprocess
import json
import os
import shutil
import tempfile
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "nikto",
    "name": "Nikto Web Scanner",
    "description": (
        "Web-server vulnerability scanner powered by Nikto. "
        "Detects outdated software, dangerous files, misconfigurations, "
        "missing security headers, and known CVEs."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TUNING_LABELS = {
    "0": "File Upload",
    "1": "Interesting File",
    "2": "Misconfiguration",
    "3": "Information Disclosure",
    "4": "Injection",
    "5": "Remote File Retrieval (inside web root)",
    "6": "Denial of Service",
    "7": "Remote File Retrieval (server-wide)",
    "8": "Command Execution",
    "9": "SQL Injection",
    "a": "Authentication Bypass",
    "b": "Software Identification",
    "c": "Remote Source Inclusion",
    "x": "Reverse Tuning (all except selected)",
}

_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
]


def _nikto_available() -> bool:
    return shutil.which("nikto") is not None


def _run_nikto(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run nikto with the supplied argument list; return (returncode, stdout, stderr)."""
    cmd = ["nikto"] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Nikto scan timed out after {} seconds.".format(timeout)
    except FileNotFoundError:
        return -1, "", "nikto binary not found."


def _parse_nikto_json(json_path: str) -> dict[str, Any]:
    """
    Parse the JSON output file produced by nikto -Format json.
    Nikto's JSON schema wraps everything in a top-level key; handle both
    the wrapped and unwrapped variants gracefully.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            return {}
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return {"parse_error": str(exc)}

    # Some nikto versions wrap output: {"nikto": {"host": [...], ...}}
    if "nikto" in data:
        data = data["nikto"]

    return data


def _extract_vulnerabilities(parsed: dict) -> tuple[list, str, dict]:
    """
    Return (vuln_list, server_banner, headers_dict) from parsed nikto JSON.
    Handles both single-host and multi-host output shapes.
    """
    vulns: list[dict] = []
    server = ""
    headers: dict[str, str] = {}

    # nikto JSON uses a 'host' list at the top level
    hosts = parsed.get("host", [parsed]) if isinstance(parsed, dict) else [parsed]

    for host_block in hosts:
        if not isinstance(host_block, dict):
            continue
        server = server or host_block.get("banner", host_block.get("server", ""))

        # Headers are sometimes reported as a nested dict
        if "headers" in host_block and isinstance(host_block["headers"], dict):
            headers.update(host_block["headers"])

        items = host_block.get("vulnerabilities", host_block.get("items", []))
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            # Normalize field names across nikto versions
            vuln = {
                "id": item.get("id", item.get("OSVDBID", "")),
                "method": item.get("method", item.get("HTTP_method", "GET")),
                "url": item.get("url", item.get("URI", "")),
                "description": item.get("msg", item.get("description", "")),
                "osvdb": item.get("OSVDB", ""),
                "references": item.get("references", []),
            }
            # Infer header info from description when headers dict is absent
            for hdr in _SECURITY_HEADERS:
                if hdr.lower() in vuln["description"].lower():
                    if "missing" in vuln["description"].lower():
                        if hdr not in headers:
                            headers[hdr] = "MISSING"
            vulns.append(vuln)

    return vulns, server, headers


def _group_by_type(vulns: list[dict]) -> dict[str, int]:
    by_type: dict[str, int] = {}
    for v in vulns:
        desc = v.get("description", "").lower()
        matched = False
        for code, label in _TUNING_LABELS.items():
            if any(kw in desc for kw in label.lower().split()):
                by_type[label] = by_type.get(label, 0) + 1
                matched = True
                break
        if not matched:
            by_type["Other"] = by_type.get("Other", 0) + 1
    return by_type


def _score_headers(missing: list[str], present: list[str]) -> str:
    total = len(_SECURITY_HEADERS)
    present_count = len(present)
    ratio = present_count / total if total else 0
    if ratio >= 0.90:
        return "A"
    if ratio >= 0.75:
        return "B"
    if ratio >= 0.50:
        return "C"
    if ratio >= 0.25:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def nikto_scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    tuning: str = "",
    output_format: str = "json",
) -> dict:
    """
    Run a full Nikto scan against a single target.

    Parameters
    ----------
    target : str
        Hostname or IP address to scan.
    port : int
        TCP port (default 80).
    ssl : bool
        Enable SSL/TLS scanning (equivalent to -ssl flag).
    tuning : str
        Nikto tuning code(s): 0–9, a–c, x (see TUNING_LABELS).
    output_format : str
        Currently always 'json'; reserved for future use.
    """
    if not _nikto_available():
        return {
            "error": (
                "nikto not installed. "
                "Install: sudo apt install nikto  OR  brew install nikto"
            )
        }

    out_file = tempfile.mktemp(suffix=".json", prefix="nikto_")
    try:
        args = [
            "-h", target,
            "-p", str(port),
            "-Format", "json",
            "-output", out_file,
            "-nointeractive",
        ]
        if ssl:
            args.append("-ssl")
        if tuning:
            args += ["-Tuning", tuning]

        rc, stdout, stderr = _run_nikto(args, timeout=120)

        parsed: dict[str, Any] = {}
        if os.path.exists(out_file):
            parsed = _parse_nikto_json(out_file)

        # Fall back to stdout if file is empty / missing
        if not parsed and stdout.strip():
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                parsed = {"raw_output": stdout}

        if "parse_error" in parsed:
            return {"error": parsed["parse_error"], "stderr": stderr}

        vulns, server, headers = _extract_vulnerabilities(parsed)
        by_type = _group_by_type(vulns)

        return {
            "target": target,
            "port": port,
            "ssl": ssl,
            "tuning": tuning or "none",
            "vulnerabilities": vulns,
            "total": len(vulns),
            "by_type": by_type,
            "server": server,
            "headers": headers,
            "scan_exit_code": rc,
            "stderr": stderr if rc not in (0, 1) else "",
        }
    finally:
        if os.path.exists(out_file):
            os.remove(out_file)


def nikto_scan_multiple(targets: list, port: int = 80) -> dict:
    """
    Scan a list of targets sequentially and aggregate results.

    Parameters
    ----------
    targets : list[str]
        List of hostnames or IP addresses.
    port : int
        TCP port to use for all targets (default 80).
    """
    if not _nikto_available():
        return {
            "error": (
                "nikto not installed. "
                "Install: sudo apt install nikto  OR  brew install nikto"
            )
        }

    if not targets:
        return {"error": "No targets provided."}

    results: dict[str, dict] = {}
    total_vulns = 0

    for target in targets:
        res = nikto_scan(target=str(target), port=port)
        results[str(target)] = res
        total_vulns += res.get("total", 0)

    most_vulnerable = max(
        results,
        key=lambda t: results[t].get("total", 0),
        default="",
    )

    return {
        "results": results,
        "total_vulns": total_vulns,
        "most_vulnerable": most_vulnerable,
        "targets_scanned": len(targets),
    }


def nikto_check_headers(target: str) -> dict:
    """
    Focused scan that checks for missing HTTP security headers.

    Parameters
    ----------
    target : str
        Hostname or IP address to scan.
    """
    if not _nikto_available():
        return {
            "error": (
                "nikto not installed. "
                "Install: sudo apt install nikto  OR  brew install nikto"
            )
        }

    # tuning "b" = Software Identification — also surfaces header-related findings
    out_file = tempfile.mktemp(suffix=".json", prefix="nikto_hdr_")
    try:
        args = [
            "-h", target,
            "-Format", "json",
            "-output", out_file,
            "-Tuning", "b",
            "-nointeractive",
        ]
        rc, stdout, stderr = _run_nikto(args, timeout=120)

        parsed: dict[str, Any] = {}
        if os.path.exists(out_file):
            parsed = _parse_nikto_json(out_file)
        if not parsed and stdout.strip():
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                parsed = {}

        vulns, server, headers_from_scan = _extract_vulnerabilities(parsed)

        # Build header presence map from scan findings
        header_status: dict[str, str] = {}
        for hdr in _SECURITY_HEADERS:
            # Mark as present unless nikto flagged it as missing
            header_status[hdr] = headers_from_scan.get(hdr, "PRESENT")

        # Cross-check via nikto vulnerability descriptions
        for vuln in vulns:
            desc = vuln.get("description", "")
            for hdr in _SECURITY_HEADERS:
                if hdr.lower() in desc.lower() and "missing" in desc.lower():
                    header_status[hdr] = "MISSING"

        missing = [h for h, s in header_status.items() if s == "MISSING"]
        present = [h for h, s in header_status.items() if s != "MISSING"]
        score = _score_headers(missing, present)

        return {
            "target": target,
            "missing_headers": missing,
            "present_headers": present,
            "header_details": header_status,
            "score": score,
            "server": server,
            "total_findings": len(vulns),
            "scan_exit_code": rc,
        }
    finally:
        if os.path.exists(out_file):
            os.remove(out_file)


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------
TOOLS = {
    "nikto_scan": {
        "fn": nikto_scan,
        "description": (
            "Run a full Nikto web vulnerability scan against a single host. "
            "Returns detected vulnerabilities grouped by type, server banner, "
            "and HTTP header information."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname or IP address of the target web server.",
                },
                "port": {
                    "type": "integer",
                    "description": "TCP port to scan (default 80).",
                    "default": 80,
                },
                "ssl": {
                    "type": "boolean",
                    "description": "Enable SSL/TLS mode (-ssl flag). Default false.",
                    "default": False,
                },
                "tuning": {
                    "type": "string",
                    "description": (
                        "Nikto tuning code(s) to restrict scan type. "
                        "0=File Upload, 1=Interesting File, 2=Misconfiguration, "
                        "3=Info Disclosure, 4=Injection, 5=Remote File Retrieval, "
                        "6=DoS, 7=Remote File Retrieval (server-wide), "
                        "8=Command Execution, 9=SQL Injection, "
                        "a=Auth Bypass, b=Software ID, c=Remote Source Inclusion, "
                        "x=Reverse Tuning. Leave empty for all checks."
                    ),
                    "default": "",
                },
                "output_format": {
                    "type": "string",
                    "description": "Output format (currently only 'json' supported).",
                    "default": "json",
                },
            },
            "required": ["target"],
        },
    },
    "nikto_scan_multiple": {
        "fn": nikto_scan_multiple,
        "description": (
            "Scan a list of targets sequentially with Nikto. "
            "Returns aggregated results and identifies the most vulnerable host."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hostnames or IP addresses to scan.",
                },
                "port": {
                    "type": "integer",
                    "description": "TCP port to use for all targets (default 80).",
                    "default": 80,
                },
            },
            "required": ["targets"],
        },
    },
    "nikto_check_headers": {
        "fn": nikto_check_headers,
        "description": (
            "Focused Nikto scan that checks for missing HTTP security headers "
            "(HSTS, CSP, X-Frame-Options, etc.) and grades the target A–F."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname or IP address of the target web server.",
                },
            },
            "required": ["target"],
        },
    },
}
