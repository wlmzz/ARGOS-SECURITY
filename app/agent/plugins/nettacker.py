"""
ARGOS Plugin: OWASP Nettacker — Automated Penetration Testing Framework
Multi-threaded scanning: port scan, subdomain enum, directory brute, vuln scan,
SSL testing, CMS detection, and 200+ scan modules.

⚠️  AUTHORIZED PENETRATION TESTING ONLY.

Install: pip install owasp-nettacker
  or:    git clone https://github.com/OWASP/Nettacker && pip install -r requirements.txt

Optional REST API: python3 -m owasp_nettacker --start-api-server --api-port 5000

Repo: https://github.com/OWASP/Nettacker
"""
from __future__ import annotations
import os, subprocess, json, re, tempfile
from pathlib import Path

MANIFEST = {
    "id":          "nettacker",
    "name":        "OWASP Nettacker",
    "description": "OWASP automated pentest framework: port scan, subdomain, dir brute, vuln scan, 200+ modules. PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_NETTACKER_DIR = Path("/opt/argos/tools/nettacker")
_TIMEOUT       = 600


def _ensure_nettacker() -> bool:
    # Check if installed as package
    r = subprocess.run(
        ["python3", "-m", "owasp_nettacker", "--version"],
        capture_output=True, timeout=15
    )
    if r.returncode == 0:
        return True
    # Install via pip
    inst = subprocess.run(
        ["pip3", "install", "-q", "--break-system-packages", "owasp-nettacker"],
        capture_output=True, timeout=120
    )
    if inst.returncode == 0:
        return True
    # Fallback: clone from git
    if not _NETTACKER_DIR.exists():
        _NETTACKER_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth=1", "-q",
             "https://github.com/OWASP/Nettacker.git", str(_NETTACKER_DIR)],
            capture_output=True, timeout=120
        )
        if (_NETTACKER_DIR / "requirements.txt").exists():
            subprocess.run(
                ["pip3", "install", "-q", "--break-system-packages",
                 "-r", str(_NETTACKER_DIR / "requirements.txt")],
                capture_output=True, timeout=120
            )
    return _NETTACKER_DIR.exists()


def _run_nettacker(args: list, timeout: int = _TIMEOUT) -> dict:
    if not _ensure_nettacker():
        return {"error": "Failed to install OWASP Nettacker"}

    # Try module invocation first, then script
    base_cmds = [
        ["python3", "-m", "owasp_nettacker"],
        ["python3", str(_NETTACKER_DIR / "nettacker.py")],
    ]

    for base in base_cmds:
        try:
            r = subprocess.run(
                base + args,
                capture_output=True, text=True, timeout=timeout
            )
            if r.returncode == 0 or r.stdout or r.stderr:
                return {
                    "returncode": r.returncode,
                    "output":     (r.stdout + r.stderr)[-6000:],
                }
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return {"error": f"Scan timed out after {timeout}s"}
        except Exception as e:
            return {"error": str(e)}

    return {"error": "nettacker not found. Install: pip install owasp-nettacker"}


def nettacker_scan(target: str, modules: str = "port_scan",
                   threads: int = 10,
                   timeout_per_host: int = 3,
                   output_file: str = "",
                   scan_timeout: int = _TIMEOUT) -> dict:
    """Run an OWASP Nettacker scan against a target.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target:            IP, hostname, domain, CIDR, or range (e.g. 192.168.1.0/24)
    modules:           comma-separated modules (default: port_scan)
                       Common: port_scan, subdomain, dir_scan, vuln_scan, ssl_scan,
                               cms_detection, http_methods, server_version, default_login
                       Use 'all' for everything (slow)
    threads:           parallel threads (default: 10)
    timeout_per_host:  seconds per host (default: 3)
    output_file:       save results to file (HTML/JSON based on extension)
    """
    if not output_file:
        output_file = f"/tmp/nettacker_{re.sub(r'[^a-zA-Z0-9]', '_', target)}.json"

    args = [
        "-i", target,
        "-m", modules,
        "-t", str(threads),
        "--timeout", str(timeout_per_host),
        "-o", output_file,
    ]

    result = _run_nettacker(args, timeout=scan_timeout)
    result["target"]      = target
    result["modules"]     = modules
    result["source"]      = "OWASP Nettacker"
    result["output_file"] = output_file
    result["note"]        = "AUTHORIZED PENETRATION TESTING ONLY"

    # Try to read JSON output
    if Path(output_file).exists():
        try:
            data = json.loads(Path(output_file).read_text())
            result["parsed_results"] = data if isinstance(data, list) else [data]
        except Exception:
            pass

    return result


def nettacker_vuln_scan(target: str, threads: int = 10,
                         scan_timeout: int = _TIMEOUT) -> dict:
    """Run a full vulnerability scan with OWASP Nettacker.
    Covers: port scan, SSL, HTTP methods, server version, default credentials, CMS detection.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target: IP, hostname, domain, or CIDR
    """
    modules = ",".join([
        "port_scan", "ssl_scan", "http_methods", "server_version",
        "default_login", "cms_detection", "drupal_version",
        "wp_version", "joomla_version",
    ])
    return nettacker_scan(target, modules, threads, scan_timeout=scan_timeout)


def nettacker_subdomain_enum(domain: str, threads: int = 20,
                              wordlist: str = "",
                              scan_timeout: int = 300) -> dict:
    """Enumerate subdomains using OWASP Nettacker.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    domain:   target domain (e.g. example.com)
    threads:  parallel threads (default: 20)
    wordlist: custom wordlist path (uses built-in if empty)
    """
    args = ["-i", domain, "-m", "subdomain", "-t", str(threads)]
    if wordlist:
        args += ["--wordlist", wordlist]

    result = _run_nettacker(args, timeout=scan_timeout)
    result["target"] = domain
    result["source"] = "OWASP Nettacker - subdomain enum"
    result["note"]   = "AUTHORIZED PENETRATION TESTING ONLY"
    return result


def nettacker_list_modules() -> dict:
    """List all available OWASP Nettacker scan modules."""
    result = _run_nettacker(["--show-all-modules"], timeout=30)
    return {
        "source":  "OWASP Nettacker",
        "modules": result.get("output", ""),
        "note":    "Use module names with nettacker_scan(modules='module1,module2')",
    }


TOOLS = {
    "nettacker_scan": {
        "fn": nettacker_scan,
        "description": (
            "OWASP Nettacker scan: port_scan, subdomain, dir_scan, vuln_scan, ssl_scan, cms_detection, "
            "default_login, http_methods, server_version. Use 'all' for everything. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":           {"type": "string",  "description": "IP, hostname, domain, or CIDR"},
                "modules":          {"type": "string",  "description": "Comma-separated modules (default: port_scan). Use 'all' for full scan."},
                "threads":          {"type": "integer", "description": "Parallel threads (default: 10)"},
                "timeout_per_host": {"type": "integer", "description": "Seconds per host (default: 3)"},
                "output_file":      {"type": "string",  "description": "Output file path (.json or .html)"},
            },
            "required": ["target"]
        }
    },
    "nettacker_vuln_scan": {
        "fn": nettacker_vuln_scan,
        "description": (
            "Full vulnerability scan with OWASP Nettacker: port scan, SSL, HTTP methods, "
            "server version, default credentials, CMS detection. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":  {"type": "string",  "description": "IP, hostname, domain, or CIDR"},
                "threads": {"type": "integer", "description": "Parallel threads (default: 10)"},
            },
            "required": ["target"]
        }
    },
    "nettacker_subdomain_enum": {
        "fn": nettacker_subdomain_enum,
        "description": "Enumerate subdomains with OWASP Nettacker. ⚠️ AUTHORIZED PENTEST ONLY.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain":   {"type": "string",  "description": "Target domain (e.g. example.com)"},
                "threads":  {"type": "integer", "description": "Threads (default: 20)"},
                "wordlist": {"type": "string",  "description": "Custom wordlist path"},
            },
            "required": ["domain"]
        }
    },
    "nettacker_list_modules": {
        "fn": nettacker_list_modules,
        "description": "List all available OWASP Nettacker scan modules.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
}
