"""
ARGOS Plugin: Gobuster + Feroxbuster
Directory/file brute-forcing and DNS subdomain enumeration.
Gobuster: apt install gobuster  OR  go install github.com/OJ/gobuster/v3@latest
Feroxbuster (fallback): https://github.com/epi052/feroxbuster

Wordlists (install once):
  apt install seclists
  → /usr/share/seclists/Discovery/Web-Content/common.txt
  → /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
"""
from __future__ import annotations
import os
import re
import subprocess
import tempfile
from pathlib import Path

MANIFEST = {
    "id":          "gobuster",
    "name":        "Gobuster",
    "description": "Directory/file brute-forcing and DNS subdomain enumeration. Falls back to feroxbuster if gobuster not installed.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

# Default wordlists — SecLists preferred, fallback to dirb/dirbuster
_DEFAULT_DIR_WORDLIST = next((
    str(p) for p in [
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"),
    ] if p.exists()
), "")

_DEFAULT_DNS_WORDLIST = next((
    str(p) for p in [
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        Path("/usr/share/wordlists/dnsmap.txt"),
    ] if p.exists()
), "")


def _check_tool(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0


def gobuster_dir(url: str, wordlist: str = "", extensions: str = "",
                 threads: int = 20, timeout: int = 120) -> dict:
    """Brute-force directories and files on a web server.
    extensions: comma-separated file extensions to try (e.g. 'php,html,txt,bak')
    """
    # URL validation — must be http/https
    if not re.match(r"^https?://[a-zA-Z0-9.\-/:%@_~?&=#+]+$", url):
        return {"error": "Invalid URL format. Must start with http:// or https://"}

    wordlist = wordlist or _DEFAULT_DIR_WORDLIST
    if not wordlist:
        return {"error": "No wordlist found. Install seclists: apt install seclists"}
    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}"}

    if _check_tool("gobuster"):
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", str(min(threads, 50)),
            "--no-progress",
            "--no-color",
            "-q",
        ]
        if extensions:
            safe_ext = re.sub(r"[^a-zA-Z0-9,]", "", extensions)
            cmd += ["-x", safe_ext]
    elif _check_tool("feroxbuster"):
        cmd = [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist,
            "--threads", str(min(threads, 50)),
            "--quiet",
            "--no-recursion",
        ]
        if extensions:
            safe_ext = re.sub(r"[^a-zA-Z0-9,]", "", extensions)
            for ext in safe_ext.split(","):
                cmd += ["-x", ext]
    else:
        return {
            "error": "Neither gobuster nor feroxbuster found.",
            "install": "apt install gobuster  OR  https://github.com/epi052/feroxbuster"
        }

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"url": url, "status": "timeout", "message": f"Scan timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}

    # Parse found paths
    found = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # gobuster: "Found: /path (Status: 200) [Size: 1234]"
        # feroxbuster: "200      GET  ... /path"
        m = re.search(r"(Found|GET|POST)\s+.*?(/\S+)", line)
        status_m = re.search(r"(?:Status|^\d{3})\s*:?\s*(\d{3})", line)
        if m or status_m:
            found.append({
                "path":   m.group(2) if m else "",
                "status": status_m.group(1) if status_m else "",
                "raw":    line[:200],
            })

    return {
        "url":         url,
        "wordlist":    Path(wordlist).name,
        "source":      "Gobuster",
        "found_count": len(found),
        "findings":    found[:100],
    }


def gobuster_dns(domain: str, wordlist: str = "", threads: int = 20, timeout: int = 120) -> dict:
    """Enumerate subdomains via DNS brute-force.
    Returns valid subdomains and their resolved IPs.
    """
    domain = domain.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9.\-]{1,253}$", domain):
        return {"error": "Invalid domain format"}

    wordlist = wordlist or _DEFAULT_DNS_WORDLIST
    if not wordlist:
        return {"error": "No DNS wordlist found. Install seclists: apt install seclists"}
    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}"}

    if not _check_tool("gobuster"):
        return {
            "error": "gobuster not found for DNS mode.",
            "install": "apt install gobuster",
            "alternative": "Use subdomain_enum() for passive enumeration (no install needed)",
        }

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", str(min(threads, 50)),
        "--no-color", "-q",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"domain": domain, "status": "timeout", "message": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}

    subdomains = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # gobuster dns output: "Found: sub.domain.com [1.2.3.4]"
        m = re.search(r"Found:\s+([a-zA-Z0-9.\-]+)\s*(?:\[([0-9., ]+)\])?", line)
        if m:
            subdomains.append({
                "subdomain": m.group(1),
                "ips": [ip.strip() for ip in (m.group(2) or "").split(",")] if m.group(2) else [],
            })

    return {
        "domain":          domain,
        "wordlist":        Path(wordlist).name,
        "source":          "Gobuster DNS",
        "subdomain_count": len(subdomains),
        "subdomains":      subdomains[:100],
    }


TOOLS = {
    "gobuster_dir": {
        "fn": gobuster_dir,
        "description": (
            "Brute-force directories and files on a web server using Gobuster (or feroxbuster fallback). "
            "Finds hidden admin panels, backup files, API endpoints, config files. "
            "Uses SecLists wordlists by default. "
            "extensions example: 'php,html,txt,bak,js'. Requires gobuster CLI."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url":        {"type": "string",  "description": "Target URL (e.g. 'https://example.com')"},
                "wordlist":   {"type": "string",  "description": "Path to wordlist (uses SecLists default if empty)"},
                "extensions": {"type": "string",  "description": "File extensions to try, comma-separated (e.g. 'php,html,txt')"},
                "threads":    {"type": "integer", "description": "Concurrent threads (default: 20, max: 50)"},
                "timeout":    {"type": "integer", "description": "Max seconds to wait (default: 120)"},
            },
            "required": ["url"]
        }
    },
    "gobuster_dns": {
        "fn": gobuster_dns,
        "description": (
            "Enumerate subdomains via active DNS brute-force using Gobuster. "
            "Faster and more thorough than passive methods. "
            "Uses SecLists DNS wordlist by default. Requires gobuster CLI."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain":   {"type": "string",  "description": "Target domain (e.g. 'example.com')"},
                "wordlist": {"type": "string",  "description": "Path to DNS wordlist (uses SecLists default if empty)"},
                "threads":  {"type": "integer", "description": "Concurrent threads (default: 20, max: 50)"},
                "timeout":  {"type": "integer", "description": "Max seconds to wait (default: 120)"},
            },
            "required": ["domain"]
        }
    },
}
