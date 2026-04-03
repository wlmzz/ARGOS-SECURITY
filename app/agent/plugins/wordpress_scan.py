"""
ARGOS Plugin: WordPress Security Scanner
WPScan — the defacto WordPress vulnerability scanner.
Detects: outdated plugins/themes/core, user enumeration, config exposure,
         default credentials, security misconfigurations.

⚠️  AUTHORIZED PENETRATION TESTING ONLY.

Install: gem install wpscan  (Ruby required)
  or:    docker pull wpscanteam/wpscan

WPScan Token (free, recommended): register at https://wpscan.com/register
Set: WPSCAN_API_TOKEN env var

Repo: https://github.com/wpscanteam/wpscan (wlmzz/wpscan)
"""
from __future__ import annotations
import os, subprocess, json, shutil, re
from pathlib import Path

MANIFEST = {
    "id":          "wordpress_scan",
    "name":        "WPScan (WordPress Security Scanner)",
    "description": "WordPress vuln scanner: plugins/themes/core CVEs, user enum, config exposure. PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TIMEOUT = 300


def _ensure_wpscan() -> str | None:
    """Return path to wpscan executable or None if not available."""
    # Check if wpscan is in PATH
    if shutil.which("wpscan"):
        return "wpscan"
    # Check common locations
    for p in ["/usr/local/bin/wpscan", "/usr/bin/wpscan"]:
        if Path(p).exists():
            return p
    # Try to install via gem
    if shutil.which("gem"):
        r = subprocess.run(
            ["gem", "install", "wpscan", "--no-document"],
            capture_output=True, timeout=300
        )
        if r.returncode == 0 and shutil.which("wpscan"):
            return "wpscan"
    # Try Docker
    if shutil.which("docker"):
        return "docker"
    return None


def _run_wpscan(args: list, timeout: int = _TIMEOUT) -> dict:
    """Run wpscan with the given arguments."""
    wpscan = _ensure_wpscan()
    if not wpscan:
        return {
            "error": (
                "WPScan not found. Install: gem install wpscan\n"
                "Or Docker: docker pull wpscanteam/wpscan"
            )
        }

    token = os.getenv("WPSCAN_API_TOKEN", "")

    if wpscan == "docker":
        cmd = ["docker", "run", "--rm", "-it", "wpscanteam/wpscan"] + args
    else:
        cmd = [wpscan] + args

    if token:
        cmd += ["--api-token", token]

    cmd += ["--format", "json", "--no-banner"]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = r.stdout + r.stderr

        # Parse JSON output
        try:
            data = json.loads(r.stdout)
            return {"json": data, "raw": output[-1000:]}
        except Exception:
            return {"output": output[-5000:], "returncode": r.returncode}

    except subprocess.TimeoutExpired:
        return {"error": f"WPScan timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def wpscan_vuln_scan(target_url: str,
                      enumerate: str = "vp,vt,u1-5,ap",
                      aggressive: bool = False,
                      timeout: int = _TIMEOUT) -> dict:
    """Scan a WordPress site for vulnerabilities.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_url:  URL of the WordPress site (e.g. https://example.com)
    enumerate:   what to enumerate:
                   vp = vulnerable plugins
                   ap = all plugins
                   vt = vulnerable themes
                   at = all themes
                   u  = usernames (u1-5 = first 5 user IDs)
                   tt = timthumbs
                   cb = config backups
                   dbe = database exports
    aggressive:  use more aggressive detection (slower, noisier)
    """
    args = ["--url", target_url, "--enumerate", enumerate]
    if aggressive:
        args += ["--plugins-detection", "aggressive", "--themes-detection", "aggressive"]

    result = _run_wpscan(args, timeout=timeout)
    result["target"]     = target_url
    result["source"]     = "WPScan"
    result["enumerated"] = enumerate
    result["note"]       = "AUTHORIZED PENETRATION TESTING ONLY"

    # Parse key findings from JSON if available
    if "json" in result:
        data = result["json"]
        result["summary"] = {
            "wordpress_version": data.get("version", {}).get("number", "unknown"),
            "interesting_findings": len(data.get("interesting_findings", [])),
            "plugins_found":   len(data.get("plugins", {})),
            "themes_found":    len(data.get("themes", {})),
            "users_found":     len(data.get("users", {})),
            "vulnerabilities": sum(
                len(p.get("vulnerabilities", [])) for p in data.get("plugins", {}).values()
            ) + len(data.get("version", {}).get("vulnerabilities", [])),
        }
        # Extract critical vulns
        vulns = []
        for plugin_name, plugin_data in data.get("plugins", {}).items():
            for vuln in plugin_data.get("vulnerabilities", []):
                vulns.append({
                    "component": f"plugin:{plugin_name}",
                    "title":     vuln.get("title", ""),
                    "cvss":      vuln.get("cvss", {}).get("score", "N/A"),
                    "cve":       vuln.get("references", {}).get("cve", []),
                })
        result["vulnerabilities"] = vulns[:20]

    return result


def wpscan_user_enum(target_url: str, max_users: int = 10,
                      timeout: int = 60) -> dict:
    """Enumerate WordPress users via ID scanning.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_url: WordPress site URL
    max_users:  number of user IDs to probe (default: 10)
    """
    args = ["--url", target_url, "--enumerate", f"u1-{max_users}"]
    result = _run_wpscan(args, timeout=timeout)
    result["target"]    = target_url
    result["source"]    = "WPScan User Enumeration"
    result["note"]      = "AUTHORIZED PENETRATION TESTING ONLY"

    if "json" in result:
        users = result["json"].get("users", {})
        result["users_found"] = [
            {"id": uid, "login": u.get("username", ""), "is_admin": False}
            for uid, u in users.items()
        ]

    return result


def wpscan_password_attack(target_url: str, username: str,
                             wordlist: str = "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
                             timeout: int = 120) -> dict:
    """Brute-force WordPress login with a wordlist.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_url: WordPress site URL
    username:   username to attack
    wordlist:   path to password wordlist
    """
    if not Path(wordlist).exists():
        # Fallback to a smaller list
        fallbacks = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
        ]
        for fb in fallbacks:
            if Path(fb).exists():
                wordlist = fb
                break
        else:
            return {"error": f"Wordlist not found: {wordlist}. Install: apt install seclists"}

    args = ["--url", target_url, "--username", username,
            "--passwords", wordlist, "--password-attack", "xmlrpc"]
    result = _run_wpscan(args, timeout=timeout)
    result["target"]   = target_url
    result["username"] = username
    result["source"]   = "WPScan Password Attack"
    result["note"]     = "AUTHORIZED PENETRATION TESTING ONLY"
    return result


TOOLS = {
    "wpscan_vuln_scan": {
        "fn": wpscan_vuln_scan,
        "description": (
            "Scan a WordPress site: vulnerable plugins/themes, CVEs, outdated core, "
            "user enumeration, config file exposure. WPSCAN_API_TOKEN env var for full CVE data. "
            "⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_url":  {"type": "string",  "description": "WordPress site URL"},
                "enumerate":   {"type": "string",  "description": "What to check: vp,vt,ap,at,u1-5,cb,dbe (default: vp,vt,u1-5,ap)"},
                "aggressive":  {"type": "boolean", "description": "Aggressive detection mode (slower, more thorough)"},
                "timeout":     {"type": "integer", "description": "Max seconds (default: 300)"},
            },
            "required": ["target_url"]
        }
    },
    "wpscan_user_enum": {
        "fn": wpscan_user_enum,
        "description": "Enumerate WordPress user accounts by probing user IDs. ⚠️ AUTHORIZED PENTEST ONLY.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string",  "description": "WordPress site URL"},
                "max_users":  {"type": "integer", "description": "Max user IDs to probe (default: 10)"},
            },
            "required": ["target_url"]
        }
    },
    "wpscan_password_attack": {
        "fn": wpscan_password_attack,
        "description": (
            "Brute-force WordPress login with a wordlist. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "WordPress site URL"},
                "username":   {"type": "string", "description": "Username to attack"},
                "wordlist":   {"type": "string", "description": "Path to password wordlist"},
            },
            "required": ["target_url", "username"]
        }
    },
}
