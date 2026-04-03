"""
ARGOS Plugin: Web Recon Toolkit
Combines rapidscan, Vaile, Astra REST API security scanning, and skipfish.

Tools:
  - rapidscan:  fast multi-tool web vulnerability scanner (nmap, whois, SSL, headers, etc.)
  - Vaile:      web application reconnaissance (headers, WHOIS, GeoIP, ports, DNS, robots)
  - Astra:      REST API security testing (OWASP Top 10 for APIs)
  - skipfish:   Google's active web application security scanner (10,000+ checks)

⚠️  AUTHORIZED PENETRATION TESTING ONLY.

Auto-installs tools to /opt/argos/tools/
  rapidscan: https://github.com/skavngr/rapidscan
  Vaile:     https://github.com/Sab0tag3d/Vaile
  Astra:     https://github.com/flipkart-incubator/Astra
  skipfish:  apt install skipfish  (or brew install skipfish)
"""
from __future__ import annotations
import os, subprocess, re, json
from pathlib import Path

MANIFEST = {
    "id":          "web_recon",
    "name":        "Web Recon Toolkit (rapidscan + Vaile + Astra)",
    "description": "Web recon & API security: rapidscan (multi-tool vuln scan), Vaile (web recon), Astra (REST API OWASP Top 10). PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TOOLS_BASE    = Path("/opt/argos/tools")
_RAPIDSCAN_DIR = _TOOLS_BASE / "rapidscan"
_VAILE_DIR     = _TOOLS_BASE / "Vaile"
_ASTRA_DIR     = _TOOLS_BASE / "Astra"


def _clone_tool(repo: str, dest: Path, timeout: int = 120) -> bool:
    if dest.exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         f"https://github.com/{repo}.git", str(dest)],
        capture_output=True, timeout=timeout
    )
    if r.returncode == 0 and (dest / "requirements.txt").exists():
        subprocess.run(
            ["pip3", "install", "-q", "--break-system-packages",
             "-r", str(dest / "requirements.txt")],
            capture_output=True, timeout=120
        )
    return r.returncode == 0


# ─── rapidscan ────────────────────────────────────────────────────────────────

def rapidscan(target: str, timeout: int = 300) -> dict:
    """Run rapidscan — a fast, automated multi-tool web vulnerability scanner.
    Checks: WHOIS, GeoIP, nmap ports, SSL/TLS, HTTP headers, robots.txt,
            content discovery, banner grab, and more.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target: domain or IP (e.g. example.com or 192.168.1.1)
    """
    if not _clone_tool("skavngr/rapidscan", _RAPIDSCAN_DIR):
        return {"error": "Failed to install rapidscan"}

    script = next(
        (p for p in [_RAPIDSCAN_DIR / "rapidscan.py", _RAPIDSCAN_DIR / "rapidscan"]
         if p.exists()),
        None
    )
    if not script:
        return {"error": "rapidscan script not found after clone"}

    try:
        r = subprocess.run(
            ["python3", str(script), target],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(_RAPIDSCAN_DIR)
        )
        output = (r.stdout + r.stderr)[-8000:]
        return {
            "tool":       "rapidscan",
            "target":     target,
            "source":     "ARGOS Web Recon",
            "output":     output,
            "note":       "AUTHORIZED PENETRATION TESTING ONLY",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"rapidscan timed out after {timeout}s", "target": target}
    except Exception as e:
        return {"error": str(e)}


# ─── Vaile ────────────────────────────────────────────────────────────────────

def vaile_recon(url: str, mode: str = "all", timeout: int = 120) -> dict:
    """Run Vaile web application reconnaissance.
    Gathers: HTTP headers, security headers, WHOIS, GeoIP, open ports, DNS,
             robots.txt, sitemap, technology detection.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    url:  target URL (e.g. https://example.com)
    mode: 'all' | 'headers' | 'whois' | 'ports' | 'dns' (default: all)
    """
    if not _clone_tool("Sab0tag3d/Vaile", _VAILE_DIR):
        return {"error": "Failed to install Vaile"}

    script = next(
        (p for p in [_VAILE_DIR / "Vaile.py", _VAILE_DIR / "vaile.py",
                     _VAILE_DIR / "main.py"]
         if p.exists()),
        None
    )
    if not script:
        return {"error": "Vaile script not found after clone"}

    args = [url]
    if mode == "all":
        args.append("--all")
    elif mode != "all":
        args.append(f"--{mode}")

    try:
        r = subprocess.run(
            ["python3", str(script)] + args,
            capture_output=True, text=True, timeout=timeout,
            cwd=str(_VAILE_DIR)
        )
        output = (r.stdout + r.stderr)[-6000:]
        return {
            "tool":   "Vaile",
            "target": url,
            "mode":   mode,
            "source": "ARGOS Web Recon",
            "output": output,
            "note":   "AUTHORIZED PENETRATION TESTING ONLY",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Vaile timed out after {timeout}s", "target": url}
    except Exception as e:
        return {"error": str(e)}


# ─── Astra (REST API security) ────────────────────────────────────────────────

def astra_api_scan(target_url: str, collection_file: str = "",
                    timeout: int = 300) -> dict:
    """Scan a REST API for OWASP Top 10 vulnerabilities using Astra.
    Tests: SQLi, XSS, broken auth, rate limiting, CORS, improper HTTP methods,
           information disclosure, JWT vulnerabilities.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_url:      Base URL of the REST API (e.g. http://api.example.com)
    collection_file: Postman/OpenAPI collection file (optional — uses auto-discovery if empty)
    """
    if not _clone_tool("flipkart-incubator/Astra", _ASTRA_DIR):
        return {"error": "Failed to install Astra"}

    # Astra is Django-based — try to run the scan CLI
    script = next(
        (p for p in [_ASTRA_DIR / "astra.py", _ASTRA_DIR / "manage.py"]
         if p.exists()),
        None
    )

    if not script:
        return {"error": "Astra script not found after clone"}

    if str(script).endswith("manage.py"):
        # Django management command
        cmd = ["python3", str(script), "scan", "--target", target_url]
    else:
        cmd = ["python3", str(script), "--target", target_url]

    if collection_file:
        cmd += ["--collection", collection_file]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(_ASTRA_DIR)
        )
        output = (r.stdout + r.stderr)[-6000:]

        # Try to parse JSON output
        result = {
            "tool":       "Astra",
            "target":     target_url,
            "source":     "ARGOS Web Recon",
            "output":     output,
            "note":       "AUTHORIZED PENETRATION TESTING ONLY",
        }
        try:
            # Look for JSON in output
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                result["parsed"] = json.loads(json_match.group())
        except Exception:
            pass
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Astra scan timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def skipfish_scan(target_url: str, output_dir: str = "",
                  timeout: int = 300) -> dict:
    """Scan a web application with skipfish — Google's active security scanner.
    Performs 10,000+ checks: crawling, injection points, file inclusion,
    session management, response analysis, blind injection detection.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_url: URL to scan (e.g. https://example.com)
    output_dir: where to save the HTML report (default: /tmp/skipfish_<host>)
    """
    import shutil, re as _re, time as _time
    clean_host = _re.sub(r"^https?://", "", target_url).split("/")[0].replace(":", "_")
    out = output_dir or f"/tmp/skipfish_{clean_host}"

    # Ensure skipfish is available
    sf_bin = shutil.which("skipfish")
    if not sf_bin:
        # Try to install
        if shutil.which("apt-get"):
            subprocess.run(["apt-get", "install", "-y", "-q", "skipfish"],
                           capture_output=True, timeout=120)
            sf_bin = shutil.which("skipfish")
        elif shutil.which("brew"):
            subprocess.run(["brew", "install", "skipfish"],
                           capture_output=True, timeout=120)
            sf_bin = shutil.which("skipfish")

    if not sf_bin:
        return {
            "error": "skipfish not found. Install: apt install skipfish (Debian/Kali) or brew install skipfish (macOS)",
            "target": target_url,
        }

    cmd = [sf_bin, "-o", out, target_url]

    start = _time.time()
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        elapsed = round(_time.time() - start, 1)
        output = (r.stdout + r.stderr)[-5000:]

        result = {
            "tool":       "skipfish",
            "target":     target_url,
            "output_dir": out,
            "duration_s": elapsed,
            "output":     output,
            "source":     "ARGOS Web Recon",
            "note":       "AUTHORIZED PENETRATION TESTING ONLY",
        }

        # Parse summary stats from skipfish output
        issues = re.search(r"Issues: (\d+)", output)
        crawled = re.search(r"Nodes: (\d+)", output)
        if issues:
            result["issues_found"] = int(issues.group(1))
        if crawled:
            result["pages_crawled"] = int(crawled.group(1))

        return result
    except subprocess.TimeoutExpired:
        return {"error": f"skipfish timed out after {timeout}s", "target": target_url,
                "output_dir": out, "note": "Partial results may be in output_dir"}
    except Exception as e:
        return {"error": str(e), "target": target_url}


def web_recon_full(target: str, timeout: int = 300) -> dict:
    """Full web reconnaissance: rapidscan + Vaile combined.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target: domain, IP, or URL
    """
    url    = target if target.startswith("http") else f"https://{target}"
    domain = re.sub(r"^https?://", "", url).split("/")[0]

    results = {
        "rapidscan": rapidscan(domain, timeout=timeout),
        "vaile":     vaile_recon(url, "all", timeout=120),
    }
    errors = [k for k, v in results.items() if "error" in v]
    return {
        "target":    target,
        "source":    "ARGOS Web Recon (Full)",
        "tests_run": len(results),
        "errors":    errors,
        "results":   results,
        "note":      "AUTHORIZED PENETRATION TESTING ONLY",
    }


TOOLS = {
    "rapidscan": {
        "fn": rapidscan,
        "description": (
            "Fast multi-tool web vulnerability scan: WHOIS, GeoIP, nmap, SSL/TLS, HTTP headers, "
            "robots.txt, banner grab, content discovery. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":  {"type": "string",  "description": "Domain or IP (e.g. example.com)"},
                "timeout": {"type": "integer", "description": "Max seconds (default: 300)"},
            },
            "required": ["target"]
        }
    },
    "vaile_recon": {
        "fn": vaile_recon,
        "description": (
            "Web application recon with Vaile: HTTP headers, security headers, WHOIS, GeoIP, "
            "open ports, DNS, robots.txt, sitemap, tech detection. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url":     {"type": "string",  "description": "Target URL (e.g. https://example.com)"},
                "mode":    {"type": "string",  "description": "'all' | 'headers' | 'whois' | 'ports' | 'dns' (default: all)"},
                "timeout": {"type": "integer", "description": "Max seconds (default: 120)"},
            },
            "required": ["url"]
        }
    },
    "astra_api_scan": {
        "fn": astra_api_scan,
        "description": (
            "REST API security scan with Astra: OWASP Top 10 for APIs — SQLi, XSS, broken auth, "
            "rate limiting, CORS, improper methods, JWT vulnerabilities. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_url":      {"type": "string", "description": "Base URL of the REST API"},
                "collection_file": {"type": "string", "description": "Postman/OpenAPI collection file (optional)"},
                "timeout":         {"type": "integer", "description": "Max seconds (default: 300)"},
            },
            "required": ["target_url"]
        }
    },
    "skipfish_scan": {
        "fn": skipfish_scan,
        "description": (
            "Active web application security scan with skipfish (Google): 10,000+ checks — "
            "crawling, SQL/XSS/command injection, file inclusion, session management. "
            "Generates HTML report. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string",  "description": "URL to scan (e.g. https://example.com)"},
                "output_dir": {"type": "string",  "description": "Report output dir (default: /tmp/skipfish_<host>)"},
                "timeout":    {"type": "integer", "description": "Max seconds (default: 300)"},
            },
            "required": ["target_url"]
        }
    },
    "web_recon_full": {
        "fn": web_recon_full,
        "description": (
            "Full web recon: rapidscan + Vaile combined scan. "
            "Complete target profiling for web pentesting. ⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":  {"type": "string",  "description": "Domain, IP, or URL"},
                "timeout": {"type": "integer", "description": "Max seconds per tool (default: 300)"},
            },
            "required": ["target"]
        }
    },
}
