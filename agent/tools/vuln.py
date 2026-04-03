"""Vulnerability scanning tools: nuclei, whatweb, SSL check."""
from __future__ import annotations
import subprocess, json, re, ssl, socket
from pathlib import Path
from typing import Any


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()[:8000]
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return f"[TOOL NOT FOUND: {cmd[0]}] — run installer/install.sh"
    except Exception as e:
        return f"[ERROR: {e}]"


def nuclei_scan(target: str, severity: str = "medium,high,critical",
                templates: str = "") -> dict:
    """Scan a target for vulnerabilities using Nuclei templates.
    target: URL or IP (e.g. 'https://example.com' or '192.168.1.1').
    severity: comma-separated levels to include: info,low,medium,high,critical.
    templates: optional template tags e.g. 'cve,misconfig,default-login'.
    Returns list of findings with severity, template name, and description.
    Use only on authorized targets.
    """
    if not re.match(r"^[a-zA-Z0-9\.\:\-_/]+$", target):
        return {"error": "Invalid target format"}
    valid_sev = {"info", "low", "medium", "high", "critical"}
    sev_list = [s.strip().lower() for s in severity.split(",") if s.strip().lower() in valid_sev]
    if not sev_list:
        sev_list = ["medium", "high", "critical"]

    cmd = [
        "nuclei", "-u", target,
        "-severity", ",".join(sev_list),
        "-json-export", "-",
        "-silent",
        "-timeout", "10",
        "-retries", "1",
    ]
    if templates:
        safe_tpl = re.sub(r"[^a-zA-Z0-9,\-_]", "", templates)
        cmd += ["-tags", safe_tpl]

    # Update templates if needed (non-blocking)
    templates_dir = Path.home() / ".config" / "nuclei" / "templates"
    if not templates_dir.exists():
        subprocess.run(["nuclei", "-update-templates", "-silent"],
                       capture_output=True, timeout=60)

    raw = _run(cmd, timeout=300)

    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "template": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", "").upper(),
                "description": entry.get("info", {}).get("description", "")[:300],
                "matched_at": entry.get("matched-at", ""),
                "reference": entry.get("info", {}).get("reference", [])[:2],
            })
        except json.JSONDecodeError:
            pass

    findings.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5))

    return {
        "tool": "nuclei",
        "target": target,
        "severity_filter": sev_list,
        "total_findings": len(findings),
        "findings": findings[:50],
        "raw_output": raw[:2000] if not findings else "",
    }


def whatweb_scan(url: str) -> dict:
    """Fingerprint web technologies on a URL using WhatWeb.
    Identifies CMS, frameworks, server software, JS libraries, and more.
    Use only on authorized targets.
    """
    if not re.match(r"^https?://[a-zA-Z0-9\.\:\-_/\?=&%]+$", url):
        return {"error": "Invalid URL format — must start with http:// or https://"}
    raw = _run(["whatweb", "--log-json=-", "--quiet", url], timeout=30)
    try:
        results = json.loads(raw)
        if isinstance(results, list) and results:
            r = results[0]
            plugins = r.get("plugins", {})
            tech = {}
            for name, data in plugins.items():
                versions = data.get("version", [])
                strings = data.get("string", [])
                tech[name] = versions[0] if versions else (strings[0] if strings else True)
            return {
                "tool": "whatweb",
                "url": url,
                "status": r.get("http_status"),
                "technologies": tech,
            }
    except Exception:
        pass
    return {"tool": "whatweb", "url": url, "raw_output": raw[:2000]}


def ssl_check(hostname: str, port: int = 443) -> dict:
    """Check SSL/TLS certificate for a hostname: expiry, issuer, subject, SANs.
    Identifies expired certs, self-signed certs, weak configurations.
    """
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
        return {"error": "Invalid hostname"}
    port = int(port)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        import datetime
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days_left = (not_after - now).days

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        issues = []
        if days_left < 0:
            issues.append("EXPIRED")
        elif days_left < 14:
            issues.append(f"EXPIRES_SOON ({days_left} days)")
        if subject.get("commonName") == issuer.get("commonName"):
            issues.append("SELF_SIGNED")
        if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            issues.append(f"WEAK_PROTOCOL ({protocol})")

        return {
            "tool": "ssl_check",
            "hostname": hostname,
            "port": port,
            "valid": len(issues) == 0,
            "issues": issues,
            "subject_cn": subject.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": str(not_before.date()),
            "not_after": str(not_after.date()),
            "days_remaining": days_left,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "san_domains": sans[:10],
        }
    except ssl.SSLCertVerificationError as e:
        return {"tool": "ssl_check", "hostname": hostname, "valid": False,
                "issues": ["CERT_VERIFICATION_FAILED"], "error": str(e)}
    except Exception as e:
        return {"tool": "ssl_check", "hostname": hostname, "error": str(e)}


TOOLS = {
    "nuclei_scan": {
        "fn": nuclei_scan,
        "description": (
            "Scan a target URL or IP for vulnerabilities using Nuclei's 10,000+ templates. "
            "Detects CVEs, misconfigurations, exposed admin panels, default credentials, and more. "
            "Use only on authorized targets."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or IP to scan (e.g. 'https://example.com' or '10.0.0.1')"},
                "severity": {"type": "string", "description": "Severity filter: 'medium,high,critical' (default) or 'info,low,medium,high,critical'"},
                "templates": {"type": "string", "description": "Optional template tags: 'cve', 'misconfig', 'default-login', 'exposure', 'takeover', etc."},
            },
            "required": ["target"]
        }
    },
    "whatweb_scan": {
        "fn": whatweb_scan,
        "description": "Fingerprint web technologies on a URL: CMS (WordPress, Joomla), server (Apache, nginx), frameworks, JS libraries, and more.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to fingerprint, e.g. 'https://example.com'"}
            },
            "required": ["url"]
        }
    },
    "ssl_check": {
        "fn": ssl_check,
        "description": "Check SSL/TLS certificate for a hostname: expiry date, issuer, protocol version, cipher. Flags expired, self-signed, or weak TLS.",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Hostname to check SSL for (e.g. 'example.com')"},
                "port": {"type": "integer", "description": "Port number (default: 443)"}
            },
            "required": ["hostname"]
        }
    }
}
