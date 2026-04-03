"""Log analysis, threat scoring, and report generation tools."""
from __future__ import annotations
import re, json, subprocess
from pathlib import Path
from datetime import datetime
from typing import Any


_SUSPICIOUS_PATTERNS = [
    (r"\b(?:root|admin|administrator)\b.*\bfailed\b", "BRUTE_FORCE", "HIGH"),
    (r"Failed password.*from\s+([\d\.]+)", "BRUTE_FORCE", "HIGH"),
    (r"Invalid user.*from\s+([\d\.]+)", "BRUTE_FORCE", "MEDIUM"),
    (r"(?:UNION|SELECT|INSERT|DROP|--\s|\'[\s]*OR[\s]*\')", "SQL_INJECTION", "CRITICAL"),
    (r"(?:\.\./|\.\.\\|%2e%2e%2f)", "PATH_TRAVERSAL", "HIGH"),
    (r"(?:<script|javascript:|onerror=|onload=)", "XSS", "HIGH"),
    (r"(?:/etc/passwd|/etc/shadow|cmd\.exe|powershell)", "CMD_INJECTION", "CRITICAL"),
    (r"(?:wget|curl)\s+https?://\S+\s*\|", "DOWNLOAD_EXEC", "CRITICAL"),
    (r"(?:\.encrypted|\.locked|\.crypt|vssadmin.*delete)", "RANSOMWARE", "CRITICAL"),
    (r"(?:mimikatz|lsass|sekurlsa)", "CREDENTIAL_DUMP", "CRITICAL"),
    (r"(?:nc\s+-|ncat\s+-|/dev/tcp/)", "REVERSE_SHELL", "CRITICAL"),
    (r"404.*(\d{3,4})\s+times", "DIR_ENUMERATION", "MEDIUM"),
]


def analyze_log(content: str, source: str = "unknown") -> dict:
    """Analyze log content for security threats and IOCs."""
    lines = content.splitlines()
    findings = []
    seen = set()

    for i, line in enumerate(lines[:5000]):
        for pattern, attack_type, severity in _SUSPICIOUS_PATTERNS:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                key = f"{attack_type}:{line[:80]}"
                if key not in seen:
                    seen.add(key)
                    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                    findings.append({
                        "line": i + 1,
                        "attack_type": attack_type,
                        "severity": severity,
                        "snippet": line.strip()[:200],
                        "source_ips": ips,
                    })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    summary = {
        "source": source,
        "lines_analyzed": min(len(lines), 5000),
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "attack_types": list(set(f["attack_type"] for f in findings)),
        "unique_ips": list(set(ip for f in findings for ip in f.get("source_ips", [])))[:20],
        "findings": findings[:50],
    }
    return summary


def read_log_file(path: str, lines: int = 500) -> dict:
    """Read a log file from the filesystem and analyze it."""
    p = Path(path)
    # Safety: only allow reading log files
    allowed_dirs = ["/var/log", "/opt/argos", "/opt/finance", "/opt/hr", "/tmp"]
    if not any(str(p).startswith(d) for d in allowed_dirs):
        return {"error": f"Access denied: only log directories allowed: {allowed_dirs}"}
    if not p.exists():
        return {"error": f"File not found: {path}"}
    try:
        result = subprocess.run(["tail", "-n", str(lines), str(p)],
                                capture_output=True, text=True, timeout=10)
        content = result.stdout
        analysis = analyze_log(content, source=path)
        analysis["file_path"] = path
        analysis["size_bytes"] = p.stat().st_size
        return analysis
    except Exception as e:
        return {"error": str(e)}


def generate_report(title: str, findings: list, recommendations: list,
                    severity: str = "MEDIUM") -> dict:
    """Generate a structured security incident report."""
    now = datetime.utcnow().isoformat()
    report = {
        "report_id": f"ARGOS-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "title": title,
        "generated_at": now,
        "overall_severity": severity.upper(),
        "executive_summary": f"Security analysis identified {len(findings)} finding(s) requiring attention.",
        "findings": findings,
        "recommendations": recommendations,
        "generated_by": "ARGOS Cybersecurity Agent",
    }
    # Save to disk
    report_dir = Path("/opt/argos/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{report['report_id']}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    report["saved_to"] = str(report_path)
    return report


def ban_ip(ip: str, reason: str = "threat detected by ARGOS") -> dict:
    """Ban an IP address permanently via fail2ban. Use only for confirmed threats."""
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return {"error": "Invalid IP address format"}
    # Whitelist: never ban these
    protected = {"127.0.0.1", os.getenv("ARGOS_SERVER_IP", ""), "localhost"}
    if ip in protected:
        return {"error": f"Cannot ban protected IP: {ip}"}
    try:
        r = subprocess.run(
            ["fail2ban-client", "set", "plesk-permanent-ban", "banip", ip],
            capture_output=True, text=True, timeout=10
        )
        success = r.returncode == 0
        # Log the action
        log_path = Path("/opt/argos/logs/defensive_actions.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps({
                "action": "ban_ip", "ip": ip, "reason": reason,
                "timestamp": datetime.utcnow().isoformat(), "success": success
            }) + "\n")
        return {"action": "ban_ip", "ip": ip, "success": success,
                "reason": reason, "output": r.stdout.strip()}
    except Exception as e:
        return {"error": str(e)}


def unban_ip(ip: str) -> dict:
    """Remove an IP ban via fail2ban."""
    try:
        r = subprocess.run(
            ["fail2ban-client", "set", "plesk-permanent-ban", "unbanip", ip],
            capture_output=True, text=True, timeout=10
        )
        return {"action": "unban_ip", "ip": ip,
                "success": r.returncode == 0, "output": r.stdout.strip()}
    except Exception as e:
        return {"error": str(e)}


def list_banned_ips() -> dict:
    """List all currently banned IPs."""
    try:
        r = subprocess.run(
            ["fail2ban-client", "status", "plesk-permanent-ban"],
            capture_output=True, text=True, timeout=10
        )
        return {"output": r.stdout.strip()}
    except Exception as e:
        return {"error": str(e)}


TOOLS = {
    "analyze_log": {
        "fn": analyze_log,
        "description": "Analyze raw log content for security threats: brute force, SQL injection, XSS, ransomware, C2 activity, etc. Returns structured findings with severity levels.",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Raw log text to analyze"},
                "source": {"type": "string", "description": "Log source name (e.g. 'nginx', 'sshd', 'auth.log')"}
            },
            "required": ["content"]
        }
    },
    "read_log_file": {
        "fn": read_log_file,
        "description": "Read and analyze a log file from the server filesystem. Allowed paths: /var/log/, /opt/argos/, /opt/finance/, /opt/hr/",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the log file"},
                "lines": {"type": "integer", "description": "Number of lines to read from end (default 500)"}
            },
            "required": ["path"]
        }
    },
    "generate_report": {
        "fn": generate_report,
        "description": "Generate a structured security incident report and save it to /opt/argos/reports/",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Report title"},
                "findings": {"type": "array", "items": {"type": "object"}, "description": "List of security findings"},
                "recommendations": {"type": "array", "items": {"type": "string"}, "description": "List of remediation recommendations"},
                "severity": {"type": "string", "description": "Overall severity: LOW, MEDIUM, HIGH, CRITICAL"}
            },
            "required": ["title", "findings", "recommendations"]
        }
    },
    "ban_ip": {
        "fn": ban_ip,
        "description": "Permanently ban an IP address via fail2ban. Use only for confirmed malicious IPs (brute force, scanning, exploitation attempts).",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to ban"},
                "reason": {"type": "string", "description": "Reason for banning (e.g. 'SSH brute force 500+ attempts')"}
            },
            "required": ["ip"]
        }
    },
    "unban_ip": {
        "fn": unban_ip,
        "description": "Remove a ban for an IP address (false positive correction).",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to unban"}
            },
            "required": ["ip"]
        }
    },
    "list_banned_ips": {
        "fn": list_banned_ips,
        "description": "List all currently banned IP addresses.",
        "parameters": {"type": "object", "properties": {}}
    }
}
