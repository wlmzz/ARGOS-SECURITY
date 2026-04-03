"""Honeypot management: deploy, monitor, and read attacker activity logs."""
from __future__ import annotations
import subprocess, json, re, os, signal
from pathlib import Path
from datetime import datetime


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()[:4000]
    except subprocess.TimeoutExpired:
        return -1, f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return -1, f"[NOT FOUND: {cmd[0]}]"
    except Exception as e:
        return -1, str(e)


HONEYPOT_LOG = Path("/opt/argos/logs/honeypot.json")
HONEYPOT_PID = Path("/opt/argos/logs/honeypot.pid")


def deploy_honeypot(services: list[str] | None = None, log_path: str | None = None) -> dict:
    """Deploy a multi-service honeypot to capture attacker activity.
    Uses qeeqbox/honeypots — runs fake SSH, HTTP, FTP, Telnet, MySQL, etc.
    Attackers who connect are logged with their IP, credentials, and commands.

    services: list of services to fake. Options: ssh, http, https, ftp, telnet,
              smtp, mysql, postgres, redis, vnc, rdp, dns, snmp, ldap, sip.
              Default: ['ssh', 'http', 'ftp', 'telnet'].
    log_path: where to write captured activity (default: /opt/argos/logs/honeypot.json).

    IMPORTANT: Use ports > 1024 for non-root or run as root.
    Recommended: run on non-standard ports to avoid conflicts with real services.
    """
    services = services or ["ssh", "http", "ftp", "telnet"]
    log_path = log_path or str(HONEYPOT_LOG)

    # Check if already running
    if HONEYPOT_PID.exists():
        try:
            pid = int(HONEYPOT_PID.read_text().strip())
            os.kill(pid, 0)  # Check if process exists
            return {"status": "already_running", "pid": pid, "log_path": log_path,
                    "message": "Honeypot is already active. Use read_honeypot_logs() to see captures."}
        except (ProcessLookupError, ValueError):
            HONEYPOT_PID.unlink(missing_ok=True)

    # Validate services
    valid_services = {"ssh", "http", "https", "ftp", "telnet", "smtp", "mysql",
                      "postgres", "redis", "vnc", "rdp", "dns", "snmp", "ldap", "sip"}
    clean_services = [s.lower() for s in services if s.lower() in valid_services]
    if not clean_services:
        return {"error": f"No valid services. Choose from: {', '.join(valid_services)}"}

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    # Build honeypots command
    # qeeqbox honeypots uses: honeypots --setup ssh,http --ip 0.0.0.0 --port 22 --logs file
    cmd = [
        "python3", "-m", "honeypots",
        "--setup", ",".join(clean_services),
        "--ip", "0.0.0.0",
        "--logs", "file",
        "--logs-location", log_path,
    ]

    # Launch in background
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        HONEYPOT_PID.write_text(str(proc.pid))
        return {
            "status": "deployed",
            "pid": proc.pid,
            "services": clean_services,
            "log_path": log_path,
            "message": f"Honeypot active on {len(clean_services)} fake services. Attackers will be logged automatically.",
        }
    except FileNotFoundError:
        return {"error": "honeypots not installed — run: pip install honeypots"}
    except Exception as e:
        return {"error": str(e)}


def honeypot_status() -> dict:
    """Check if the honeypot is running and return basic statistics."""
    if not HONEYPOT_PID.exists():
        return {"status": "not_running", "message": "Deploy with deploy_honeypot()"}

    try:
        pid = int(HONEYPOT_PID.read_text().strip())
        os.kill(pid, 0)
        is_running = True
    except (ProcessLookupError, ValueError):
        is_running = False
        HONEYPOT_PID.unlink(missing_ok=True)

    captures = 0
    unique_ips = set()
    if HONEYPOT_LOG.exists():
        try:
            for line in HONEYPOT_LOG.read_text().splitlines():
                if line.strip():
                    entry = json.loads(line)
                    captures += 1
                    if "src_ip" in entry:
                        unique_ips.add(entry["src_ip"])
                    elif "ip" in entry:
                        unique_ips.add(entry["ip"])
        except Exception:
            pass

    return {
        "status": "running" if is_running else "stopped",
        "pid": pid if is_running else None,
        "log_path": str(HONEYPOT_LOG),
        "total_captures": captures,
        "unique_attacker_ips": len(unique_ips),
        "attacker_ips": list(unique_ips)[:20],
    }


def read_honeypot_logs(lines: int = 50, ip_filter: str | None = None) -> dict:
    """Read recent honeypot captures — attacker IPs, credentials tried, commands run.
    lines: number of recent entries to return (default: 50).
    ip_filter: optional IP address to filter captures for a specific attacker.
    Returns structured captures with IP, service, credentials, and commands.
    """
    if not HONEYPOT_LOG.exists():
        return {"error": "No honeypot log found. Deploy honeypot first with deploy_honeypot()"}

    lines = min(max(1, lines), 500)
    entries = []
    try:
        raw_lines = HONEYPOT_LOG.read_text().splitlines()
        for line in reversed(raw_lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("src_ip") or entry.get("ip", "")
                if ip_filter and ip != ip_filter:
                    continue
                entries.append({
                    "timestamp": entry.get("timestamp") or entry.get("time", ""),
                    "service": entry.get("server_type") or entry.get("service", ""),
                    "attacker_ip": ip,
                    "attacker_port": entry.get("src_port"),
                    "credentials_tried": {
                        "username": entry.get("username", ""),
                        "password": entry.get("password", ""),
                    },
                    "commands": entry.get("commands", []),
                    "data": entry.get("data", "")[:300],
                })
                if len(entries) >= lines:
                    break
            except json.JSONDecodeError:
                continue
    except Exception as e:
        return {"error": str(e)}

    # Summary stats
    from collections import Counter
    ips = [e["attacker_ip"] for e in entries if e["attacker_ip"]]
    services = [e["service"] for e in entries if e["service"]]
    users = [e["credentials_tried"]["username"] for e in entries if e["credentials_tried"]["username"]]
    passwords = [e["credentials_tried"]["password"] for e in entries if e["credentials_tried"]["password"]]

    return {
        "tool": "honeypot_logs",
        "total_entries": len(entries),
        "top_attacker_ips": dict(Counter(ips).most_common(10)),
        "top_targeted_services": dict(Counter(services).most_common(5)),
        "top_usernames_tried": dict(Counter(users).most_common(10)),
        "top_passwords_tried": dict(Counter(passwords).most_common(10)),
        "entries": entries,
    }


def stop_honeypot() -> dict:
    """Stop the running honeypot."""
    if not HONEYPOT_PID.exists():
        return {"status": "not_running"}
    try:
        pid = int(HONEYPOT_PID.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        HONEYPOT_PID.unlink(missing_ok=True)
        return {"status": "stopped", "pid": pid}
    except Exception as e:
        return {"error": str(e)}


TOOLS = {
    "deploy_honeypot": {
        "fn": deploy_honeypot,
        "description": (
            "Deploy a multi-service honeypot to capture attacker activity. "
            "Creates fake SSH, HTTP, FTP, MySQL, and other services that log attacker IPs, "
            "credentials tried, and commands executed. Runs in background."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Services to fake: ['ssh', 'http', 'ftp', 'telnet', 'mysql', 'redis', 'rdp', 'vnc']. Default: ssh, http, ftp, telnet"
                },
                "log_path": {"type": "string", "description": "Path to write capture logs (default: /opt/argos/logs/honeypot.json)"}
            },
            "required": []
        }
    },
    "honeypot_status": {
        "fn": honeypot_status,
        "description": "Check honeypot status: running/stopped, total captures, unique attacker IPs.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "read_honeypot_logs": {
        "fn": read_honeypot_logs,
        "description": (
            "Read honeypot captures: attacker IPs, credentials tried, commands executed. "
            "Shows top attacker IPs, most-tried usernames/passwords, targeted services."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "description": "Number of recent entries to return (default: 50)"},
                "ip_filter": {"type": "string", "description": "Optional: filter captures from a specific IP"}
            },
            "required": []
        }
    },
    "stop_honeypot": {
        "fn": stop_honeypot,
        "description": "Stop the running honeypot.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    }
}
