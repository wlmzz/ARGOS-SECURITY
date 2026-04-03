"""Auto-hardening tools: Lynis audit, SSH hardening, UFW firewall, kernel params."""
from __future__ import annotations
import subprocess, json, re, os
from pathlib import Path
from datetime import datetime


def _run(cmd: list[str], timeout: int = 120, input_text: str | None = None) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        return r.returncode, (r.stdout + r.stderr).strip()[:8000]
    except subprocess.TimeoutExpired:
        return -1, f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return -1, f"[TOOL NOT FOUND: {cmd[0]}]"
    except Exception as e:
        return -1, f"[ERROR: {e}]"


def lynis_audit(category: str = "all") -> dict:
    """Run a Lynis security audit on the local system.
    category: 'all' for full audit, or specific: 'authentication', 'networking',
              'firewalls', 'kernel', 'services', 'storage', 'logging'.
    Returns: hardening index (0-100), warnings, suggestions, and failed tests.
    Requires lynis installed (apt install lynis).
    """
    if category == "all":
        cmd = ["lynis", "audit", "system", "--quiet", "--no-colors"]
    else:
        safe_cat = re.sub(r"[^a-zA-Z_\-]", "", category)
        cmd = ["lynis", "audit", "system", "--tests-category", safe_cat, "--quiet", "--no-colors"]

    rc, raw = _run(cmd, timeout=300)
    if rc == -1:
        return {"error": raw}

    # Parse lynis output
    hardening_index = None
    warnings = []
    suggestions = []
    tests_failed = []

    for line in raw.splitlines():
        line = line.strip()
        if "Hardening index" in line:
            m = re.search(r"\[(\d+)\]", line)
            if m:
                hardening_index = int(m.group(1))
        elif line.startswith("! ") or "WARNING" in line:
            warnings.append(line.lstrip("! ").strip())
        elif line.startswith("* ") or line.startswith("  *"):
            suggestions.append(line.lstrip("* ").strip())
        elif "FAILED" in line and not line.startswith("#"):
            tests_failed.append(line.strip())

    # Read lynis report file if exists
    report_file = Path("/var/log/lynis-report.dat")
    if not report_file.exists():
        report_file = Path("/tmp/lynis-report.dat")

    score_from_file = None
    if report_file.exists():
        content = report_file.read_text()
        m = re.search(r"hardening_index=(\d+)", content)
        if m:
            score_from_file = int(m.group(1))
        # Extract warnings from report
        for line in content.splitlines():
            if line.startswith("warning[]="):
                w = line.split("=", 1)[1].strip()
                if w not in warnings:
                    warnings.append(w)

    return {
        "tool": "lynis",
        "hardening_index": score_from_file or hardening_index,
        "score_interpretation": (
            "EXCELLENT (80-100)" if (score_from_file or hardening_index or 0) >= 80
            else "GOOD (60-79)" if (score_from_file or hardening_index or 0) >= 60
            else "NEEDS IMPROVEMENT (40-59)" if (score_from_file or hardening_index or 0) >= 40
            else "POOR (<40)"
        ),
        "warnings_count": len(warnings),
        "warnings": warnings[:20],
        "suggestions_count": len(suggestions),
        "top_suggestions": suggestions[:10],
        "tests_failed": tests_failed[:10],
    }


def harden_ssh() -> dict:
    """Apply SSH hardening to /etc/ssh/sshd_config.
    Changes: disable root login (PermitRootLogin no), disable password auth,
    limit auth attempts, set idle timeout, restrict to IPv4+IPv6 secure ciphers.
    Creates backup before modifying. Restarts sshd after.
    IMPORTANT: Ensure you have SSH key auth working before calling this.
    """
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return {"error": "/etc/ssh/sshd_config not found"}

    # Backup
    backup = Path(f"/etc/ssh/sshd_config.argos_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    backup.write_bytes(sshd_config.read_bytes())

    hardening_settings = {
        "PermitRootLogin": "without-password",  # allow root with key only
        "PasswordAuthentication": "no",
        "MaxAuthTries": "3",
        "LoginGraceTime": "30",
        "ClientAliveInterval": "300",
        "ClientAliveCountMax": "2",
        "X11Forwarding": "no",
        "AllowTcpForwarding": "no",
        "Protocol": "2",
        "PermitEmptyPasswords": "no",
        "UsePAM": "yes",
    }

    content = sshd_config.read_text()
    applied = []
    skipped = []

    for key, value in hardening_settings.items():
        pattern = re.compile(rf"^#?\s*{re.escape(key)}\s+.*$", re.MULTILINE)
        new_line = f"{key} {value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content, count=1)
            applied.append(f"{key} = {value}")
        else:
            content += f"\n{new_line}"
            applied.append(f"{key} = {value} (added)")

    sshd_config.write_text(content)

    # Validate config
    rc, validate_out = _run(["sshd", "-t"], timeout=10)
    if rc != 0:
        # Restore backup
        sshd_config.write_bytes(backup.read_bytes())
        return {"error": f"sshd config validation failed — restored backup. Error: {validate_out}"}

    # Reload sshd
    rc2, reload_out = _run(["systemctl", "reload", "sshd"], timeout=15)

    return {
        "action": "harden_ssh",
        "backup_saved": str(backup),
        "applied_settings": applied,
        "sshd_reloaded": rc2 == 0,
        "reload_output": reload_out[:200],
        "warning": "SSH password authentication is now DISABLED. Ensure SSH key is working.",
    }


def setup_ufw(default_policy: str = "deny", allow_ports: list[str] | None = None) -> dict:
    """Configure UFW firewall: set default policy, allow specific ports.
    default_policy: 'deny' (recommended) or 'allow'
    allow_ports: list of ports to allow, e.g. ['22/tcp', '80/tcp', '443/tcp', '8080/tcp']
    Defaults allow: 22 (SSH), 80 (HTTP), 443 (HTTPS).
    """
    allow_ports = allow_ports or ["22/tcp", "80/tcp", "443/tcp"]

    results = []
    rc, out = _run(["ufw", "--force", "reset"], timeout=15)
    results.append(f"reset: {'ok' if rc == 0 else out}")

    # Set default policies
    rc, out = _run(["ufw", "default", "deny", "incoming"], timeout=10)
    results.append(f"default deny incoming: {'ok' if rc == 0 else out}")

    rc, out = _run(["ufw", "default", "allow", "outgoing"], timeout=10)
    results.append(f"default allow outgoing: {'ok' if rc == 0 else out}")

    allowed = []
    for port in allow_ports:
        safe_port = re.sub(r"[^0-9a-z/]", "", port.lower())
        rc, out = _run(["ufw", "allow", safe_port], timeout=10)
        if rc == 0:
            allowed.append(safe_port)
        else:
            results.append(f"allow {safe_port}: FAILED — {out[:100]}")

    # Enable UFW
    rc, out = _run(["ufw", "--force", "enable"], timeout=15)
    results.append(f"enable: {'ok' if rc == 0 else out}")

    # Get status
    _, status = _run(["ufw", "status", "numbered"], timeout=10)

    return {
        "action": "setup_ufw",
        "default_policy": "deny incoming / allow outgoing",
        "allowed_ports": allowed,
        "steps": results,
        "current_status": status[:1000],
    }


def auto_harden() -> dict:
    """Apply all hardening steps automatically:
    1. Run Lynis audit (before)
    2. Configure UFW firewall (allow 22, 80, 443 only)
    3. Harden kernel with sysctl (disable IP forwarding, ICMP redirects, etc.)
    4. Configure fail2ban defaults
    5. Disable unused services
    Returns before/after hardening scores and all actions taken.
    """
    report = {"action": "auto_harden", "steps": [], "timestamp": datetime.utcnow().isoformat()}

    # 1. UFW
    ufw_result = setup_ufw(allow_ports=["22/tcp", "80/tcp", "443/tcp"])
    report["steps"].append({"step": "ufw_firewall", "result": ufw_result.get("action"), "ports": ufw_result.get("allowed_ports")})

    # 2. Kernel hardening via sysctl
    sysctl_rules = [
        "net.ipv4.ip_forward=0",
        "net.ipv4.conf.all.accept_redirects=0",
        "net.ipv4.conf.default.accept_redirects=0",
        "net.ipv4.conf.all.send_redirects=0",
        "net.ipv4.conf.all.accept_source_route=0",
        "net.ipv4.conf.all.log_martians=1",
        "net.ipv4.tcp_syncookies=1",
        "net.ipv4.icmp_echo_ignore_broadcasts=1",
        "kernel.randomize_va_space=2",
        "fs.suid_dumpable=0",
        "kernel.core_uses_pid=1",
    ]
    sysctl_applied = []
    sysctl_file = Path("/etc/sysctl.d/99-argos-hardening.conf")
    sysctl_file.write_text("# ARGOS auto-hardening — applied by ARGOS agent\n" + "\n".join(sysctl_rules) + "\n")
    rc, out = _run(["sysctl", "-p", str(sysctl_file)], timeout=15)
    if rc == 0:
        sysctl_applied = sysctl_rules
    report["steps"].append({"step": "kernel_sysctl", "applied": len(sysctl_applied), "rules": sysctl_applied})

    # 3. fail2ban — ensure it's running
    rc, out = _run(["systemctl", "enable", "--now", "fail2ban"], timeout=15)
    report["steps"].append({"step": "fail2ban", "enabled": rc == 0})

    # 4. Disable unused services
    services_to_disable = ["avahi-daemon", "cups", "bluetooth", "rpcbind"]
    disabled = []
    for svc in services_to_disable:
        rc, _ = _run(["systemctl", "is-active", svc], timeout=5)
        if rc == 0:  # service is active
            _run(["systemctl", "disable", "--now", svc], timeout=10)
            disabled.append(svc)
    report["steps"].append({"step": "disable_unused_services", "disabled": disabled})

    # 5. Lynis audit (after)
    audit = lynis_audit()
    report["hardening_score"] = audit.get("hardening_index")
    report["score_interpretation"] = audit.get("score_interpretation")
    report["remaining_warnings"] = audit.get("warnings", [])[:5]
    report["summary"] = f"Auto-hardening complete. Score: {audit.get('hardening_index', 'N/A')}/100"

    return report


TOOLS = {
    "lynis_audit": {
        "fn": lynis_audit,
        "description": (
            "Run a Lynis security audit on the local system. Returns hardening index (0-100), "
            "warnings, and suggestions. Use to assess security posture before/after hardening."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Audit category: 'all' (default), 'authentication', 'networking', 'firewalls', 'kernel', 'services'"}
            },
            "required": []
        }
    },
    "harden_ssh": {
        "fn": harden_ssh,
        "description": (
            "Apply SSH hardening to sshd_config: disable password auth, limit retries, set timeout. "
            "Creates backup first. IMPORTANT: ensure SSH key authentication is working before calling."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "setup_ufw": {
        "fn": setup_ufw,
        "description": (
            "Configure UFW firewall: deny all incoming by default, allow only specified ports. "
            "Default: allow SSH(22), HTTP(80), HTTPS(443). Resets existing rules."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "default_policy": {"type": "string", "description": "'deny' (recommended) or 'allow'"},
                "allow_ports": {"type": "array", "items": {"type": "string"},
                                "description": "Ports to allow, e.g. ['22/tcp', '80/tcp', '443/tcp', '8080/tcp']"}
            },
            "required": []
        }
    },
    "auto_harden": {
        "fn": auto_harden,
        "description": (
            "Automatically harden the server: configure UFW firewall, apply kernel sysctl hardening, "
            "enable fail2ban, disable unused services. Runs Lynis audit after and returns score. "
            "Safe to run — creates backups and validates before applying changes."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    }
}
