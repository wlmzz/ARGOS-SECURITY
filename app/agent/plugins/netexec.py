"""
ARGOS Plugin: NetExec (nxc)
Network authentication and credential testing — successor to CrackMapExec.
Supports SMB, SSH, LDAP, WinRM, FTP, RDP, VNC, MSSQL and more.

Install: pipx install git+https://github.com/Pennyw0rth/NetExec
Repo: https://github.com/Pennyw0rth/NetExec

⚠️  AUTHORIZED PENETRATION TESTING ONLY.
    Never use against systems you don't own or lack explicit written permission to test.
"""
from __future__ import annotations
import os
import re
import subprocess
from typing import Optional

MANIFEST = {
    "id":          "netexec",
    "name":        "NetExec",
    "description": "Network authentication testing (SMB/SSH/LDAP/WinRM). Successor to CrackMapExec. Authorized pentesting only.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_MAX_TIMEOUT = 120


def _check_nxc() -> bool:
    return subprocess.run(["which", "nxc"], capture_output=True).returncode == 0


def _run_nxc(args: list[str], timeout: int = _MAX_TIMEOUT) -> dict:
    if not _check_nxc():
        return {
            "error": (
                "nxc (NetExec) not found. Install: "
                "pipx install git+https://github.com/Pennyw0rth/NetExec"
            )
        }
    try:
        proc = subprocess.run(
            ["nxc"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        output = proc.stdout + proc.stderr
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        return {"output": lines, "exit_code": proc.returncode, "raw": output[-4000:]}
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def _parse_nxc_output(lines: list[str]) -> dict:
    """Parse nxc color-coded output into structured results."""
    success = []
    failed  = []
    info    = []

    for line in lines:
        # [+] = success (green), [-] = failed (red), [*] = info
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line)  # strip ANSI
        if "[+]" in clean:
            success.append(clean)
        elif "[-]" in clean:
            failed.append(clean[:200])
        elif "[*]" in clean:
            info.append(clean)

    return {"successes": success, "failed_count": len(failed), "info": info}


def netexec_smb(target: str, username: str = "", password: str = "",
                options: str = "", timeout: int = 60) -> dict:
    """Test SMB authentication and enumerate Windows/Samba shares, users, groups.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    Without credentials: anonymous/null session probe.
    With credentials: share listing, user/group enumeration.
    options examples: '--shares', '--users', '--groups', '--sam', '--pass-pol'
    """
    if not re.match(r"^[a-zA-Z0-9.\-/,: ]+$", target):
        return {"error": "Invalid target format"}

    args = ["smb", target]
    if username:
        args += ["-u", username]
    if password:
        args += ["-p", password]
    if options:
        for opt in options.split():
            if re.match(r"^--?[a-zA-Z0-9\-_]+$", opt):
                args.append(opt)

    result = _run_nxc(args, timeout)
    if "error" in result:
        return result

    parsed = _parse_nxc_output(result["output"])
    return {
        "target":    target,
        "protocol":  "SMB",
        "source":    "NetExec",
        "auth_success": bool(parsed["successes"]),
        **parsed,
        "raw_output": result.get("raw", ""),
    }


def netexec_ssh(target: str, username: str, password: str = "",
                key_file: str = "", command: str = "", timeout: int = 60) -> dict:
    """Test SSH authentication and optionally execute a command.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    key_file: path to private key file (alternative to password)
    command: shell command to run on success (e.g. 'id', 'whoami')
    """
    if not re.match(r"^[a-zA-Z0-9.\-/,:]+$", target):
        return {"error": "Invalid target format"}
    if not username:
        return {"error": "Username required for SSH"}

    args = ["ssh", target, "-u", username]
    if password:
        args += ["-p", password]
    if key_file and os.path.exists(key_file):
        args += ["--key-file", key_file]
    if command:
        # Sanitize command — no shell injection
        safe_cmd = re.sub(r"[;&|`$]", "", command)
        args += ["-x", safe_cmd]

    result = _run_nxc(args, timeout)
    if "error" in result:
        return result

    parsed = _parse_nxc_output(result["output"])
    return {
        "target":    target,
        "protocol":  "SSH",
        "source":    "NetExec",
        "auth_success": bool(parsed["successes"]),
        **parsed,
        "raw_output": result.get("raw", ""),
    }


def netexec_ldap(target: str, username: str = "", password: str = "",
                 domain: str = "", options: str = "", timeout: int = 60) -> dict:
    """Enumerate Active Directory via LDAP: users, groups, kerberoasting, AS-REP roasting.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    options examples: '--users', '--groups', '--kerberoasting out.txt', '--asreproast out.txt', '--bloodhound'
    """
    if not re.match(r"^[a-zA-Z0-9.\-/,:]+$", target):
        return {"error": "Invalid target format"}

    args = ["ldap", target]
    if username:
        args += ["-u", username]
    if password:
        args += ["-p", password]
    if domain:
        args += ["-d", domain]
    if options:
        for opt in options.split():
            if re.match(r"^--?[a-zA-Z0-9\-_./]+$", opt):
                args.append(opt)

    result = _run_nxc(args, timeout)
    if "error" in result:
        return result

    parsed = _parse_nxc_output(result["output"])
    return {
        "target":    target,
        "protocol":  "LDAP",
        "source":    "NetExec",
        "auth_success": bool(parsed["successes"]),
        **parsed,
        "raw_output": result.get("raw", ""),
    }


def netexec_winrm(target: str, username: str, password: str = "",
                  command: str = "", timeout: int = 60) -> dict:
    """Test WinRM (Windows Remote Management) authentication and execute commands.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.
    """
    if not re.match(r"^[a-zA-Z0-9.\-/,:]+$", target):
        return {"error": "Invalid target format"}
    if not username:
        return {"error": "Username required for WinRM"}

    args = ["winrm", target, "-u", username]
    if password:
        args += ["-p", password]
    if command:
        safe_cmd = re.sub(r"[;&|`$]", "", command)
        args += ["-x", safe_cmd]

    result = _run_nxc(args, timeout)
    if "error" in result:
        return result

    parsed = _parse_nxc_output(result["output"])
    return {
        "target":    target,
        "protocol":  "WinRM",
        "source":    "NetExec",
        "auth_success": bool(parsed["successes"]),
        **parsed,
        "raw_output": result.get("raw", ""),
    }


TOOLS = {
    "netexec_smb": {
        "fn": netexec_smb,
        "description": (
            "Test SMB (port 445) authentication and enumerate Windows/Samba: shares, users, groups, password policy. "
            "Use without credentials for null-session probe. "
            "options: '--shares', '--users', '--groups', '--sam', '--pass-pol'. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY. Requires NetExec (nxc) installed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":   {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                "username": {"type": "string", "description": "Username (empty for anonymous probe)"},
                "password": {"type": "string", "description": "Password"},
                "options":  {"type": "string", "description": "Additional nxc flags (e.g. '--shares --users')"},
                "timeout":  {"type": "integer","description": "Timeout in seconds (default: 60)"},
            },
            "required": ["target"]
        }
    },
    "netexec_ssh": {
        "fn": netexec_ssh,
        "description": (
            "Test SSH authentication on a target and optionally execute a command. "
            "Can use password or key file for auth. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY. Requires NetExec (nxc) installed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":   {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "SSH username"},
                "password": {"type": "string", "description": "SSH password"},
                "key_file": {"type": "string", "description": "Path to private key file"},
                "command":  {"type": "string", "description": "Shell command to execute on success (e.g. 'id')"},
                "timeout":  {"type": "integer","description": "Timeout in seconds (default: 60)"},
            },
            "required": ["target", "username"]
        }
    },
    "netexec_ldap": {
        "fn": netexec_ldap,
        "description": (
            "Enumerate Active Directory via LDAP: users, groups, Kerberoastable accounts, AS-REP roastable accounts. "
            "options: '--users', '--groups', '--kerberoasting out.txt', '--asreproast out.txt'. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY. Requires NetExec (nxc) installed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":   {"type": "string", "description": "Domain controller IP or hostname"},
                "username": {"type": "string", "description": "Domain username"},
                "password": {"type": "string", "description": "Password"},
                "domain":   {"type": "string", "description": "Domain name (e.g. 'corp.local')"},
                "options":  {"type": "string", "description": "Additional flags (e.g. '--users --groups')"},
                "timeout":  {"type": "integer","description": "Timeout in seconds (default: 60)"},
            },
            "required": ["target"]
        }
    },
    "netexec_winrm": {
        "fn": netexec_winrm,
        "description": (
            "Test Windows Remote Management (WinRM, ports 5985/5986) authentication and run commands. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY. Requires NetExec (nxc) installed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":   {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "Windows username"},
                "password": {"type": "string", "description": "Password"},
                "command":  {"type": "string", "description": "Command to execute on success"},
                "timeout":  {"type": "integer","description": "Timeout in seconds (default: 60)"},
            },
            "required": ["target", "username"]
        }
    },
}
