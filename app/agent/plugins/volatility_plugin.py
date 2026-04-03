"""
ARGOS Plugin: Volatility 3 Memory Forensics
Memory dump analysis using Volatility 3 (vol / vol3).
"""

import os
import re
import shutil
import subprocess

MANIFEST = {
    "id": "volatility-forensics",
    "name": "Volatility Memory Forensics",
    "description": (
        "Memory dump analysis powered by Volatility 3. "
        "Extracts process lists, network connections, malicious memory regions, "
        "password hashes, command-line arguments, and OS information."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

_SUBPROCESS_TIMEOUT = 120

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _vol_binary() -> str | None:
    """Return the first available Volatility binary (vol3 preferred, then vol)."""
    for candidate in ("vol3", "vol"):
        if shutil.which(candidate):
            return candidate
    return None


def _run(cmd: list) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    return result.returncode, result.stdout, result.stderr


def _not_installed() -> dict:
    return {
        "error": (
            "vol / vol3 not installed. "
            "Install: pip install volatility3  "
            "or see https://github.com/volatilityfoundation/volatility3"
        )
    }


def _dump_missing(dump_path: str) -> dict | None:
    if not os.path.exists(dump_path):
        return {"error": f"Memory dump not found: {dump_path}"}
    return None


def _parse_vol_table(stdout: str) -> list[dict]:
    """
    Parse Volatility 3 TSV-like tab-separated table output.
    First non-empty line is treated as the header.
    """
    rows: list[dict] = []
    lines = [l for l in stdout.splitlines() if l.strip()]
    if not lines:
        return rows

    # Detect header: first line that doesn't start with a warning/error marker
    header_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip progress/warning lines
        if stripped.startswith(("Volatility", "WARNING", "ERROR", "Progress", "*")):
            continue
        header_idx = i
        break

    header_line = lines[header_idx]
    # Volatility 3 uses tab-separated columns
    sep = "\t" if "\t" in header_line else None
    headers = [h.strip() for h in (header_line.split(sep) if sep else header_line.split())]

    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("WARNING", "ERROR", "Progress", "*", "Volatility")):
            continue
        cols = [c.strip() for c in (line.split(sep) if sep else line.split())]
        row = {}
        for i, h in enumerate(headers):
            row[h] = cols[i] if i < len(cols) else ""
        rows.append(row)

    return rows


def _detect_os(stdout: str) -> str:
    """Guess OS from vol info/banner output."""
    text = stdout.lower()
    if "windows" in text or "ntoskrnl" in text or "win32" in text:
        return "windows"
    if "linux" in text:
        return "linux"
    if "darwin" in text or "macos" in text or "xnu" in text:
        return "macos"
    return "unknown"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def volatility_info(dump_path: str) -> dict:
    """
    Extract OS and architecture information from a memory dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    # Try windows.info first; on failure fall back to linux.banner
    rc, stdout, stderr = _run([vol, "-f", dump_path, "windows.info"])
    if rc != 0 or not stdout.strip():
        rc, stdout, stderr = _run([vol, "-f", dump_path, "linux.banner"])

    detected_os = _detect_os(stdout + stderr)

    # Extract key-value pairs from output (e.g. "Kernel Base\t0xf80000000000")
    kv: dict = {}
    for line in stdout.splitlines():
        if "\t" in line:
            key, _, val = line.partition("\t")
            kv[key.strip()] = val.strip()

    return {
        "os": detected_os,
        "architecture": kv.get("Is64Bit", kv.get("Architecture", "unknown")),
        "kernel_version": kv.get("NtBuildLab", kv.get("Kernel Version", "unknown")),
        "profile": kv.get("Layer name", kv.get("Suggested Profile(s)", "unknown")),
        "raw": kv,
    }


def volatility_pslist(dump_path: str) -> dict:
    """
    List all processes found in a memory dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    # Auto-detect OS to choose the right plugin
    info = volatility_info(dump_path)
    detected_os = info.get("os", "unknown")
    plugin = "linux.pslist" if detected_os == "linux" else "windows.pslist"

    rc, stdout, stderr = _run([vol, "-f", dump_path, plugin])

    rows = _parse_vol_table(stdout)
    processes: list[dict] = []
    for row in rows:
        # Normalize column names across Windows/Linux plugins
        processes.append(
            {
                "pid": row.get("PID", row.get("Pid", "")),
                "ppid": row.get("PPID", row.get("PPid", "")),
                "name": row.get("ImageFileName", row.get("COMM", row.get("Name", ""))),
                "offset": row.get("Offset(V)", row.get("Offset", "")),
                "create_time": row.get("CreateTime", row.get("Start", "")),
            }
        )

    return {"processes": processes, "total": len(processes)}


def volatility_netscan(dump_path: str) -> dict:
    """
    Extract network connections from a memory dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    info = volatility_info(dump_path)
    detected_os = info.get("os", "unknown")
    plugin = "linux.netstat" if detected_os == "linux" else "windows.netscan"

    rc, stdout, stderr = _run([vol, "-f", dump_path, plugin])
    rows = _parse_vol_table(stdout)

    connections: list[dict] = []
    for row in rows:
        connections.append(
            {
                "offset": row.get("Offset", row.get("Offset(V)", "")),
                "proto": row.get("Proto", row.get("Type", "")),
                "local_addr": row.get("LocalAddr", row.get("Laddr", "")),
                "local_port": row.get("LocalPort", row.get("Lport", "")),
                "remote_addr": row.get("ForeignAddr", row.get("Raddr", "")),
                "remote_port": row.get("ForeignPort", row.get("Rport", "")),
                "state": row.get("State", ""),
                "pid": row.get("PID", row.get("Pid", "")),
                "owner": row.get("Owner", ""),
                "created": row.get("Created", ""),
            }
        )

    return {"connections": connections, "total": len(connections)}


def volatility_malfind(dump_path: str) -> dict:
    """
    Identify suspicious memory regions (code injection, shellcode) in a dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    rc, stdout, stderr = _run([vol, "-f", dump_path, "windows.malfind"])
    rows = _parse_vol_table(stdout)

    regions: list[dict] = []
    for row in rows:
        regions.append(
            {
                "pid": row.get("PID", row.get("Pid", "")),
                "process": row.get("Process", row.get("ImageFileName", "")),
                "start": row.get("Start VPN", row.get("Start", "")),
                "end": row.get("End VPN", row.get("End", "")),
                "protection": row.get("Protection", row.get("VadProtection", "")),
                "tag": row.get("Tag", ""),
                "hex_dump": row.get("Hexdump", ""),
                "disasm": row.get("Disasm", ""),
            }
        )

    return {"suspicious_regions": regions, "total": len(regions)}


def volatility_hashdump(dump_path: str) -> dict:
    """
    Extract NTLM password hashes from a Windows memory dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    rc, stdout, stderr = _run([vol, "-f", dump_path, "windows.hashdump"])

    hashes: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("Volatility", "WARNING", "User")):
            continue
        # Format: Username:RID:LMHash:NTLMHash:::
        parts = line.split(":")
        if len(parts) >= 4:
            hashes.append(
                {
                    "user": parts[0],
                    "rid": parts[1] if len(parts) > 1 else "",
                    "lm": parts[2] if len(parts) > 2 else "",
                    "ntlm": parts[3] if len(parts) > 3 else "",
                }
            )

    return {"hashes": hashes, "total": len(hashes)}


def volatility_cmdline(dump_path: str) -> dict:
    """
    Extract command-line arguments for each process in a memory dump.

    Parameters
    ----------
    dump_path : Absolute path to the memory dump file.
    """
    vol = _vol_binary()
    if not vol:
        return _not_installed()
    err = _dump_missing(dump_path)
    if err:
        return err

    rc, stdout, stderr = _run([vol, "-f", dump_path, "windows.cmdline"])

    cmdlines: list[dict] = []
    current: dict | None = None

    for line in stdout.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith(("Volatility", "WARNING", "ERROR", "PID")):
            continue

        # Volatility 3 windows.cmdline output:
        # <PID>    <Process>    <Args>
        parts = line_stripped.split("\t")
        if len(parts) >= 3:
            cmdlines.append(
                {
                    "pid": parts[0].strip(),
                    "process": parts[1].strip(),
                    "cmdline": "\t".join(parts[2:]).strip(),
                }
            )
        elif len(parts) == 1 and current:
            # Continuation line (args wrapped)
            current["cmdline"] += " " + line_stripped

    return {"cmdlines": cmdlines, "total": len(cmdlines)}


# ---------------------------------------------------------------------------
# ARGOS TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "volatility_info": {
        "fn": volatility_info,
        "description": (
            "Extract OS, architecture, and kernel version from a memory dump "
            "using Volatility 3 (windows.info / linux.banner)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the memory dump file (.raw, .vmem, .lime, etc.).",
                }
            },
            "required": ["dump_path"],
        },
    },
    "volatility_pslist": {
        "fn": volatility_pslist,
        "description": (
            "List all processes from a memory dump. "
            "Auto-detects Windows/Linux and uses the appropriate plugin."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the memory dump file.",
                }
            },
            "required": ["dump_path"],
        },
    },
    "volatility_netscan": {
        "fn": volatility_netscan,
        "description": "Extract network connections and sockets from a memory dump.",
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the memory dump file.",
                }
            },
            "required": ["dump_path"],
        },
    },
    "volatility_malfind": {
        "fn": volatility_malfind,
        "description": (
            "Find suspicious memory regions indicative of code injection or shellcode "
            "using windows.malfind."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the memory dump file.",
                }
            },
            "required": ["dump_path"],
        },
    },
    "volatility_hashdump": {
        "fn": volatility_hashdump,
        "description": (
            "Extract NTLM and LM password hashes from a Windows memory dump "
            "using windows.hashdump."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the Windows memory dump file.",
                }
            },
            "required": ["dump_path"],
        },
    },
    "volatility_cmdline": {
        "fn": volatility_cmdline,
        "description": (
            "Extract command-line arguments for every process in a Windows memory dump "
            "using windows.cmdline. Useful for detecting payload execution patterns."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Absolute path to the Windows memory dump file.",
                }
            },
            "required": ["dump_path"],
        },
    },
}
