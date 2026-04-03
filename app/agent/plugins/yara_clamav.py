"""
ARGOS Plugin: YARA + ClamAV
Malware scanning via YARA rules and ClamAV antivirus engine.
"""

import os
import re
import shutil
import subprocess
import tempfile

MANIFEST = {
    "id": "yara-clamav",
    "name": "YARA & ClamAV Scanner",
    "description": (
        "Malware detection using YARA rule-based scanning and ClamAV antivirus. "
        "Supports file/directory scanning, process memory inspection, "
        "custom rule management, and ClamAV definition updates."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

_SUBPROCESS_TIMEOUT = 120

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_BUILTIN_RULE = r"""
rule SuspiciousStrings
{
    meta:
        description = "Detects common suspicious strings"
        author      = "ARGOS builtin"
    strings:
        $mz  = { 4D 5A }
        $cmd = "cmd.exe" nocase
        $ps  = "powershell" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        any of them
}
"""


def _yara_available() -> bool:
    return shutil.which("yara") is not None


def _run(cmd: list, *, cwd: str | None = None, input_data: str | None = None) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        cwd=cwd,
        input=input_data,
    )
    return result.returncode, result.stdout, result.stderr


def _collect_yar_files(rules_dir: str) -> list[str]:
    """Return list of .yar/.yara files in rules_dir (non-recursive glob)."""
    files = []
    if os.path.isdir(rules_dir):
        for root, _dirs, names in os.walk(rules_dir):
            for name in names:
                if name.endswith((".yar", ".yara")):
                    files.append(os.path.join(root, name))
    return files


def _parse_yara_output(stdout: str) -> list[dict]:
    """
    Parse YARA text output. Each line has the format:
        RuleName [tag1,tag2] TargetPath
    or (no tags):
        RuleName TargetPath
    """
    matches = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Pattern: RULE_NAME [tags] FILE
        m = re.match(r"^(\S+)\s+(?:\[([^\]]*)\]\s+)?(.+)$", line)
        if m:
            rule = m.group(1)
            tags_raw = m.group(2) or ""
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
            file_path = m.group(3).strip()
            matches.append({"rule": rule, "file": file_path, "tags": tags, "meta": {}})
    return matches


def _ensure_builtin_rule() -> str:
    """Write builtin rule to a temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        suffix=".yar", delete=False, mode="w", prefix="argos_builtin_"
    )
    tmp.write(_BUILTIN_RULE)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def yara_scan(path: str, rules_dir: str = "/opt/argos/yara_rules") -> dict:
    """
    Scan a file or directory with YARA rules.

    Parameters
    ----------
    path      : Target file or directory to scan.
    rules_dir : Directory containing .yar/.yara rule files.
                Falls back to a builtin rule if dir is empty/missing.
    """
    if not _yara_available():
        return {"error": "yara not installed. Install: sudo apt install yara  |  brew install yara"}

    if not os.path.exists(path):
        return {"error": f"Path does not exist: {path}"}

    tmp_rule = None
    yar_files = _collect_yar_files(rules_dir)

    if not yar_files:
        tmp_rule = _ensure_builtin_rule()
        yar_files = [tmp_rule]

    all_matches: list[dict] = []
    files_scanned = 0

    try:
        for rule_file in yar_files:
            cmd = ["yara", "-r", rule_file, path]
            rc, stdout, stderr = _run(cmd)
            # yara exits 0 (match) or 1 (no match) – both are normal
            parsed = _parse_yara_output(stdout)
            all_matches.extend(parsed)

        # Count scanned files
        if os.path.isdir(path):
            for _, _, fnames in os.walk(path):
                files_scanned += len(fnames)
        else:
            files_scanned = 1

    finally:
        if tmp_rule and os.path.exists(tmp_rule):
            os.unlink(tmp_rule)

    return {
        "matches": all_matches,
        "total_matches": len(all_matches),
        "files_scanned": files_scanned,
    }


def yara_scan_process(pid: int, rules_dir: str = "/opt/argos/yara_rules") -> dict:
    """
    Scan a running process memory with YARA rules.

    Parameters
    ----------
    pid       : Process ID to scan.
    rules_dir : Directory containing .yar/.yara rule files.
    """
    if not _yara_available():
        return {"error": "yara not installed. Install: sudo apt install yara  |  brew install yara"}

    tmp_rule = None
    yar_files = _collect_yar_files(rules_dir)

    if not yar_files:
        tmp_rule = _ensure_builtin_rule()
        yar_files = [tmp_rule]

    all_matches: list[dict] = []

    try:
        for rule_file in yar_files:
            # YARA accepts a PID string as the target to scan process memory
            cmd = ["yara", rule_file, str(pid)]
            rc, stdout, stderr = _run(cmd)
            parsed = _parse_yara_output(stdout)
            all_matches.extend(parsed)
    finally:
        if tmp_rule and os.path.exists(tmp_rule):
            os.unlink(tmp_rule)

    return {
        "pid": pid,
        "matches": all_matches,
        "total_matches": len(all_matches),
    }


def yara_add_rule(name: str, rule_content: str, category: str = "custom") -> dict:
    """
    Save a new YARA rule to the rules directory and validate its syntax.

    Parameters
    ----------
    name         : Rule filename (without extension).
    rule_content : Full YARA rule text.
    category     : Sub-directory category (default: "custom").
    """
    if not _yara_available():
        return {"error": "yara not installed. Install: sudo apt install yara  |  brew install yara"}

    safe_name = re.sub(r"[^\w\-]", "_", name)
    safe_cat = re.sub(r"[^\w\-]", "_", category)

    dest_dir = os.path.join("/opt/argos/yara_rules", safe_cat)
    os.makedirs(dest_dir, exist_ok=True)

    dest_path = os.path.join(dest_dir, f"{safe_name}.yar")

    # Write rule to destination
    with open(dest_path, "w") as fh:
        fh.write(rule_content)

    # Validate syntax: yara <rule_file> /dev/null
    rc, stdout, stderr = _run(["yara", dest_path, "/dev/null"])
    valid = rc == 0

    if not valid:
        return {
            "status": "saved",
            "path": dest_path,
            "valid": False,
            "syntax_error": stderr.strip(),
        }

    return {
        "status": "saved",
        "path": dest_path,
        "valid": True,
    }


def clamav_scan(path: str, recursive: bool = True) -> dict:
    """
    Scan a file or directory with ClamAV.

    Parameters
    ----------
    path      : Target file or directory.
    recursive : Whether to scan directories recursively.
    """
    if shutil.which("clamscan") is None:
        return {
            "error": (
                "clamscan not installed. "
                "Install: sudo apt install clamav  |  brew install clamav"
            )
        }

    if not os.path.exists(path):
        return {"error": f"Path does not exist: {path}"}

    cmd = ["clamscan", "--infected", "--no-summary"]
    if recursive:
        cmd.append("-r")
    cmd.append(path)

    rc, stdout, stderr = _run(cmd)

    # Parse infected files from output
    # ClamAV format: "/path/to/file: Eicar-Test-Signature FOUND"
    infected: list[dict] = []
    total_scanned = 0

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith("FOUND"):
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                file_path = parts[0].strip()
                signature = parts[1].replace("FOUND", "").strip()
                infected.append({"file": file_path, "signature": signature})
        # clamscan --no-summary still sometimes prints summary lines
        m = re.search(r"Scanned files:\s*(\d+)", line, re.IGNORECASE)
        if m:
            total_scanned = int(m.group(1))

    # If --infected suppressed clean lines, count scanned from fs
    if total_scanned == 0 and os.path.isdir(path):
        for _, _, fnames in os.walk(path):
            total_scanned += len(fnames)
    elif total_scanned == 0:
        total_scanned = 1

    return {
        "infected": infected,
        "total_scanned": total_scanned,
        "infected_count": len(infected),
    }


def clamav_update() -> dict:
    """
    Update ClamAV virus definitions using freshclam.
    """
    if shutil.which("freshclam") is None:
        return {
            "error": (
                "freshclam not installed. "
                "Install: sudo apt install clamav  |  brew install clamav"
            )
        }

    rc, stdout, stderr = _run(["freshclam"])
    combined = (stdout + "\n" + stderr).strip()

    if rc == 0:
        return {"status": "updated", "output": combined}
    else:
        return {"status": "error", "output": combined, "returncode": rc}


# ---------------------------------------------------------------------------
# ARGOS TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "yara_scan": {
        "fn": yara_scan,
        "description": (
            "Scan a file or directory with YARA rules. "
            "Falls back to builtin rules if no rules directory is found."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file or directory to scan.",
                },
                "rules_dir": {
                    "type": "string",
                    "description": "Directory containing .yar/.yara rule files.",
                    "default": "/opt/argos/yara_rules",
                },
            },
            "required": ["path"],
        },
    },
    "yara_scan_process": {
        "fn": yara_scan_process,
        "description": "Scan a running process memory with YARA rules using its PID.",
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Process ID to scan.",
                },
                "rules_dir": {
                    "type": "string",
                    "description": "Directory containing .yar/.yara rule files.",
                    "default": "/opt/argos/yara_rules",
                },
            },
            "required": ["pid"],
        },
    },
    "yara_add_rule": {
        "fn": yara_add_rule,
        "description": (
            "Save a new YARA rule to disk and validate its syntax. "
            "The rule is stored in /opt/argos/yara_rules/{category}/{name}.yar."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Rule filename (without .yar extension).",
                },
                "rule_content": {
                    "type": "string",
                    "description": "Complete YARA rule text.",
                },
                "category": {
                    "type": "string",
                    "description": "Sub-directory category within the rules directory.",
                    "default": "custom",
                },
            },
            "required": ["name", "rule_content"],
        },
    },
    "clamav_scan": {
        "fn": clamav_scan,
        "description": "Scan a file or directory with ClamAV and return infected file details.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to file or directory to scan.",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Scan directories recursively.",
                    "default": True,
                },
            },
            "required": ["path"],
        },
    },
    "clamav_update": {
        "fn": clamav_update,
        "description": "Update ClamAV virus definitions using freshclam.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}
