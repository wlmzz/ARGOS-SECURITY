"""
zircolite_sigma.py — ARGOS plugin
SIGMA rule-based threat detection on Windows Event logs, Sysmon, Linux audit logs.
Uses Zircolite (https://github.com/wagga40/Zircolite).
"""

import subprocess
import json
import os
import shutil
import tempfile
from datetime import datetime

MANIFEST = {
    "id": "zircolite_sigma",
    "name": "Zircolite SIGMA",
    "version": "1.0.0",
    "description": "SIGMA-based log analysis for Windows EVTX, Sysmon, Linux audit logs",
    "author": "ARGOS",
    "category": "forensics",
    "tools": [
        "sigma_analyze_evtx",
        "sigma_analyze_sysmon",
        "sigma_analyze_linux",
        "sigma_update_rules",
        "sigma_full_analysis",
    ],
}

ZIRCOLITE_DIR = "/opt/argos/zircolite"
RULES_DIR = os.path.join(ZIRCOLITE_DIR, "rules")
RESULTS_DIR = "/opt/argos/logs/sigma"

os.makedirs(RESULTS_DIR, exist_ok=True)


def _run(cmd: list, timeout: int = 300) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _ensure_zircolite() -> tuple[bool, str]:
    """Install Zircolite if not present."""
    if shutil.which("zircolite"):
        return True, shutil.which("zircolite")

    # Try pip install
    rc, _, err = _run(["pip3", "install", "zircolite", "--break-system-packages", "-q"])
    if rc == 0 and shutil.which("zircolite"):
        return True, shutil.which("zircolite")

    # Try git clone + direct run
    if not os.path.isdir(ZIRCOLITE_DIR):
        rc, _, err = _run(
            ["git", "clone", "--depth", "1",
             "https://github.com/wagga40/Zircolite",
             ZIRCOLITE_DIR],
            timeout=60,
        )
        if rc != 0:
            return False, f"Failed to clone Zircolite: {err}"

    script = os.path.join(ZIRCOLITE_DIR, "zircolite.py")
    if os.path.exists(script):
        # Install deps
        req = os.path.join(ZIRCOLITE_DIR, "requirements.txt")
        if os.path.exists(req):
            _run(["pip3", "install", "-r", req, "--break-system-packages", "-q"])
        return True, f"python3 {script}"

    return False, "Zircolite not available"


def _get_ruleset(ruleset_name: str) -> str:
    """Return path to a SIGMA ruleset."""
    ruleset_map = {
        "windows": os.path.join(ZIRCOLITE_DIR, "rules/rules_windows_generic_full.json"),
        "windows_high": os.path.join(ZIRCOLITE_DIR, "rules/rules_windows_generic.json"),
        "sysmon": os.path.join(ZIRCOLITE_DIR, "rules/rules_windows_sysmon.json"),
        "linux": os.path.join(ZIRCOLITE_DIR, "rules/rules_linux.json"),
        "antivirus": os.path.join(ZIRCOLITE_DIR, "rules/rules_windows_antivirus.json"),
    }
    path = ruleset_map.get(ruleset_name)
    if path and os.path.exists(path):
        return path
    # Fallback to any available ruleset
    for v in ruleset_map.values():
        if os.path.exists(v):
            return v
    return ""


def _parse_zircolite_output(output_file: str) -> dict:
    """Parse Zircolite JSON output into structured findings."""
    if not os.path.exists(output_file):
        return {"alerts": [], "count": 0}
    try:
        with open(output_file) as f:
            data = json.load(f)
        alerts = []
        for rule in data:
            rule_name = rule.get("title", rule.get("id", "Unknown"))
            level = rule.get("level", "unknown")
            count = len(rule.get("matches", []))
            alerts.append({
                "rule": rule_name,
                "level": level,
                "matches": count,
                "tags": rule.get("tags", []),
                "description": rule.get("description", ""),
            })
        # Sort by severity
        level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        alerts.sort(key=lambda x: level_order.get(x["level"], 5))
        return {"alerts": alerts, "count": len(alerts),
                "critical": sum(1 for a in alerts if a["level"] == "critical"),
                "high": sum(1 for a in alerts if a["level"] == "high"),
                "medium": sum(1 for a in alerts if a["level"] == "medium")}
    except Exception as e:
        return {"error": f"Parse error: {e}", "alerts": [], "count": 0}


def sigma_analyze_evtx(evtx_path: str, ruleset: str = "windows_high",
                        output_format: str = "json", timeout_sec: int = 180) -> dict:
    """
    Analyze Windows Event Log (.evtx) files using SIGMA rules via Zircolite.
    Detects lateral movement, privilege escalation, credential dumping, and more.

    Args:
        evtx_path: Path to .evtx file or directory containing .evtx files
        ruleset: Rule set to use: 'windows', 'windows_high', 'sysmon', 'antivirus' (default: windows_high)
        output_format: 'json' or 'csv' (default: json)
        timeout_sec: Analysis timeout in seconds

    Returns:
        Detected alerts sorted by severity with SIGMA rule names and MITRE ATT&CK tags
    """
    if not os.path.exists(evtx_path):
        return {"error": f"Path not found: {evtx_path}"}

    ok, zircolite = _ensure_zircolite()
    if not ok:
        return {"error": f"Zircolite not available: {zircolite}",
                "install": "pip3 install zircolite"}

    ruleset_path = _get_ruleset(ruleset)
    if not ruleset_path:
        # Try sigma_update_rules first
        return {"error": "No SIGMA ruleset found. Run sigma_update_rules() first."}

    outfile = os.path.join(RESULTS_DIR, f"sigma_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")

    # Build command
    if zircolite.startswith("python3 "):
        base_cmd = zircolite.split()
    else:
        base_cmd = [zircolite]

    cmd = base_cmd + [
        "--evtx", evtx_path,
        "--ruleset", ruleset_path,
        "--outfile", outfile,
        "--outfields", "EventID,Computer,TimeCreated,CommandLine,Image,ParentImage",
    ]

    rc, out, err = _run(cmd, timeout=timeout_sec)

    result = {
        "evtx_path": evtx_path,
        "ruleset": ruleset,
        "analysis_time": datetime.utcnow().isoformat(),
        "output_file": outfile,
        "raw_stderr": err[:2000] if err else "",
    }

    if os.path.exists(outfile):
        result.update(_parse_zircolite_output(outfile))
    else:
        result["error"] = "No output generated"
        result["raw_stdout"] = out[:2000]

    return result


def sigma_analyze_sysmon(log_path: str, timeout_sec: int = 180) -> dict:
    """
    Analyze Sysmon logs (XML/JSON) using SIGMA rules.
    Detects process injection, network connections, file creation patterns.

    Args:
        log_path: Path to Sysmon EVTX or JSON export
        timeout_sec: Analysis timeout

    Returns:
        SIGMA alerts with process/network/file IOCs
    """
    if not os.path.exists(log_path):
        return {"error": f"Path not found: {log_path}"}

    ok, zircolite = _ensure_zircolite()
    if not ok:
        return {"error": f"Zircolite not available: {zircolite}"}

    ruleset_path = _get_ruleset("sysmon")
    if not ruleset_path:
        ruleset_path = _get_ruleset("windows_high")
    if not ruleset_path:
        return {"error": "No Sysmon ruleset found. Run sigma_update_rules() first."}

    outfile = os.path.join(RESULTS_DIR, f"sysmon_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")

    if zircolite.startswith("python3 "):
        base_cmd = zircolite.split()
    else:
        base_cmd = [zircolite]

    cmd = base_cmd + [
        "--evtx", log_path,
        "--ruleset", ruleset_path,
        "--outfile", outfile,
        "--sysmon",
    ]

    _run(cmd, timeout=timeout_sec)

    result = {
        "log_path": log_path,
        "mode": "sysmon",
        "analysis_time": datetime.utcnow().isoformat(),
    }
    result.update(_parse_zircolite_output(outfile))
    return result


def sigma_analyze_linux(log_path: str, log_type: str = "auditd",
                         timeout_sec: int = 120) -> dict:
    """
    Analyze Linux audit logs using SIGMA rules.
    Detects privilege escalation, lateral movement, persistence mechanisms.

    Args:
        log_path: Path to auditd, syslog, or auth.log file
        log_type: 'auditd', 'syslog', or 'json' (default: auditd)
        timeout_sec: Analysis timeout

    Returns:
        SIGMA alerts for Linux-specific threats
    """
    if not os.path.exists(log_path):
        return {"error": f"Path not found: {log_path}"}

    ok, zircolite = _ensure_zircolite()
    if not ok:
        return {"error": f"Zircolite not available: {zircolite}"}

    ruleset_path = _get_ruleset("linux")
    if not ruleset_path:
        return {"error": "No Linux SIGMA ruleset found. Run sigma_update_rules() first."}

    outfile = os.path.join(RESULTS_DIR, f"linux_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")

    if zircolite.startswith("python3 "):
        base_cmd = zircolite.split()
    else:
        base_cmd = [zircolite]

    cmd = base_cmd + [
        "--evtx", log_path,
        "--ruleset", ruleset_path,
        "--outfile", outfile,
    ]

    if log_type == "json":
        cmd += ["--jsononly"]

    rc, out, err = _run(cmd, timeout=timeout_sec)

    result = {
        "log_path": log_path,
        "log_type": log_type,
        "analysis_time": datetime.utcnow().isoformat(),
    }
    result.update(_parse_zircolite_output(outfile))
    return result


def sigma_update_rules(source: str = "zircolite") -> dict:
    """
    Download/update SIGMA detection rules.
    Pulls latest rulesets from Zircolite's packaged rules or SigmaHQ.

    Args:
        source: 'zircolite' (bundled), 'sigmahq' (full community rules) (default: zircolite)

    Returns:
        List of available rulesets and their rule counts
    """
    result = {"source": source, "rulesets": [], "status": ""}

    # Clone/update Zircolite which includes bundled SIGMA rulesets
    if not os.path.isdir(ZIRCOLITE_DIR):
        rc, out, err = _run(
            ["git", "clone", "--depth", "1",
             "https://github.com/wagga40/Zircolite",
             ZIRCOLITE_DIR],
            timeout=120,
        )
        if rc != 0:
            return {"error": f"Clone failed: {err}"}
        result["status"] = "cloned"
    else:
        rc, out, err = _run(["git", "-C", ZIRCOLITE_DIR, "pull", "--ff-only"], timeout=60)
        result["status"] = "updated" if rc == 0 else "already_current"

    # Install Python deps
    req = os.path.join(ZIRCOLITE_DIR, "requirements.txt")
    if os.path.exists(req):
        _run(["pip3", "install", "-r", req, "--break-system-packages", "-q"])

    # List available rulesets
    rules_path = os.path.join(ZIRCOLITE_DIR, "rules")
    if os.path.isdir(rules_path):
        for f in sorted(os.listdir(rules_path)):
            if f.endswith(".json"):
                path = os.path.join(rules_path, f)
                try:
                    with open(path) as fp:
                        rules = json.load(fp)
                    result["rulesets"].append({
                        "file": f,
                        "path": path,
                        "rule_count": len(rules),
                    })
                except Exception:
                    result["rulesets"].append({"file": f, "path": path})

    return result


def sigma_full_analysis(target_dir: str, deep: bool = False, timeout_sec: int = 600) -> dict:
    """
    Full SIGMA analysis across all log types found in a directory.
    Auto-detects EVTX, JSON logs, and Linux audit logs.

    Args:
        target_dir: Directory to scan for log files
        deep: If True, use full Windows ruleset instead of high-confidence only
        timeout_sec: Total analysis timeout

    Returns:
        Consolidated report across all log types with top threats and MITRE tags
    """
    if not os.path.isdir(target_dir):
        return {"error": f"Directory not found: {target_dir}"}

    ok, zircolite = _ensure_zircolite()
    if not ok:
        return {"error": f"Zircolite not available: {zircolite}",
                "install": "Run sigma_update_rules() first"}

    report = {
        "target_dir": target_dir,
        "analysis_time": datetime.utcnow().isoformat(),
        "phases": {},
        "top_threats": [],
        "mitre_tactics": {},
        "total_alerts": 0,
    }

    # Find log files
    evtx_files = []
    sysmon_files = []
    linux_logs = []

    for root, _, files in os.walk(target_dir):
        for f in files:
            fp = os.path.join(root, f)
            if f.endswith(".evtx"):
                if "sysmon" in f.lower():
                    sysmon_files.append(fp)
                else:
                    evtx_files.append(fp)
            elif f in ("audit.log", "auth.log", "secure", "syslog"):
                linux_logs.append(fp)

    # Analyze each type
    ruleset = "windows" if deep else "windows_high"

    if evtx_files:
        for evtx in evtx_files[:5]:  # Cap at 5 files
            r = sigma_analyze_evtx(evtx, ruleset=ruleset, timeout_sec=timeout_sec // 3)
            report["phases"][os.path.basename(evtx)] = r

    if sysmon_files:
        for sf in sysmon_files[:3]:
            r = sigma_analyze_sysmon(sf, timeout_sec=timeout_sec // 4)
            report["phases"][f"sysmon_{os.path.basename(sf)}"] = r

    if linux_logs:
        for ll in linux_logs[:3]:
            r = sigma_analyze_linux(ll, timeout_sec=timeout_sec // 4)
            report["phases"][f"linux_{os.path.basename(ll)}"] = r

    # Consolidate
    all_alerts = []
    for phase_result in report["phases"].values():
        alerts = phase_result.get("alerts", [])
        all_alerts.extend(alerts)
        report["total_alerts"] += phase_result.get("count", 0)

    # Top threats (critical + high)
    report["top_threats"] = [
        a for a in all_alerts
        if a.get("level") in ("critical", "high")
    ][:20]

    # MITRE tactic aggregation
    for alert in all_alerts:
        for tag in alert.get("tags", []):
            if tag.startswith("attack."):
                tactic = tag.replace("attack.", "").replace("_", " ").title()
                report["mitre_tactics"][tactic] = report["mitre_tactics"].get(tactic, 0) + 1

    return report


TOOLS = {
    "sigma_analyze_evtx": sigma_analyze_evtx,
    "sigma_analyze_sysmon": sigma_analyze_sysmon,
    "sigma_analyze_linux": sigma_analyze_linux,
    "sigma_update_rules": sigma_update_rules,
    "sigma_full_analysis": sigma_full_analysis,
}
