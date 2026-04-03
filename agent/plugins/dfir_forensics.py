"""
dfir_forensics.py — ARGOS plugin
Digital forensics and incident response: Windows EVTX analysis, registry, prefetch,
timeline generation, artifact collection.
Tools: dfir-toolkit (Rust), evtx_dump, python-evtx, IR PowerShell scripts.
"""

import subprocess
import json
import os
import re
import shutil
import tempfile
from datetime import datetime

MANIFEST = {
    "id": "dfir_forensics",
    "name": "DFIR Forensics",
    "version": "1.0.0",
    "description": "EVTX analysis, registry forensics, prefetch, timeline, IR artifact collection",
    "author": "ARGOS",
    "category": "forensics",
    "tools": [
        "evtx_analyze",
        "evtx_to_timeline",
        "registry_forensics",
        "prefetch_analyze",
        "ir_collect_artifacts",
    ],
}

RESULTS_DIR = "/opt/argos/logs/dfir"
os.makedirs(RESULTS_DIR, exist_ok=True)

# dfir-toolkit binary paths after cargo install
DFIR_TOOLS = {
    "evtx2bodyfile": shutil.which("evtx2bodyfile"),
    "evtxanalyze": shutil.which("evtxanalyze"),
    "regdump": shutil.which("regdump"),
    "pf2bodyfile": shutil.which("pf2bodyfile"),
    "lnk2bodyfile": shutil.which("lnk2bodyfile"),
    "ts2date": shutil.which("ts2date"),
}


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _ensure_dfir_toolkit() -> dict:
    """Install dfir-toolkit via cargo if not present."""
    missing = [k for k, v in DFIR_TOOLS.items() if not v]
    if not missing:
        return {"status": "ok", "tools": list(DFIR_TOOLS.keys())}

    if not shutil.which("cargo"):
        return {"status": "missing_cargo",
                "install": "curl https://sh.rustup.rs -sSf | sh -s -- -y"}

    rc, out, err = _run(
        ["cargo", "install", "dfir-toolkit", "--locked"],
        timeout=300,
    )
    if rc == 0:
        # Refresh tool paths
        cargo_bin = os.path.expanduser("~/.cargo/bin")
        for tool in DFIR_TOOLS:
            path = os.path.join(cargo_bin, tool)
            if os.path.exists(path):
                DFIR_TOOLS[tool] = path
        return {"status": "installed", "tools": [k for k, v in DFIR_TOOLS.items() if v]}

    return {"status": "error", "error": err[:1000]}


def _parse_evtx_python(evtx_path: str, max_events: int = 1000) -> list[dict]:
    """Parse EVTX using python-evtx as fallback."""
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        import xml.etree.ElementTree as ET

        events = []
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    sys_data = root.find("e:System", ns)
                    event = {}
                    if sys_data is not None:
                        eid = sys_data.find("e:EventID", ns)
                        if eid is not None:
                            event["EventID"] = eid.text
                        tc = sys_data.find("e:TimeCreated", ns)
                        if tc is not None:
                            event["TimeCreated"] = tc.get("SystemTime", "")
                        comp = sys_data.find("e:Computer", ns)
                        if comp is not None:
                            event["Computer"] = comp.text
                    events.append(event)
                    if len(events) >= max_events:
                        break
                except Exception:
                    continue
        return events
    except ImportError:
        return []


def evtx_analyze(evtx_path: str, event_ids: list = None,
                  keywords: list = None, limit: int = 500) -> dict:
    """
    Analyze Windows Event Log (.evtx) file.
    Extracts security events: logons, process creation, network connections.

    Args:
        evtx_path: Path to .evtx file
        event_ids: Filter by specific Event IDs (e.g. [4624, 4625, 4688] for logon+process)
        keywords: Filter events containing these strings
        limit: Maximum events to return (default: 500)

    Returns:
        Parsed events with timeline, statistics, and suspicious patterns
    """
    if not os.path.exists(evtx_path):
        return {"error": f"File not found: {evtx_path}"}

    result = {
        "file": evtx_path,
        "analysis_time": datetime.utcnow().isoformat(),
        "events": [],
        "statistics": {},
        "suspicious_patterns": [],
    }

    # Try evtxanalyze (dfir-toolkit)
    if DFIR_TOOLS.get("evtxanalyze"):
        cmd = [DFIR_TOOLS["evtxanalyze"], evtx_path, "--format", "json"]
        rc, out, err = _run(cmd, timeout=60)
        if rc == 0 and out.strip():
            try:
                events = [json.loads(line) for line in out.strip().splitlines() if line]
                result["events"] = events[:limit]
                result["total_events"] = len(events)
                # Stats
                eid_counts = {}
                for e in events:
                    eid = str(e.get("EventID", "unknown"))
                    eid_counts[eid] = eid_counts.get(eid, 0) + 1
                result["statistics"]["event_id_counts"] = dict(
                    sorted(eid_counts.items(), key=lambda x: x[1], reverse=True)[:20]
                )
                # Apply filters
                if event_ids:
                    result["events"] = [e for e in result["events"]
                                        if str(e.get("EventID")) in [str(i) for i in event_ids]]
                return result
            except Exception:
                pass

    # Try python-evtx fallback
    events = _parse_evtx_python(evtx_path, max_events=limit)
    if events:
        result["events"] = events
        result["total_events"] = len(events)
        eid_counts = {}
        for e in events:
            eid = str(e.get("EventID", "?"))
            eid_counts[eid] = eid_counts.get(eid, 0) + 1
        result["statistics"]["event_id_counts"] = dict(
            sorted(eid_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        )
        return result

    # Try evtx_dump (python-evtx CLI)
    if shutil.which("evtx_dump"):
        rc, out, err = _run(["evtx_dump", evtx_path, "-f", "jsonl"], timeout=60)
        if rc == 0:
            lines = out.strip().splitlines()[:limit]
            for line in lines:
                try:
                    result["events"].append(json.loads(line))
                except Exception:
                    pass
            result["total_events"] = len(result["events"])
            return result

    # Check if any tool is available
    install_hint = "pip3 install python-evtx  OR  cargo install dfir-toolkit"
    return {"error": "No EVTX parser available", "install": install_hint}


def evtx_to_timeline(evtx_path: str, output_format: str = "bodyfile") -> dict:
    """
    Convert EVTX to a timeline (bodyfile format for mactime, or CSV/JSON).
    Bodyfile can be processed with Sleuth Kit's mactime for timeline analysis.

    Args:
        evtx_path: Path to .evtx file or directory
        output_format: 'bodyfile', 'csv', or 'json' (default: bodyfile)

    Returns:
        Timeline entries and path to output file
    """
    if not os.path.exists(evtx_path):
        return {"error": f"Path not found: {evtx_path}"}

    outfile = os.path.join(
        RESULTS_DIR,
        f"timeline_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{output_format}"
    )

    # Use evtx2bodyfile (dfir-toolkit)
    if DFIR_TOOLS.get("evtx2bodyfile") and output_format == "bodyfile":
        cmd = [DFIR_TOOLS["evtx2bodyfile"], evtx_path]
        rc, out, err = _run(cmd, timeout=120)
        if rc == 0 and out.strip():
            with open(outfile, "w") as f:
                f.write(out)
            lines = out.strip().splitlines()
            return {
                "evtx_path": evtx_path,
                "output_file": outfile,
                "format": "bodyfile",
                "entries": len(lines),
                "sample": lines[:10],
                "mactime_cmd": f"mactime -b {outfile} -d > timeline.csv",
            }

    # Fallback: parse and build timeline manually
    events = _parse_evtx_python(evtx_path, max_events=5000)
    if not events:
        return {"error": "No parser available for EVTX", "install": "cargo install dfir-toolkit"}

    timeline = sorted(
        [e for e in events if e.get("TimeCreated")],
        key=lambda x: x.get("TimeCreated", "")
    )

    if output_format == "json":
        with open(outfile, "w") as f:
            json.dump(timeline, f, indent=2)
    else:
        with open(outfile, "w") as f:
            for entry in timeline:
                tc = entry.get("TimeCreated", "")
                eid = entry.get("EventID", "?")
                comp = entry.get("Computer", "?")
                f.write(f"0|{comp} (EventID {eid})|0|0|0|0|0|0|{tc}|0|0\n")

    return {
        "evtx_path": evtx_path,
        "output_file": outfile,
        "format": output_format,
        "entries": len(timeline),
    }


def registry_forensics(hive_path: str, search_keys: list = None) -> dict:
    """
    Analyze Windows registry hive files for forensic artifacts.
    Extracts run keys, services, user activity, USB history, installed software.

    Args:
        hive_path: Path to registry hive (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
        search_keys: List of registry keys/values to search for (optional)

    Returns:
        Registry contents, persistence mechanisms, suspicious entries
    """
    if not os.path.exists(hive_path):
        return {"error": f"Hive not found: {hive_path}"}

    result = {
        "hive": hive_path,
        "analysis_time": datetime.utcnow().isoformat(),
        "findings": {},
        "suspicious": [],
    }

    # Try regdump (dfir-toolkit)
    if DFIR_TOOLS.get("regdump"):
        cmd = [DFIR_TOOLS["regdump"], hive_path, "--format", "json"]
        if search_keys:
            for k in search_keys[:5]:
                cmd += ["--key", k]
        rc, out, err = _run(cmd, timeout=60)
        if rc == 0 and out.strip():
            try:
                result["findings"]["raw"] = json.loads(out)
                return result
            except Exception:
                result["findings"]["raw_text"] = out[:5000]
                return result

    # Try python-registry as fallback
    try:
        import Registry.Registry as Registry

        reg = Registry.Registry(hive_path)

        def _walk_key(key, depth=0, max_depth=3):
            if depth > max_depth:
                return {}
            data = {"values": {}, "subkeys": {}}
            try:
                for val in key.values():
                    data["values"][val.name()] = str(val.value())[:500]
            except Exception:
                pass
            if depth < max_depth:
                try:
                    for sub in key.subkeys():
                        data["subkeys"][sub.name()] = _walk_key(sub, depth + 1, max_depth)
                except Exception:
                    pass
            return data

        # Key persistence locations
        persistence_keys = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SYSTEM\\CurrentControlSet\\Services",
        ]

        for pk in persistence_keys:
            try:
                key = reg.open(pk)
                result["findings"][pk] = _walk_key(key, max_depth=2)
            except Exception:
                pass

        if search_keys:
            for sk in search_keys:
                try:
                    key = reg.open(sk)
                    result["findings"][sk] = _walk_key(key)
                except Exception:
                    result["findings"][sk] = "not_found"

        return result

    except ImportError:
        return {"error": "No registry parser available",
                "install": "pip3 install python-registry  OR  cargo install dfir-toolkit"}


def prefetch_analyze(prefetch_path: str) -> dict:
    """
    Analyze Windows Prefetch files (.pf) to determine program execution history.
    Shows execution count, last run times, and file dependencies.

    Args:
        prefetch_path: Path to .pf file or C:/Windows/Prefetch directory

    Returns:
        Program execution history with timestamps and dependency lists
    """
    if not os.path.exists(prefetch_path):
        return {"error": f"Path not found: {prefetch_path}"}

    result = {
        "path": prefetch_path,
        "analysis_time": datetime.utcnow().isoformat(),
        "executions": [],
    }

    # Try pf2bodyfile (dfir-toolkit)
    if DFIR_TOOLS.get("pf2bodyfile"):
        cmd = [DFIR_TOOLS["pf2bodyfile"], prefetch_path]
        if os.path.isdir(prefetch_path):
            # Analyze all .pf files
            for f in os.listdir(prefetch_path):
                if f.endswith(".pf"):
                    rc, out, err = _run(
                        [DFIR_TOOLS["pf2bodyfile"], os.path.join(prefetch_path, f)],
                        timeout=30,
                    )
                    if rc == 0 and out.strip():
                        result["executions"].append({
                            "file": f,
                            "bodyfile": out.strip(),
                        })
        else:
            rc, out, err = _run(cmd, timeout=30)
            if rc == 0:
                result["executions"] = [{"bodyfile": out.strip()}]

        if result["executions"]:
            return result

    # Try python-prefetch fallback
    try:
        import prefetch

        files = []
        if os.path.isdir(prefetch_path):
            files = [os.path.join(prefetch_path, f)
                     for f in os.listdir(prefetch_path) if f.endswith(".pf")]
        else:
            files = [prefetch_path]

        for fp in files[:50]:
            try:
                pf = prefetch.Prefetch(fp)
                result["executions"].append({
                    "executable": pf.executableName,
                    "run_count": pf.runCount,
                    "last_run": str(pf.lastRunTime),
                    "volumes": [str(v) for v in getattr(pf, "volumesInformation", [])],
                })
            except Exception as e:
                result["executions"].append({"file": fp, "error": str(e)})

        return result

    except ImportError:
        pass

    return {"error": "No prefetch parser available",
            "install": "cargo install dfir-toolkit  OR  pip3 install python-prefetch"}


def ir_collect_artifacts(output_dir: str = None, include: list = None) -> dict:
    """
    Collect forensic artifacts from the current Linux system for incident response.
    Gathers processes, network connections, cron jobs, bash history, SUID binaries,
    recently modified files, and active connections.

    Args:
        output_dir: Directory to save collected artifacts (default: /opt/argos/logs/dfir/ir_<timestamp>)
        include: Artifact types to collect (default: all)
                 Options: processes, network, cron, history, suid, modified, logins, modules

    Returns:
        Collected artifacts with potential IOCs highlighted
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outdir = output_dir or os.path.join(RESULTS_DIR, f"ir_{ts}")
    os.makedirs(outdir, exist_ok=True)

    all_types = ["processes", "network", "cron", "history", "suid", "modified", "logins", "modules"]
    collect = include or all_types

    result = {
        "output_dir": outdir,
        "collection_time": datetime.utcnow().isoformat(),
        "artifacts": {},
        "iocs": [],
    }

    collectors = {
        "processes": (["ps", "aux", "--forest"], "processes.txt"),
        "network": (["ss", "-tulpn"], "network.txt"),
        "logins": (["last", "-n", "100"], "logins.txt"),
        "modules": (["lsmod"], "kernel_modules.txt"),
    }

    for name, (cmd, filename) in collectors.items():
        if name not in collect:
            continue
        rc, out, err = _run(cmd, timeout=10)
        if rc == 0:
            path = os.path.join(outdir, filename)
            with open(path, "w") as f:
                f.write(out)
            result["artifacts"][name] = {"file": path, "lines": len(out.splitlines())}

    # Cron jobs
    if "cron" in collect:
        cron_data = []
        for d in ["/etc/cron*", "/var/spool/cron", "/etc/crontab"]:
            rc, out, _ = _run(["find", d, "-type", "f"], timeout=5)
            if rc == 0:
                for f in out.strip().splitlines()[:20]:
                    rc2, content, _ = _run(["cat", f], timeout=5)
                    if rc2 == 0 and content.strip():
                        cron_data.append({"file": f, "content": content[:1000]})
        path = os.path.join(outdir, "cron.json")
        with open(path, "w") as f:
            json.dump(cron_data, f, indent=2)
        result["artifacts"]["cron"] = {"file": path, "count": len(cron_data)}

    # Bash/shell history
    if "history" in collect:
        history_data = []
        for hist_file in ["/root/.bash_history", "/root/.zsh_history",
                           "/home/*/.bash_history", "/home/*/.zsh_history"]:
            import glob
            for hf in glob.glob(hist_file):
                try:
                    with open(hf) as f:
                        lines = f.readlines()
                    history_data.append({"file": hf, "commands": lines[-100:]})
                except Exception:
                    pass
        path = os.path.join(outdir, "history.json")
        with open(path, "w") as f:
            json.dump(history_data, f, indent=2)
        result["artifacts"]["history"] = {"file": path, "files": len(history_data)}

        # Flag suspicious commands
        suspicious_patterns = [
            r"base64 -d", r"wget.*http", r"curl.*http", r"chmod.*\+x",
            r"nc -e", r"bash -i", r"/dev/tcp", r"python.*-c",
            r"rm -rf /", r"dd if=", r"mkfs\.",
        ]
        for hdata in history_data:
            for cmd_line in hdata.get("commands", []):
                for pat in suspicious_patterns:
                    if re.search(pat, cmd_line, re.IGNORECASE):
                        result["iocs"].append({
                            "type": "suspicious_command",
                            "file": hdata["file"],
                            "command": cmd_line.strip(),
                            "pattern": pat,
                        })

    # SUID binaries
    if "suid" in collect:
        rc, out, _ = _run(
            ["find", "/", "-perm", "-4000", "-type", "f", "-ls"],
            timeout=30,
        )
        if rc == 0:
            path = os.path.join(outdir, "suid_binaries.txt")
            with open(path, "w") as f:
                f.write(out)
            lines = out.strip().splitlines()
            result["artifacts"]["suid"] = {"file": path, "count": len(lines)}
            # Flag unexpected SUID
            expected_suid = {
                "passwd", "sudo", "su", "ping", "ping6", "newgrp",
                "gpasswd", "chage", "chsh", "chfn", "mount", "umount"
            }
            for line in lines:
                binary = line.split()[-1] if line.split() else ""
                bname = os.path.basename(binary)
                if bname and bname not in expected_suid:
                    result["iocs"].append({
                        "type": "unexpected_suid",
                        "binary": binary,
                        "line": line.strip(),
                    })

    # Recently modified files
    if "modified" in collect:
        rc, out, _ = _run(
            ["find", "/etc", "/tmp", "/var/tmp", "/dev/shm",
             "-mtime", "-1", "-type", "f"],
            timeout=15,
        )
        if rc == 0:
            files = out.strip().splitlines()
            path = os.path.join(outdir, "recently_modified.txt")
            with open(path, "w") as f:
                f.write(out)
            result["artifacts"]["modified"] = {"file": path, "count": len(files)}
            # Flag suspicious locations
            for fp in files:
                if any(fp.startswith(d) for d in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                    result["iocs"].append({
                        "type": "suspicious_modified",
                        "file": fp,
                        "reason": "writable temp location",
                    })

    result["ioc_count"] = len(result["iocs"])
    return result


TOOLS = {
    "evtx_analyze": evtx_analyze,
    "evtx_to_timeline": evtx_to_timeline,
    "registry_forensics": registry_forensics,
    "prefetch_analyze": prefetch_analyze,
    "ir_collect_artifacts": ir_collect_artifacts,
}
