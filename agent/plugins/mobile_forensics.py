"""
mobile_forensics.py — ARGOS plugin
Mobile device forensics using MVT (Mobile Verification Toolkit) by Amnesty International.
Detects stalkerware, spyware (Pegasus, FinFisher), and mobile compromises.
https://github.com/mvt-project/mvt
"""

import subprocess
import json
import os
import shutil
from datetime import datetime

MANIFEST = {
    "id": "mobile_forensics",
    "name": "Mobile Forensics",
    "version": "1.0.0",
    "description": "MVT — detect spyware/stalkerware on iOS/Android, Pegasus IOC scanning",
    "author": "ARGOS",
    "category": "forensics",
    "tools": [
        "mvt_update_iocs",
        "mvt_ios_scan_backup",
        "mvt_android_scan_apk",
        "mvt_check_iocs",
        "mvt_generate_report",
    ],
}

MVT_DIR = "/opt/argos/mobile_forensics"
IOCS_DIR = os.path.join(MVT_DIR, "iocs")
RESULTS_DIR = os.path.join(MVT_DIR, "results")

os.makedirs(IOCS_DIR, exist_ok=True)
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


def _ensure_mvt() -> tuple[bool, str]:
    """Install MVT if not present."""
    if shutil.which("mvt-ios") and shutil.which("mvt-android"):
        return True, ""
    rc, out, err = _run(
        ["pip3", "install", "mvt", "--break-system-packages", "-q"],
        timeout=120,
    )
    if rc == 0:
        return True, ""
    return False, f"MVT install failed: {err[:500]}\nManual: pip3 install mvt"


def mvt_update_iocs(sources: list = None) -> dict:
    """
    Download/update IOC databases for MVT scanning.
    Includes Amnesty Tech IOCs, Pegasus, FinFisher, stalkerware indicators.

    Args:
        sources: List of IOC sources to fetch (default: all official sources)

    Returns:
        List of downloaded IOC files with indicator counts
    """
    default_sources = [
        "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/pegasus.stix2",
        "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/predator.stix2",
        "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/stalkerware.stix2",
        "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/all.stix2",
    ]
    sources = sources or default_sources

    result = {
        "iocs_dir": IOCS_DIR,
        "downloaded": [],
        "errors": [],
        "update_time": datetime.utcnow().isoformat(),
    }

    for url in sources:
        fname = os.path.join(IOCS_DIR, os.path.basename(url))
        rc, out, err = _run(
            ["curl", "-sL", url, "-o", fname, "--connect-timeout", "15"],
            timeout=60,
        )
        if rc == 0 and os.path.exists(fname):
            size = os.path.getsize(fname)
            # Count indicators
            indicator_count = 0
            try:
                with open(fname) as f:
                    data = json.load(f)
                indicator_count = len(data.get("objects", []))
            except Exception:
                pass
            result["downloaded"].append({
                "url": url,
                "file": fname,
                "size_bytes": size,
                "indicator_count": indicator_count,
            })
        else:
            result["errors"].append({"url": url, "error": err[:200]})

    # Also try MVT's built-in download
    ok, err_msg = _ensure_mvt()
    if ok:
        mvt_ioc_dir = os.path.join(IOCS_DIR, "mvt_official")
        os.makedirs(mvt_ioc_dir, exist_ok=True)
        rc, out, err = _run(
            ["mvt-ios", "download-iocs", "--output", mvt_ioc_dir],
            timeout=120,
        )
        if rc == 0:
            result["mvt_official"] = mvt_ioc_dir

    return result


def mvt_ios_scan_backup(backup_path: str, iocs_file: str = None,
                         decrypt_password: str = None, timeout_sec: int = 600) -> dict:
    """
    Scan an iOS device backup for spyware/stalkerware using MVT.
    Analyzes databases, plist files, crash logs, and network artifacts.

    Args:
        backup_path: Path to iTunes backup directory or decrypted backup
        iocs_file: Path to STIX2 IOC file (optional, uses downloaded IOCs if omitted)
        decrypt_password: iTunes backup encryption password (if backup is encrypted)
        timeout_sec: Analysis timeout in seconds

    Returns:
        Detected IOCs, suspicious indicators, and full timeline of detections
    """
    if not os.path.exists(backup_path):
        return {"error": f"Backup path not found: {backup_path}"}

    ok, err_msg = _ensure_mvt()
    if not ok:
        return {"error": err_msg}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(RESULTS_DIR, f"ios_{ts}")
    os.makedirs(outdir, exist_ok=True)

    # Find IOC file
    if not iocs_file:
        for candidate in ["all.stix2", "pegasus.stix2", "predator.stix2"]:
            cand_path = os.path.join(IOCS_DIR, candidate)
            if os.path.exists(cand_path):
                iocs_file = cand_path
                break

    cmd = ["mvt-ios", "check-backup", backup_path, "--output", outdir]
    if iocs_file and os.path.exists(iocs_file):
        cmd += ["--iocs", iocs_file]
    if decrypt_password:
        cmd += ["--password", decrypt_password]

    rc, out, err = _run(cmd, timeout=timeout_sec)

    result = {
        "backup_path": backup_path,
        "output_dir": outdir,
        "scan_time": datetime.utcnow().isoformat(),
        "iocs_used": iocs_file,
        "return_code": rc,
        "detections": [],
        "warnings": [],
    }

    # Parse MVT output for detections
    combined = out + err
    for line in combined.splitlines():
        line_lower = line.lower()
        if "detected" in line_lower or "[!]" in line:
            result["detections"].append(line.strip())
        elif "warning" in line_lower or "[?]" in line:
            result["warnings"].append(line.strip())

    # Read result files
    if os.path.isdir(outdir):
        result_files = []
        for f in os.listdir(outdir):
            fp = os.path.join(outdir, f)
            if f.endswith(".json"):
                try:
                    with open(fp) as fh:
                        data = json.load(fh)
                    result_files.append({
                        "file": f,
                        "entries": len(data) if isinstance(data, list) else 1,
                    })
                except Exception:
                    result_files.append({"file": f})
        result["result_files"] = result_files

    result["compromised"] = len(result["detections"]) > 0
    result["raw"] = combined[:4000]
    return result


def mvt_android_scan_apk(apk_path: str, iocs_file: str = None, timeout_sec: int = 120) -> dict:
    """
    Analyze Android APK file for spyware/malware indicators using MVT.
    Checks signatures, permissions, network IOCs, and known malware patterns.

    Args:
        apk_path: Path to .apk file
        iocs_file: Path to STIX2 IOC file (optional)
        timeout_sec: Analysis timeout

    Returns:
        APK analysis: permissions, IOC matches, suspicious patterns
    """
    if not os.path.exists(apk_path):
        return {"error": f"APK not found: {apk_path}"}

    ok, err_msg = _ensure_mvt()
    if not ok:
        return {"error": err_msg}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(RESULTS_DIR, f"apk_{ts}")
    os.makedirs(outdir, exist_ok=True)

    if not iocs_file:
        for candidate in ["all.stix2", "stalkerware.stix2"]:
            cand_path = os.path.join(IOCS_DIR, candidate)
            if os.path.exists(cand_path):
                iocs_file = cand_path
                break

    cmd = ["mvt-android", "check-apk", apk_path, "--output", outdir]
    if iocs_file and os.path.exists(iocs_file):
        cmd += ["--iocs", iocs_file]

    rc, out, err = _run(cmd, timeout=timeout_sec)

    result = {
        "apk_path": apk_path,
        "output_dir": outdir,
        "scan_time": datetime.utcnow().isoformat(),
        "return_code": rc,
        "detections": [],
        "warnings": [],
    }

    combined = out + err
    for line in combined.splitlines():
        if "detected" in line.lower() or "[!]" in line:
            result["detections"].append(line.strip())
        elif "warning" in line.lower() or "[?]" in line:
            result["warnings"].append(line.strip())

    # Check with apktool for permissions (if available)
    if shutil.which("apktool"):
        decode_dir = os.path.join(outdir, "decoded")
        rc2, out2, _ = _run(["apktool", "d", apk_path, "-o", decode_dir, "-f"], timeout=60)
        if rc2 == 0:
            manifest = os.path.join(decode_dir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                import re
                with open(manifest) as f:
                    manifest_content = f.read()
                perms = re.findall(r'android.permission\.(\w+)', manifest_content)
                dangerous_perms = {
                    "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
                    "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA",
                    "ACCESS_FINE_LOCATION", "READ_CONTACTS",
                    "READ_PHONE_STATE", "GET_ACCOUNTS",
                }
                found_dangerous = [p for p in perms if p in dangerous_perms]
                result["permissions"] = {
                    "all": list(set(perms)),
                    "dangerous": found_dangerous,
                }

    result["compromised"] = len(result["detections"]) > 0
    result["raw"] = combined[:3000]
    return result


def mvt_check_iocs(artifact_path: str, ioc_type: str = "auto") -> dict:
    """
    Check arbitrary artifacts (logs, pcap, JSON exports) against MVT IOC databases.
    Useful for quick IOC correlation without full device scan.

    Args:
        artifact_path: Path to file or directory to check
        ioc_type: Type hint: 'auto', 'stix2', 'csv' (default: auto)

    Returns:
        IOC matches found in the artifact
    """
    if not os.path.exists(artifact_path):
        return {"error": f"Path not found: {artifact_path}"}

    # Load all downloaded IOCs
    ioc_data = {
        "domains": set(),
        "ips": set(),
        "hashes": set(),
        "urls": set(),
    }

    for ioc_file in os.listdir(IOCS_DIR):
        if not ioc_file.endswith(".stix2"):
            continue
        try:
            with open(os.path.join(IOCS_DIR, ioc_file)) as f:
                stix = json.load(f)
            for obj in stix.get("objects", []):
                obj_type = obj.get("type", "")
                if obj_type == "domain-name":
                    ioc_data["domains"].add(obj.get("value", "").lower())
                elif obj_type == "ipv4-addr":
                    ioc_data["ips"].add(obj.get("value", ""))
                elif obj_type == "file" and obj.get("hashes"):
                    for h in obj["hashes"].values():
                        ioc_data["hashes"].add(h.lower())
                elif obj_type == "url":
                    ioc_data["urls"].add(obj.get("value", "").lower())
        except Exception:
            continue

    # Convert to lists for matching
    ioc_counts = {k: len(v) for k, v in ioc_data.items()}
    if sum(ioc_counts.values()) == 0:
        return {"error": "No IOCs loaded. Run mvt_update_iocs() first.",
                "ioc_counts": ioc_counts}

    # Scan artifact
    import re
    matches = []

    def _scan_text(text: str, source: str):
        # Domain matches
        domain_pattern = re.compile(r'\b([a-z0-9\-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b')
        for m in domain_pattern.finditer(text.lower()):
            d = m.group(1)
            if d in ioc_data["domains"]:
                matches.append({"type": "domain", "value": d, "source": source})

        # IP matches
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for m in ip_pattern.finditer(text):
            if m.group(1) in ioc_data["ips"]:
                matches.append({"type": "ip", "value": m.group(1), "source": source})

        # Hash matches
        hash_pattern = re.compile(r'\b([a-f0-9]{32,64})\b', re.IGNORECASE)
        for m in hash_pattern.finditer(text):
            if m.group(1).lower() in ioc_data["hashes"]:
                matches.append({"type": "hash", "value": m.group(1), "source": source})

    if os.path.isfile(artifact_path):
        try:
            with open(artifact_path, errors="ignore") as f:
                content = f.read()
            _scan_text(content, artifact_path)
        except Exception:
            pass
    else:
        for root, _, files in os.walk(artifact_path):
            for fname in files[:100]:
                fp = os.path.join(root, fname)
                try:
                    with open(fp, errors="ignore") as f:
                        content = f.read(50000)
                    _scan_text(content, fp)
                except Exception:
                    continue

    return {
        "artifact_path": artifact_path,
        "ioc_counts": ioc_counts,
        "matches": matches[:100],
        "match_count": len(matches),
        "compromised": len(matches) > 0,
        "check_time": datetime.utcnow().isoformat(),
    }


def mvt_generate_report(results_dir: str = None) -> dict:
    """
    Generate a consolidated mobile forensics report from MVT scan results.
    Summarizes all detections, timeline, and recommendations.

    Args:
        results_dir: Directory with MVT results (default: all results in /opt/argos/mobile_forensics/results)

    Returns:
        Consolidated report with all detections and recommendations
    """
    scan_dir = results_dir or RESULTS_DIR

    if not os.path.isdir(scan_dir):
        return {"error": f"Results directory not found: {scan_dir}"}

    report = {
        "generated": datetime.utcnow().isoformat(),
        "scans": [],
        "total_detections": 0,
        "total_warnings": 0,
        "recommendations": [],
    }

    # Walk results directory for scan outputs
    for scan_name in sorted(os.listdir(scan_dir)):
        scan_path = os.path.join(scan_dir, scan_name)
        if not os.path.isdir(scan_path):
            continue

        scan_summary = {
            "scan": scan_name,
            "detections": [],
            "files_analyzed": 0,
        }

        for f in os.listdir(scan_path):
            if not f.endswith(".json"):
                continue
            fp = os.path.join(scan_path, f)
            try:
                with open(fp) as fh:
                    data = json.load(fh)
                scan_summary["files_analyzed"] += 1
                if isinstance(data, list) and data:
                    scan_summary["detections"].append({
                        "file": f,
                        "entries": len(data),
                        "sample": data[:3],
                    })
                    report["total_detections"] += len(data)
            except Exception:
                continue

        report["scans"].append(scan_summary)

    # Recommendations
    if report["total_detections"] > 0:
        report["recommendations"] = [
            "Device likely compromised — consider full factory reset",
            "Change all passwords from a clean device",
            "Enable 2FA on all accounts",
            "Report to law enforcement if stalkerware detected",
            "Contact access.now helpline (spyware@accessnow.org) for victim support",
        ]
        report["risk_level"] = "HIGH"
    elif report["total_warnings"] > 0:
        report["recommendations"] = [
            "Review warnings manually for false positives",
            "Update device OS to latest version",
            "Review installed applications and permissions",
        ]
        report["risk_level"] = "MEDIUM"
    else:
        report["risk_level"] = "LOW"
        report["recommendations"] = ["No indicators detected. Keep device updated."]

    return report


TOOLS = {
    "mvt_update_iocs": mvt_update_iocs,
    "mvt_ios_scan_backup": mvt_ios_scan_backup,
    "mvt_android_scan_apk": mvt_android_scan_apk,
    "mvt_check_iocs": mvt_check_iocs,
    "mvt_generate_report": mvt_generate_report,
}
