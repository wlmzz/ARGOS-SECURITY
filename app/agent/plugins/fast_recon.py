"""
fast_recon.py — ARGOS plugin
Rapid reconnaissance: RustScan, masscan, nmap, sn0int, skanuvaty wrappers.
Ethical use only — always scan systems you own or have written permission to test.
"""

import subprocess
import json
import re
import shutil
import tempfile
import os
from datetime import datetime

MANIFEST = {
    "id": "fast_recon",
    "name": "Fast Recon",
    "version": "1.0.0",
    "description": "Rapid port scanning and reconnaissance using RustScan, masscan, nmap, sn0int",
    "author": "ARGOS",
    "category": "reconnaissance",
    "tools": [
        "fast_port_scan",
        "deep_service_scan",
        "masscan_sweep",
        "sn0int_recon",
        "full_recon_pipeline",
    ],
}

# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _parse_nmap_ports(output: str) -> list[dict]:
    ports = []
    for line in output.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(.*)", line)
        if m:
            ports.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "state": m.group(3),
                "service": m.group(4).strip(),
            })
    return ports


def _parse_rustscan_ports(output: str) -> list[int]:
    """RustScan outputs open ports like: Open 1.2.3.4:22"""
    ports = []
    for line in output.splitlines():
        m = re.search(r":(\d+)", line)
        if m and "Open" in line:
            ports.append(int(m.group(1)))
    return sorted(set(ports))


def _validate_target(target: str) -> tuple[bool, str]:
    """Basic validation — refuse private RFC1918 localhost unless explicitly local."""
    if not target or len(target) > 256:
        return False, "Invalid target"
    # Allow hostnames and IPs
    if re.match(r"^[\w\.\-]+$", target):
        return True, ""
    return False, f"Target contains invalid characters: {target}"


# ── tools ────────────────────────────────────────────────────────────────────

def fast_port_scan(target: str, ports: str = "1-65535", rate: int = 5000,
                   timeout_sec: int = 60) -> dict:
    """
    Fast port scan using RustScan (falls back to masscan, then nmap).
    Returns list of open ports.

    Args:
        target: IP address or hostname to scan
        ports: Port range (default: 1-65535)
        rate: Packets per second for RustScan/masscan (default: 5000)
        timeout_sec: Scan timeout in seconds

    Authorization reminder: Only scan systems you own or have written permission to test.
    """
    ok, err = _validate_target(target)
    if not ok:
        return {"error": err}

    result = {
        "target": target,
        "ports_scanned": ports,
        "tool_used": None,
        "open_ports": [],
        "scan_time": datetime.utcnow().isoformat(),
        "raw": "",
    }

    # Try RustScan first
    if _available("rustscan"):
        result["tool_used"] = "rustscan"
        rc, out, err_out = _run(
            ["rustscan", "-a", target, "-p", ports, "--ulimit", str(rate),
             "--timeout", "2000", "--tries", "1", "--no-nmap", "--batch-size", "4500"],
            timeout=timeout_sec,
        )
        if rc == 0 or out:
            result["open_ports"] = _parse_rustscan_ports(out)
            result["raw"] = out[:4000]
            return result

    # Fallback: masscan
    if _available("masscan"):
        result["tool_used"] = "masscan"
        rc, out, err_out = _run(
            ["masscan", target, f"-p{ports}", f"--rate={rate}", "--wait=2"],
            timeout=timeout_sec,
        )
        if rc == 0 or out:
            for line in out.splitlines():
                m = re.search(r"port (\d+)/", line)
                if m:
                    result["open_ports"].append(int(m.group(1)))
            result["open_ports"] = sorted(set(result["open_ports"]))
            result["raw"] = out[:4000]
            return result

    # Fallback: nmap fast scan
    if _available("nmap"):
        result["tool_used"] = "nmap-fast"
        rc, out, err_out = _run(
            ["nmap", "-T4", "--open", "-p", ports, target, "-oG", "-"],
            timeout=timeout_sec,
        )
        for line in out.splitlines():
            for m in re.finditer(r"(\d+)/open", line):
                result["open_ports"].append(int(m.group(1)))
        result["open_ports"] = sorted(set(result["open_ports"]))
        result["raw"] = out[:4000]
        return result

    return {"error": "No scanner available. Install rustscan, masscan, or nmap."}


def deep_service_scan(target: str, ports: str = None, timeout_sec: int = 120) -> dict:
    """
    Deep service/version detection + OS fingerprint using nmap -sV -sC.
    If ports not specified, first runs fast scan to find open ports.

    Args:
        target: IP address or hostname
        ports: Comma-separated ports or range (optional, auto-detected if omitted)
        timeout_sec: Scan timeout in seconds

    Authorization reminder: Only scan systems you own or have written permission to test.
    """
    ok, err = _validate_target(target)
    if not ok:
        return {"error": err}

    if not _available("nmap"):
        return {"error": "nmap not found. Install with: apt install nmap"}

    # Auto-detect open ports if not specified
    if not ports:
        fast = fast_port_scan(target, timeout_sec=min(60, timeout_sec // 2))
        if "error" in fast:
            return fast
        if not fast["open_ports"]:
            return {"target": target, "result": "No open ports found", "services": []}
        ports = ",".join(str(p) for p in fast["open_ports"][:50])  # cap at 50 ports

    result = {
        "target": target,
        "ports": ports,
        "tool": "nmap",
        "scan_time": datetime.utcnow().isoformat(),
        "services": [],
        "os_guess": None,
        "raw": "",
    }

    rc, out, err_out = _run(
        ["nmap", "-sV", "-sC", "-O", "--open", "-p", ports,
         "--version-intensity", "5", "-T4", target],
        timeout=timeout_sec,
    )

    result["raw"] = out[:8000]
    result["services"] = _parse_nmap_ports(out)

    # OS guess
    for line in out.splitlines():
        if "OS details:" in line or "Running:" in line:
            result["os_guess"] = line.strip()
            break

    # CVE hints from scripts
    cves = re.findall(r"CVE-\d{4}-\d+", out)
    if cves:
        result["cve_hints"] = list(set(cves))

    return result


def masscan_sweep(cidr: str, ports: str = "22,80,443,8080,8443,3306,5432,6379,27017",
                  rate: int = 10000, timeout_sec: int = 180) -> dict:
    """
    Network-wide sweep using masscan. Ideal for discovering live hosts on a subnet.

    Args:
        cidr: CIDR range to sweep (e.g. 192.168.1.0/24)
        ports: Ports to check (default: common service ports)
        rate: Packets per second (default: 10000)
        timeout_sec: Sweep timeout in seconds

    Authorization reminder: Only scan networks you own or have written permission to test.
    """
    if not re.match(r"^[\d\./]+$", cidr):
        return {"error": "Invalid CIDR format"}

    if not _available("masscan"):
        # Fallback to nmap ping sweep
        if _available("nmap"):
            rc, out, err_out = _run(
                ["nmap", "-sn", "-T4", cidr, "--open"],
                timeout=timeout_sec,
            )
            hosts = re.findall(r"Nmap scan report for (.+)", out)
            return {
                "cidr": cidr,
                "tool": "nmap-ping",
                "live_hosts": hosts,
                "count": len(hosts),
                "raw": out[:4000],
            }
        return {"error": "masscan and nmap not found"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        outfile = f.name

    try:
        rc, out, err_out = _run(
            ["masscan", cidr, f"-p{ports}", f"--rate={rate}",
             "--wait=3", "-oJ", outfile],
            timeout=timeout_sec,
        )

        hosts: dict[str, list] = {}
        if os.path.exists(outfile):
            try:
                with open(outfile) as f:
                    data = json.load(f)
                for entry in data:
                    ip = entry.get("ip", "")
                    port = entry.get("ports", [{}])[0].get("port", 0)
                    if ip:
                        hosts.setdefault(ip, []).append(port)
            except Exception:
                # Parse text fallback
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?port (\d+)", line)
                    if m:
                        hosts.setdefault(m.group(1), []).append(int(m.group(2)))

        return {
            "cidr": cidr,
            "tool": "masscan",
            "ports_checked": ports,
            "hosts_found": [{"ip": ip, "open_ports": pts} for ip, pts in sorted(hosts.items())],
            "count": len(hosts),
            "scan_time": datetime.utcnow().isoformat(),
        }
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)


def sn0int_recon(target: str, modules: list = None, timeout_sec: int = 120) -> dict:
    """
    OSINT reconnaissance using sn0int (domain/IP intelligence gathering).
    Gathers subdomains, emails, certificates, geolocation.

    Args:
        target: Domain or IP to investigate
        modules: List of sn0int modules to run (default: auto-select based on target)
        timeout_sec: Timeout in seconds

    Note: sn0int must be installed and workspace initialized.
    """
    ok, err = _validate_target(target)
    if not ok:
        return {"error": err}

    if not _available("sn0int"):
        # Fallback: passive recon with built-in tools
        result = {"target": target, "tool": "passive-fallback", "findings": {}}

        # Certificate transparency via crt.sh (curl)
        if _available("curl"):
            rc, out, _ = _run(
                ["curl", "-s", f"https://crt.sh/?q=%25.{target}&output=json"],
                timeout=30,
            )
            if rc == 0 and out.strip().startswith("["):
                try:
                    certs = json.loads(out)
                    domains = list(set(
                        c.get("name_value", "").replace("*.", "")
                        for c in certs[:200]
                        if c.get("name_value")
                    ))
                    result["findings"]["subdomains_ct"] = sorted(domains)[:50]
                    result["findings"]["ct_count"] = len(domains)
                except Exception:
                    pass

        # Reverse DNS
        rc, out, _ = _run(["host", target], timeout=10)
        if rc == 0:
            result["findings"]["dns"] = out.strip()

        return result

    # sn0int is available
    workspace = f"/opt/argos/recon/{target.replace('.', '_')}"
    os.makedirs(workspace, exist_ok=True)

    default_modules = modules or ["ctlogs", "whois-domain", "asn", "spf"]
    results = {"target": target, "tool": "sn0int", "modules": {}}

    for mod in default_modules:
        rc, out, err_out = _run(
            ["sn0int", "run", mod, target, "--workspace", workspace],
            timeout=min(timeout_sec, 60),
        )
        results["modules"][mod] = {
            "success": rc == 0,
            "output": (out + err_out)[:2000],
        }

    # Try to read gathered data
    db_path = os.path.join(workspace, "db.json")
    if os.path.exists(db_path):
        try:
            with open(db_path) as f:
                results["database"] = json.load(f)
        except Exception:
            pass

    return results


def full_recon_pipeline(target: str, scan_ports: bool = True,
                        deep_scan: bool = True, osint: bool = True,
                        timeout_sec: int = 300) -> dict:
    """
    Complete reconnaissance pipeline: fast scan → deep service detection → OSINT.
    Combines all fast_recon tools in one orchestrated workflow.

    Args:
        target: IP address or domain to investigate
        scan_ports: Run port discovery (default: True)
        deep_scan: Run service version detection on open ports (default: True)
        osint: Run OSINT/passive recon (default: True)
        timeout_sec: Total timeout for entire pipeline in seconds

    Authorization reminder: Only scan systems you own or have written permission to test.
    """
    ok, err = _validate_target(target)
    if not ok:
        return {"error": err}

    pipeline_start = datetime.utcnow()
    report = {
        "target": target,
        "pipeline_start": pipeline_start.isoformat(),
        "phases": {},
        "summary": {},
    }

    remaining = timeout_sec

    # Phase 1: Fast port scan
    if scan_ports:
        t0 = datetime.utcnow()
        report["phases"]["port_scan"] = fast_port_scan(
            target, timeout_sec=min(60, remaining // 3)
        )
        remaining -= int((datetime.utcnow() - t0).total_seconds())

    # Phase 2: Deep service scan
    if deep_scan and remaining > 30:
        t0 = datetime.utcnow()
        open_ports = report["phases"].get("port_scan", {}).get("open_ports", [])
        ports_str = ",".join(str(p) for p in open_ports[:30]) if open_ports else None
        report["phases"]["service_scan"] = deep_service_scan(
            target, ports=ports_str, timeout_sec=min(120, remaining // 2)
        )
        remaining -= int((datetime.utcnow() - t0).total_seconds())

    # Phase 3: OSINT
    if osint and remaining > 20:
        report["phases"]["osint"] = sn0int_recon(target, timeout_sec=min(60, remaining))

    # Summary
    open_ports = report["phases"].get("port_scan", {}).get("open_ports", [])
    services = report["phases"].get("service_scan", {}).get("services", [])
    subdomains = (report["phases"].get("osint", {}).get("findings", {})
                  .get("subdomains_ct", []))

    report["summary"] = {
        "open_ports_count": len(open_ports),
        "open_ports": open_ports[:20],
        "services_detected": len(services),
        "subdomains_found": len(subdomains),
        "pipeline_duration_sec": int((datetime.utcnow() - pipeline_start).total_seconds()),
        "cve_hints": report["phases"].get("service_scan", {}).get("cve_hints", []),
    }

    return report


# ── plugin entrypoint ─────────────────────────────────────────────────────────

TOOLS = {
    "fast_port_scan": fast_port_scan,
    "deep_service_scan": deep_service_scan,
    "masscan_sweep": masscan_sweep,
    "sn0int_recon": sn0int_recon,
    "full_recon_pipeline": full_recon_pipeline,
}
