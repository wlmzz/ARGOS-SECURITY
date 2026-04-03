"""
network_capture.py — ARGOS plugin
Network packet capture, traffic analysis, and ML-based threat detection.
Integrates PacketStreamer (Deepfence), FlowMeter, tcpdump, tshark.
"""

import subprocess
import json
import os
import re
import shutil
import signal
import tempfile
from datetime import datetime

MANIFEST = {
    "id": "network_capture",
    "name": "Network Capture",
    "version": "1.0.0",
    "description": "Distributed packet capture, flow analysis, ML threat detection",
    "author": "ARGOS",
    "category": "network",
    "tools": [
        "capture_start",
        "capture_stop",
        "analyze_pcap",
        "flowmeter_analyze",
        "capture_summary",
    ],
}

CAPTURE_DIR = "/opt/argos/captures"
STATE_FILE = os.path.join(CAPTURE_DIR, "active_captures.json")
os.makedirs(CAPTURE_DIR, exist_ok=True)


def _run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _load_state() -> dict:
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"captures": {}}


def _save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _ensure_flowmeter() -> tuple[bool, str]:
    """Download FlowMeter binary if not present."""
    if shutil.which("flowmeter"):
        return True, shutil.which("flowmeter")

    fm_bin = "/usr/local/bin/flowmeter"
    if os.path.exists(fm_bin):
        return True, fm_bin

    # Try to download from Deepfence releases
    rc, out, err = _run(
        ["curl", "-sL",
         "https://github.com/deepfence/FlowMeter/releases/latest/download/flowmeter-linux-amd64",
         "-o", fm_bin, "--connect-timeout", "15"],
        timeout=60,
    )
    if rc == 0 and os.path.exists(fm_bin):
        os.chmod(fm_bin, 0o755)
        return True, fm_bin

    # Try Go install
    if shutil.which("go"):
        rc2, _, err2 = _run(
            ["go", "install", "github.com/deepfence/FlowMeter/pkg/...@latest"],
            timeout=180,
        )
        if rc2 == 0:
            gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()
            bin_path = os.path.join(gopath, "bin", "flowtbag")
            if os.path.exists(bin_path):
                return True, bin_path

    return False, "FlowMeter not available"


def capture_start(interface: str = "eth0", duration_sec: int = 60,
                  filter_expr: str = "", output_file: str = None,
                  name: str = None) -> dict:
    """
    Start a network packet capture on a specific interface.
    Uses tcpdump (primary) or tshark (fallback).

    Args:
        interface: Network interface to capture on (default: eth0)
        duration_sec: Capture duration in seconds (default: 60, max: 3600)
        filter_expr: BPF filter expression (e.g. 'port 80', 'host 1.2.3.4')
        output_file: Path to save .pcap file (default: auto-generated)
        name: Friendly name for this capture session

    Returns:
        Capture ID, output file path, and process info
    """
    duration_sec = min(duration_sec, 3600)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    capture_id = f"cap_{ts}"
    outfile = output_file or os.path.join(CAPTURE_DIR, f"{capture_id}.pcap")

    if not shutil.which("tcpdump") and not shutil.which("tshark"):
        return {"error": "No capture tool available",
                "install": "apt install tcpdump  OR  apt install tshark"}

    # Build command
    if shutil.which("tcpdump"):
        cmd = ["tcpdump", "-i", interface, "-w", outfile,
               "-G", str(duration_sec), "-W", "1"]
        if filter_expr:
            cmd += [filter_expr]
        tool = "tcpdump"
    else:
        cmd = ["tshark", "-i", interface, "-w", outfile,
               "-a", f"duration:{duration_sec}"]
        if filter_expr:
            cmd += ["-f", filter_expr]
        tool = "tshark"

    # Start as background process
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

        state = _load_state()
        state["captures"][capture_id] = {
            "pid": proc.pid,
            "interface": interface,
            "duration_sec": duration_sec,
            "filter": filter_expr,
            "output_file": outfile,
            "tool": tool,
            "name": name or capture_id,
            "start_time": datetime.utcnow().isoformat(),
            "status": "running",
        }
        _save_state(state)

        return {
            "capture_id": capture_id,
            "pid": proc.pid,
            "output_file": outfile,
            "interface": interface,
            "duration_sec": duration_sec,
            "filter": filter_expr,
            "tool": tool,
            "stop_cmd": f"capture_stop('{capture_id}')",
            "analyze_cmd": f"analyze_pcap('{outfile}')",
        }
    except Exception as e:
        return {"error": f"Failed to start capture: {e}"}


def capture_stop(capture_id: str = None, all_captures: bool = False) -> dict:
    """
    Stop an active packet capture.

    Args:
        capture_id: ID returned by capture_start (optional if all_captures=True)
        all_captures: Stop all running captures (default: False)

    Returns:
        Status of stopped capture(s) and output file paths
    """
    state = _load_state()
    stopped = []

    targets = list(state["captures"].keys()) if all_captures else [capture_id]

    for cid in targets:
        if cid not in state["captures"]:
            continue
        cap = state["captures"][cid]
        pid = cap.get("pid")

        if pid:
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                stopped.append({
                    "capture_id": cid,
                    "output_file": cap["output_file"],
                    "status": "stopped",
                })
            except ProcessLookupError:
                stopped.append({
                    "capture_id": cid,
                    "output_file": cap["output_file"],
                    "status": "already_completed",
                })
            cap["status"] = "stopped"

    _save_state(state)

    result = {"stopped": stopped}
    if stopped:
        result["next_step"] = f"analyze_pcap('{stopped[0]['output_file']}')"
    return result


def analyze_pcap(pcap_file: str, top_n: int = 20,
                  extract_iocs: bool = True) -> dict:
    """
    Analyze a PCAP file for network IOCs, suspicious connections, and threat indicators.
    Extracts hosts, protocols, DNS queries, HTTP requests, and credential exposure.

    Args:
        pcap_file: Path to .pcap or .pcapng file
        top_n: Number of top talkers/connections to show (default: 20)
        extract_iocs: Extract domains, IPs, URLs from traffic (default: True)

    Returns:
        Traffic summary, top connections, IOCs, suspicious patterns
    """
    if not os.path.exists(pcap_file):
        return {"error": f"PCAP not found: {pcap_file}"}

    result = {
        "pcap_file": pcap_file,
        "analysis_time": datetime.utcnow().isoformat(),
        "summary": {},
        "top_connections": [],
        "dns_queries": [],
        "http_requests": [],
        "iocs": [],
        "suspicious": [],
    }

    # Try tshark for rich analysis
    if shutil.which("tshark"):
        # Packet statistics
        rc, out, _ = _run(
            ["tshark", "-r", pcap_file, "-q", "-z", "io,stat,0"],
            timeout=30,
        )
        if rc == 0:
            result["summary"]["raw_stats"] = out[:1000]

        # Top conversations
        rc, out, _ = _run(
            ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"],
            timeout=30,
        )
        if rc == 0:
            lines = out.strip().splitlines()
            result["top_connections"] = lines[3:3 + top_n]  # skip header

        # DNS queries
        rc, out, _ = _run(
            ["tshark", "-r", pcap_file, "-Y", "dns.qry.name",
             "-T", "fields", "-e", "dns.qry.name", "-e", "ip.dst"],
            timeout=30,
        )
        if rc == 0:
            domains = []
            for line in out.strip().splitlines()[:100]:
                parts = line.split("\t")
                if parts[0]:
                    domains.append({"domain": parts[0], "server": parts[1] if len(parts) > 1 else ""})
            result["dns_queries"] = domains

        # HTTP hosts/URIs
        rc, out, _ = _run(
            ["tshark", "-r", pcap_file, "-Y", "http.request",
             "-T", "fields", "-e", "http.host", "-e", "http.request.uri",
             "-e", "ip.dst"],
            timeout=30,
        )
        if rc == 0:
            requests = []
            for line in out.strip().splitlines()[:50]:
                parts = line.split("\t")
                if parts:
                    requests.append({
                        "host": parts[0] if len(parts) > 0 else "",
                        "uri": parts[1] if len(parts) > 1 else "",
                        "dst_ip": parts[2] if len(parts) > 2 else "",
                    })
            result["http_requests"] = requests

        # Credentials in cleartext (HTTP Basic auth, FTP, Telnet)
        rc, out, _ = _run(
            ["tshark", "-r", pcap_file, "-Y",
             "http.authorization or ftp.request.command==\"PASS\" or telnet.data",
             "-T", "fields", "-e", "http.authorization",
             "-e", "ftp.request.arg", "-e", "telnet.data"],
            timeout=30,
        )
        if rc == 0 and out.strip():
            result["suspicious"].append({
                "type": "cleartext_credentials",
                "data": out[:1000],
            })

    elif shutil.which("tcpdump"):
        # Basic tcpdump analysis
        rc, out, _ = _run(
            ["tcpdump", "-r", pcap_file, "-nn", "-q"],
            timeout=30,
        )
        if rc == 0:
            lines = out.strip().splitlines()
            result["summary"]["total_packets"] = len(lines)
            result["summary"]["sample"] = lines[:20]

            # Extract IPs
            ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', out)
            ip_counts = {}
            for ip in ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            result["top_connections"] = [
                {"ip": ip, "count": count}
                for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
            ]

    else:
        return {"error": "No PCAP analyzer available", "install": "apt install tshark tcpdump"}

    # IOC extraction from traffic
    if extract_iocs:
        all_domains = set(d["domain"] for d in result["dns_queries"] if d.get("domain"))
        all_ips = set()
        for conn in result["top_connections"]:
            # Extract IPs from connection strings
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', str(conn)):
                all_ips.add(m.group(1))

        # Flag RFC1918-external connections (potential C2)
        private_ranges = [
            re.compile(r"^10\."), re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
            re.compile(r"^192\.168\.")
        ]
        external_ips = [
            ip for ip in all_ips
            if not any(p.match(ip) for p in private_ranges)
            and not ip.startswith("127.")
        ]

        result["iocs"] = {
            "domains": list(all_domains)[:50],
            "external_ips": external_ips[:50],
        }

    return result


def flowmeter_analyze(pcap_file: str, model: str = "rf",
                       threshold: float = 0.5) -> dict:
    """
    ML-based network traffic classification using FlowMeter (Deepfence).
    Classifies flows as benign or malicious using Random Forest / Neural Net.

    Args:
        pcap_file: Path to .pcap file to analyze
        model: ML model to use: 'rf' (Random Forest) or 'nn' (Neural Network)
        threshold: Classification confidence threshold (default: 0.5)

    Returns:
        Per-flow classification with confidence scores and malicious flow stats
    """
    if not os.path.exists(pcap_file):
        return {"error": f"PCAP not found: {pcap_file}"}

    ok, fm_path = _ensure_flowmeter()
    if not ok:
        # Fallback: statistical analysis without ML
        return _flowmeter_statistical_fallback(pcap_file)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(CAPTURE_DIR, f"flows_{ts}.csv")

    rc, out, err = _run(
        [fm_path, "-pcap", pcap_file, "-output", outfile, "-model", model],
        timeout=120,
    )

    result = {
        "pcap_file": pcap_file,
        "tool": "flowmeter",
        "model": model,
        "output_file": outfile,
        "analysis_time": datetime.utcnow().isoformat(),
    }

    if rc == 0 and os.path.exists(outfile):
        # Parse CSV results
        import csv
        flows = []
        malicious = []
        with open(outfile) as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row.get("label", row.get("Label", "unknown"))
                confidence = float(row.get("confidence", row.get("Confidence", 0)) or 0)
                flow_entry = {
                    "src_ip": row.get("src_ip", row.get("Source IP", "")),
                    "dst_ip": row.get("dst_ip", row.get("Destination IP", "")),
                    "dst_port": row.get("dst_port", row.get("Destination Port", "")),
                    "protocol": row.get("protocol", row.get("Protocol", "")),
                    "label": label,
                    "confidence": confidence,
                }
                flows.append(flow_entry)
                if label.lower() not in ("benign", "normal") and confidence >= threshold:
                    malicious.append(flow_entry)

        result["total_flows"] = len(flows)
        result["malicious_flows"] = malicious[:50]
        result["malicious_count"] = len(malicious)
        result["benign_count"] = len(flows) - len(malicious)
        result["threat_ratio"] = round(len(malicious) / max(len(flows), 1), 3)
    else:
        result["error"] = err[:1000] or "FlowMeter returned no output"
        result["raw"] = out[:2000]

    return result


def _flowmeter_statistical_fallback(pcap_file: str) -> dict:
    """Statistical flow analysis without ML when FlowMeter is unavailable."""
    result = {
        "pcap_file": pcap_file,
        "tool": "statistical-fallback",
        "note": "FlowMeter not available — using statistical heuristics",
        "analysis_time": datetime.utcnow().isoformat(),
        "suspicious_flows": [],
    }

    if not shutil.which("tshark"):
        return {"error": "Neither FlowMeter nor tshark available",
                "install": "apt install tshark"}

    # Analyze flow statistics with tshark
    # High-rate connections (potential DDoS/scan)
    rc, out, _ = _run(
        ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp", "-z", "conv,udp"],
        timeout=30,
    )
    if rc == 0:
        result["flow_stats"] = out[:3000]

    # Long-duration connections (potential exfil/C2 beacon)
    rc, out, _ = _run(
        ["tshark", "-r", pcap_file, "-q", "-z", "endpoints,tcp"],
        timeout=30,
    )
    if rc == 0:
        result["endpoint_stats"] = out[:2000]

    return result


def capture_summary() -> dict:
    """
    List all capture sessions (active and completed) with file sizes and status.

    Returns:
        All captures with status, file sizes, and analysis links
    """
    state = _load_state()
    summaries = []

    for cid, cap in state["captures"].items():
        outfile = cap.get("output_file", "")
        size = os.path.getsize(outfile) if os.path.exists(outfile) else 0

        # Check if process is still running
        pid = cap.get("pid")
        running = False
        if pid:
            try:
                os.kill(pid, 0)
                running = True
            except OSError:
                pass

        summaries.append({
            "capture_id": cid,
            "name": cap.get("name", cid),
            "interface": cap.get("interface"),
            "filter": cap.get("filter"),
            "start_time": cap.get("start_time"),
            "output_file": outfile,
            "size_bytes": size,
            "status": "running" if running else "completed",
            "tool": cap.get("tool"),
        })

    summaries.sort(key=lambda x: x.get("start_time", ""), reverse=True)

    return {
        "total_captures": len(summaries),
        "active": sum(1 for s in summaries if s["status"] == "running"),
        "captures": summaries,
        "captures_dir": CAPTURE_DIR,
    }


TOOLS = {
    "capture_start": capture_start,
    "capture_stop": capture_stop,
    "analyze_pcap": analyze_pcap,
    "flowmeter_analyze": flowmeter_analyze,
    "capture_summary": capture_summary,
}
