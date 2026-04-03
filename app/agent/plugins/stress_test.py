"""
stress_test.py — ARGOS plugin
Legitimate load & stress testing for systems you own or have authorization to test.
Tools: HTTP benchmark (ab/wrk/hey), TCP flood test (hping3), bandwidth test (iperf3),
       slow-connection test (slowhttptest).

IMPORTANT: This plugin requires explicit written authorization for any target.
           Unauthorized use constitutes a crime in most jurisdictions.
"""

import subprocess
import json
import re
import shutil
import os
from datetime import datetime

MANIFEST = {
    "id": "stress_test",
    "name": "Stress Test",
    "version": "1.0.0",
    "description": "Authorized load/stress testing: HTTP benchmark, TCP, bandwidth, slow-loris",
    "author": "ARGOS",
    "category": "pentest",
    "tools": [
        "http_load_test",
        "tcp_flood_test",
        "bandwidth_test",
        "slowhttp_test",
        "stress_report",
    ],
}

# ── authorization gate ────────────────────────────────────────────────────────

_AUTH_DISCLAIMER = (
    "AUTHORIZATION REQUIRED: Stress testing without written permission is illegal. "
    "Set authorized=True only after confirming you own the target or have written authorization."
)


def _check_auth(authorized: bool, target: str) -> tuple[bool, str]:
    if not authorized:
        return False, _AUTH_DISCLAIMER
    if not target or len(target) > 256:
        return False, "Invalid target"
    return True, ""


def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


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


# ── tools ─────────────────────────────────────────────────────────────────────

def http_load_test(url: str, concurrency: int = 50, requests_total: int = 10000,
                   duration_sec: int = 30, authorized: bool = False) -> dict:
    """
    HTTP load benchmark using wrk, hey, or Apache Benchmark (ab).
    Measures throughput, latency, and error rates.

    Args:
        url: Target URL (must start with http:// or https://)
        concurrency: Concurrent connections (default: 50)
        requests_total: Total requests for ab (default: 10000, ignored by wrk)
        duration_sec: Duration in seconds for wrk/hey (default: 30)
        authorized: MUST be True — confirms you have authorization to test this target

    Returns:
        Benchmark results: req/s, latency percentiles, errors
    """
    ok, err = _check_auth(authorized, url)
    if not ok:
        return {"error": err}

    if not re.match(r"^https?://", url):
        return {"error": "URL must start with http:// or https://"}

    result = {
        "url": url,
        "concurrency": concurrency,
        "authorized": True,
        "tool_used": None,
        "scan_time": datetime.utcnow().isoformat(),
        "metrics": {},
        "raw": "",
    }

    # Try wrk first (most accurate)
    if _available("wrk"):
        result["tool_used"] = "wrk"
        rc, out, err_out = _run(
            ["wrk", "-t", str(min(concurrency, 12)), "-c", str(concurrency),
             "-d", f"{duration_sec}s", "--latency", url],
            timeout=duration_sec + 30,
        )
        result["raw"] = (out + err_out)[:4000]
        # Parse wrk output
        for line in out.splitlines():
            m = re.search(r"Requests/sec:\s+([\d.]+)", line)
            if m:
                result["metrics"]["req_per_sec"] = float(m.group(1))
            m = re.search(r"Transfer/sec:\s+([\d.]+\w+)", line)
            if m:
                result["metrics"]["transfer_per_sec"] = m.group(1)
            m = re.search(r"(\d+) requests in", line)
            if m:
                result["metrics"]["total_requests"] = int(m.group(1))
        # Latency percentiles
        for pct in ["50%", "75%", "90%", "99%"]:
            m = re.search(rf"{re.escape(pct)}\s+([\d.]+\w+)", out)
            if m:
                result["metrics"][f"latency_{pct}"] = m.group(1)
        return result

    # Try hey
    if _available("hey"):
        result["tool_used"] = "hey"
        rc, out, err_out = _run(
            ["hey", "-n", str(requests_total), "-c", str(concurrency),
             "-z", f"{duration_sec}s", url],
            timeout=duration_sec + 30,
        )
        result["raw"] = (out + err_out)[:4000]
        m = re.search(r"Requests/sec:\s+([\d.]+)", out)
        if m:
            result["metrics"]["req_per_sec"] = float(m.group(1))
        m = re.search(r"Total:\s+([\d.]+)\s+secs", out)
        if m:
            result["metrics"]["total_sec"] = float(m.group(1))
        return result

    # Fallback: Apache Benchmark (ab)
    if _available("ab"):
        result["tool_used"] = "ab"
        rc, out, err_out = _run(
            ["ab", f"-n{requests_total}", f"-c{concurrency}", "-t", str(duration_sec), url],
            timeout=duration_sec + 30,
        )
        result["raw"] = (out + err_out)[:4000]
        for line in out.splitlines():
            m = re.search(r"Requests per second:\s+([\d.]+)", line)
            if m:
                result["metrics"]["req_per_sec"] = float(m.group(1))
            m = re.search(r"Time per request:\s+([\d.]+).*\[ms\] \(mean\)", line)
            if m:
                result["metrics"]["mean_latency_ms"] = float(m.group(1))
            m = re.search(r"Failed requests:\s+(\d+)", line)
            if m:
                result["metrics"]["failed_requests"] = int(m.group(1))
        return result

    return {
        "error": "No HTTP load tool available. Install wrk, hey, or apache2-utils (ab).",
        "install_hint": "apt install apache2-utils wrk",
    }


def tcp_flood_test(target: str, port: int, duration_sec: int = 10,
                   packet_size: int = 120, pps: int = 1000,
                   authorized: bool = False) -> dict:
    """
    TCP SYN flood stress test using hping3.
    Tests server's ability to handle high connection rates.
    For firewall/IDS tuning and capacity planning.

    Args:
        target: Target IP or hostname
        port: Target TCP port
        duration_sec: Test duration (default: 10s, max: 60s)
        packet_size: Packet data size in bytes (default: 120)
        pps: Packets per second (default: 1000, max: 10000)
        authorized: MUST be True — confirms you have authorization to test this target

    Returns:
        Packets sent, received, lost; round-trip stats
    """
    ok, err = _check_auth(authorized, target)
    if not ok:
        return {"error": err}

    if not 1 <= port <= 65535:
        return {"error": "Invalid port number"}

    # Safety caps
    duration_sec = min(duration_sec, 60)
    pps = min(pps, 10000)

    if not _available("hping3"):
        return {
            "error": "hping3 not found",
            "install_hint": "apt install hping3",
        }

    result = {
        "target": target,
        "port": port,
        "duration_sec": duration_sec,
        "pps": pps,
        "authorized": True,
        "tool": "hping3",
        "scan_time": datetime.utcnow().isoformat(),
        "metrics": {},
        "raw": "",
    }

    rc, out, err_out = _run(
        ["hping3", "-S", "-p", str(port),
         "--faster", "-d", str(packet_size),
         "-c", str(pps * duration_sec), target],
        timeout=duration_sec + 30,
    )

    combined = out + err_out
    result["raw"] = combined[:4000]

    # Parse hping3 summary
    m = re.search(r"(\d+) packets transmitted, (\d+) received", combined)
    if m:
        result["metrics"]["packets_sent"] = int(m.group(1))
        result["metrics"]["packets_recv"] = int(m.group(2))
        result["metrics"]["packet_loss_pct"] = round(
            (1 - int(m.group(2)) / max(int(m.group(1)), 1)) * 100, 2
        )

    m = re.search(r"min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)", combined)
    if m:
        result["metrics"]["rtt_min_ms"] = float(m.group(1))
        result["metrics"]["rtt_avg_ms"] = float(m.group(2))
        result["metrics"]["rtt_max_ms"] = float(m.group(3))

    return result


def bandwidth_test(server: str, port: int = 5201, duration_sec: int = 10,
                   direction: str = "both", authorized: bool = False) -> dict:
    """
    Network bandwidth test using iperf3.
    Measures actual TCP/UDP throughput between two hosts.
    Requires iperf3 server running on target: `iperf3 -s`

    Args:
        server: iperf3 server IP/hostname
        port: iperf3 server port (default: 5201)
        duration_sec: Test duration (default: 10s)
        direction: "upload", "download", or "both" (default: both)
        authorized: MUST be True — confirms you have authorization to test this target

    Returns:
        Bandwidth in Mbps, jitter, packet loss
    """
    ok, err = _check_auth(authorized, server)
    if not ok:
        return {"error": err}

    if not _available("iperf3"):
        return {
            "error": "iperf3 not found",
            "install_hint": "apt install iperf3",
        }

    result = {
        "server": server,
        "port": port,
        "duration_sec": duration_sec,
        "direction": direction,
        "authorized": True,
        "tool": "iperf3",
        "scan_time": datetime.utcnow().isoformat(),
        "results": {},
    }

    base_cmd = ["iperf3", "-c", server, "-p", str(port),
                 "-t", str(duration_sec), "-J"]

    if direction in ("upload", "both"):
        rc, out, _ = _run(base_cmd, timeout=duration_sec + 30)
        try:
            data = json.loads(out)
            bw = data["end"]["sum_sent"]["bits_per_second"] / 1e6
            result["results"]["upload_mbps"] = round(bw, 2)
            result["results"]["upload_retransmits"] = data["end"]["sum_sent"].get("retransmits", 0)
        except Exception:
            result["results"]["upload_raw"] = out[:2000]

    if direction in ("download", "both"):
        rc, out, _ = _run(base_cmd + ["-R"], timeout=duration_sec + 30)
        try:
            data = json.loads(out)
            bw = data["end"]["sum_received"]["bits_per_second"] / 1e6
            result["results"]["download_mbps"] = round(bw, 2)
        except Exception:
            result["results"]["download_raw"] = out[:2000]

    return result


def slowhttp_test(url: str, connections: int = 200, duration_sec: int = 30,
                  test_type: str = "slowloris", authorized: bool = False) -> dict:
    """
    Slow HTTP attack simulation using slowhttptest or custom implementation.
    Tests server resilience against slow-connection DoS (Slowloris, RUDY, Slow Read).
    Used for WAF/IDS tuning and timeout configuration validation.

    Args:
        url: Target URL
        connections: Number of slow connections (default: 200)
        duration_sec: Test duration in seconds (default: 30)
        test_type: "slowloris", "rudy", or "slowread" (default: slowloris)
        authorized: MUST be True — confirms you have authorization to test this target

    Returns:
        Connections established, server response behavior
    """
    ok, err = _check_auth(authorized, url)
    if not ok:
        return {"error": err}

    if not re.match(r"^https?://", url):
        return {"error": "URL must start with http:// or https://"}

    result = {
        "url": url,
        "test_type": test_type,
        "connections": connections,
        "duration_sec": duration_sec,
        "authorized": True,
        "scan_time": datetime.utcnow().isoformat(),
        "findings": {},
        "raw": "",
    }

    if _available("slowhttptest"):
        type_flags = {
            "slowloris": ["-H"],
            "rudy": ["-B"],
            "slowread": ["-X"],
        }
        flags = type_flags.get(test_type, ["-H"])

        rc, out, err_out = _run(
            ["slowhttptest"] + flags +
            ["-u", url, "-c", str(connections), "-l", str(duration_sec),
             "-i", "10", "-r", "200"],
            timeout=duration_sec + 30,
        )
        result["raw"] = (out + err_out)[:4000]
        result["tool"] = "slowhttptest"

        # Parse results
        for line in (out + err_out).splitlines():
            if "service available" in line.lower():
                result["findings"]["service_status"] = line.strip()
            if "connections" in line.lower() and re.search(r"\d+", line):
                result["findings"]["connection_info"] = line.strip()

    else:
        # Pure Python Slowloris simulation (educational reference implementation)
        import socket
        import time
        import threading

        result["tool"] = "python-slowloris"
        host_match = re.match(r"https?://([^/:]+)(?::(\d+))?", url)
        if not host_match:
            return {"error": "Cannot parse URL"}

        host = host_match.group(1)
        port = int(host_match.group(2) or (443 if url.startswith("https") else 80))

        sockets_open = []
        sockets_failed = 0
        lock = threading.Lock()

        def _open_socket():
            nonlocal sockets_failed
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((host, port))
                s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
                with lock:
                    sockets_open.append(s)
            except Exception:
                with lock:
                    sockets_failed += 1

        threads = [threading.Thread(target=_open_socket) for _ in range(min(connections, 200))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        time.sleep(min(duration_sec, 10))

        # Keep sockets alive briefly
        alive = 0
        for s in sockets_open:
            try:
                s.send(b"X-Header: keep-alive\r\n")
                alive += 1
            except Exception:
                pass

        for s in sockets_open:
            try:
                s.close()
            except Exception:
                pass

        result["findings"] = {
            "connections_opened": len(sockets_open),
            "connections_failed": sockets_failed,
            "connections_kept_alive": alive,
            "server_resistant": sockets_failed > len(sockets_open),
        }

    return result


def stress_report(results: list) -> dict:
    """
    Generate a consolidated stress test report from multiple test results.
    Summarizes findings, identifies bottlenecks, and provides hardening recommendations.

    Args:
        results: List of results from http_load_test, tcp_flood_test, bandwidth_test, etc.

    Returns:
        Consolidated report with findings and recommendations
    """
    if not results or not isinstance(results, list):
        return {"error": "Pass a list of test results from other stress_test tools"}

    report = {
        "generated": datetime.utcnow().isoformat(),
        "tests_analyzed": len(results),
        "findings": [],
        "recommendations": [],
        "risk_level": "LOW",
    }

    for r in results:
        if "error" in r:
            continue

        # HTTP load analysis
        if "req_per_sec" in r.get("metrics", {}):
            rps = r["metrics"]["req_per_sec"]
            if rps < 100:
                report["findings"].append(f"Low HTTP throughput: {rps:.1f} req/s")
                report["recommendations"].append(
                    "Consider enabling HTTP/2, connection keep-alive, and caching"
                )
                report["risk_level"] = "HIGH"
            elif rps < 500:
                report["findings"].append(f"Moderate HTTP throughput: {rps:.1f} req/s")
                report["risk_level"] = max(report["risk_level"], "MEDIUM",
                                            key=lambda x: ["LOW", "MEDIUM", "HIGH"].index(x))

        # Packet loss analysis
        if "packet_loss_pct" in r.get("metrics", {}):
            loss = r["metrics"]["packet_loss_pct"]
            if loss > 5:
                report["findings"].append(f"High packet loss: {loss:.1f}%")
                report["recommendations"].append(
                    "Investigate network congestion, firewall rate limiting"
                )

        # Slowloris analysis
        if "connections_kept_alive" in r.get("findings", {}):
            alive = r["findings"]["connections_kept_alive"]
            if alive > 100:
                report["findings"].append(
                    f"Server vulnerable to Slowloris: {alive} slow connections sustained"
                )
                report["recommendations"].append(
                    "Configure timeout settings: LimitRequestFields, Timeout, KeepAliveTimeout. "
                    "Consider mod_reqtimeout (Apache) or limit_req (nginx)"
                )
                report["risk_level"] = "HIGH"

        # Bandwidth
        if "upload_mbps" in r.get("results", {}):
            mbps = r["results"]["upload_mbps"]
            report["findings"].append(f"Upload bandwidth: {mbps:.1f} Mbps")

    if not report["findings"]:
        report["findings"].append("No significant issues detected in analyzed tests")

    return report


# ── plugin entrypoint ─────────────────────────────────────────────────────────

TOOLS = {
    "http_load_test": http_load_test,
    "tcp_flood_test": tcp_flood_test,
    "bandwidth_test": bandwidth_test,
    "slowhttp_test": slowhttp_test,
    "stress_report": stress_report,
}
