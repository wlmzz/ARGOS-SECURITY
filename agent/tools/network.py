"""Network recon tools: nmap, masscan, whois, ping, traceroute, dns."""
from __future__ import annotations
import subprocess, socket, json, re
from typing import Any


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()[:4000]
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return f"[TOOL NOT FOUND: {cmd[0]}] — run: apt install {cmd[0]}"
    except Exception as e:
        return f"[ERROR: {e}]"


def nmap_scan(target: str, flags: str = "-sV -T4 --top-ports 100") -> dict:
    """Port scan with nmap. flags: nmap options string."""
    safe_flags = re.sub(r"[^a-zA-Z0-9\s\-\.\/]", "", flags)
    cmd = ["nmap"] + safe_flags.split() + [target]
    return {"tool": "nmap", "target": target, "flags": safe_flags, "output": _run(cmd, 60)}


def ping_host(target: str, count: int = 4) -> dict:
    """Ping a host to check reachability."""
    count = min(max(1, count), 10)
    return {"tool": "ping", "target": target,
            "output": _run(["ping", "-c", str(count), target])}


def traceroute(target: str) -> dict:
    """Traceroute to map network path."""
    return {"tool": "traceroute", "target": target,
            "output": _run(["traceroute", "-m", "15", target], 30)}


def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """DNS lookup for a domain."""
    valid_types = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"}
    record_type = record_type.upper() if record_type.upper() in valid_types else "A"
    return {"tool": "dig", "domain": domain, "type": record_type,
            "output": _run(["dig", "+short", record_type, domain])}


def whois_lookup(target: str) -> dict:
    """WHOIS lookup for domain or IP."""
    return {"tool": "whois", "target": target,
            "output": _run(["whois", target], 20)}


def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"tool": "reverse_dns", "ip": ip, "hostname": hostname}
    except Exception as e:
        return {"tool": "reverse_dns", "ip": ip, "error": str(e)}


def masscan_scan(target: str, ports: str = "0-1000", rate: int = 500) -> dict:
    """Fast port discovery with masscan. Use for authorized targets only.
    target: IP, CIDR range (e.g. 192.168.1.0/24), or single host.
    ports: port range e.g. '80,443,22' or '0-65535'.
    rate: packets/sec — capped at 10000 for safety.
    """
    if not re.match(r"^[\d\.\/\-,a-zA-Z]+$", target):
        return {"error": "Invalid target format"}
    if not re.match(r"^[\d,\-]+$", ports):
        return {"error": "Invalid ports format"}
    rate = min(max(1, rate), 10000)
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--open", "--output-format", "json", "--output-filename", "-"]
    output = _run(cmd, timeout=120)
    # Parse masscan JSON output
    try:
        results = json.loads(f"[{output.replace('}{', '},{')}]") if output.startswith("{") else json.loads(output)
        open_ports = [{"ip": r.get("ip"), "port": r.get("ports", [{}])[0].get("port"), "proto": r.get("ports", [{}])[0].get("proto")} for r in results if isinstance(r, dict)]
        return {"tool": "masscan", "target": target, "ports": ports, "rate": rate, "open_ports": open_ports, "count": len(open_ports)}
    except Exception:
        return {"tool": "masscan", "target": target, "ports": ports, "rate": rate, "raw_output": output}


TOOLS = {
    "nmap_scan": {
        "fn": nmap_scan,
        "description": "Run nmap port scan on a target IP or hostname. Use for authorized recon.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to scan"},
                "flags": {"type": "string", "description": "nmap flags, default: -sV -T4 --top-ports 100"}
            },
            "required": ["target"]
        }
    },
    "ping_host": {
        "fn": ping_host,
        "description": "Ping a host to check if it is reachable.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "count": {"type": "integer", "description": "Number of ping packets (1-10)"}
            },
            "required": ["target"]
        }
    },
    "dns_lookup": {
        "fn": dns_lookup,
        "description": "DNS lookup for a domain. Supports A, AAAA, MX, TXT, NS, CNAME records.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to query"},
                "record_type": {"type": "string", "description": "DNS record type: A, MX, TXT, NS, etc."}
            },
            "required": ["domain"]
        }
    },
    "whois_lookup": {
        "fn": whois_lookup,
        "description": "WHOIS lookup for a domain name or IP address.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to look up"}
            },
            "required": ["target"]
        }
    },
    "reverse_dns": {
        "fn": reverse_dns,
        "description": "Reverse DNS lookup — find hostname for an IP address.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address for reverse lookup"}
            },
            "required": ["ip"]
        }
    },
    "masscan_scan": {
        "fn": masscan_scan,
        "description": "Ultra-fast port discovery with masscan. Scans thousands of ports/hosts per second. Use only on authorized targets. Returns list of open ports.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address, CIDR range (e.g. 192.168.1.0/24), or hostname"},
                "ports": {"type": "string", "description": "Port range: '80,443,22' or '0-1000' or '0-65535'. Default: 0-1000"},
                "rate": {"type": "integer", "description": "Scan rate in packets/sec (1-10000). Default: 500"}
            },
            "required": ["target"]
        }
    }
}
