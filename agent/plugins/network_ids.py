"""
ARGOS Plugin: Network IDS
Network intrusion detection and PCAP analysis via Zeek and Suricata.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile

MANIFEST = {
    "id": "network-ids",
    "name": "Network IDS (Zeek + Suricata)",
    "description": (
        "Network intrusion detection and PCAP analysis using Zeek and Suricata. "
        "Parses protocol logs, extracts IOCs (IPs, domains, URLs, file hashes), "
        "and surfaces IDS alerts with severity classification."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

_SUBPROCESS_TIMEOUT = 120

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: list, *, cwd: str | None = None) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        cwd=cwd,
    )
    return result.returncode, result.stdout, result.stderr


def _zeek_available() -> bool:
    return shutil.which("zeek") is not None


def _suricata_available() -> bool:
    return shutil.which("suricata") is not None


def _pcap_exists(pcap_file: str) -> dict | None:
    if not os.path.exists(pcap_file):
        return {"error": f"PCAP file not found: {pcap_file}"}
    return None


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable (non-private/non-special) address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        )
    except ValueError:
        return False


def _read_zeek_log(log_path: str) -> list[dict]:
    """
    Read a Zeek TSV log file and return a list of dicts.
    Handles the #fields header format.
    """
    if not os.path.exists(log_path):
        return []

    rows: list[dict] = []
    fields: list[str] = []

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            cols = line.split("\t")
            row = {fields[i]: cols[i] if i < len(cols) else "" for i in range(len(fields))}
            rows.append(row)

    return rows


def _parse_eve_json(eve_path: str, event_types: set | None = None) -> list[dict]:
    """Read Suricata eve.json, optionally filtering by event_type."""
    events: list[dict] = []
    if not os.path.exists(eve_path):
        return events
    with open(eve_path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event_types is None or obj.get("event_type") in event_types:
                events.append(obj)
    return events


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def zeek_analyze(pcap_file: str, output_dir: str = "/tmp/zeek_out") -> dict:
    """
    Run Zeek on a PCAP file and parse the generated logs.

    Parameters
    ----------
    pcap_file  : Absolute path to the .pcap / .pcapng file.
    output_dir : Directory where Zeek writes its logs.
    """
    if not _zeek_available():
        return {
            "error": (
                "zeek not installed. "
                "Install: sudo apt install zeek  "
                "or see https://zeek.org/get-zeek/"
            )
        }
    err = _pcap_exists(pcap_file)
    if err:
        return err

    os.makedirs(output_dir, exist_ok=True)

    # Run Zeek; -C disables checksum validation (common with captured traffic)
    rc, stdout, stderr = _run(
        ["zeek", "-r", pcap_file, "-C"],
        cwd=output_dir,
    )

    # Parse generated log files
    conn_rows = _read_zeek_log(os.path.join(output_dir, "conn.log"))
    http_rows = _read_zeek_log(os.path.join(output_dir, "http.log"))
    dns_rows = _read_zeek_log(os.path.join(output_dir, "dns.log"))
    ssl_rows = _read_zeek_log(os.path.join(output_dir, "ssl.log"))
    files_rows = _read_zeek_log(os.path.join(output_dir, "files.log"))
    notice_rows = _read_zeek_log(os.path.join(output_dir, "notice.log"))
    weird_rows = _read_zeek_log(os.path.join(output_dir, "weird.log"))

    # Protocol breakdown
    protocols: dict[str, int] = {}
    for row in conn_rows:
        proto = row.get("proto", "unknown").upper()
        service = row.get("service", "")
        key = f"{proto}/{service}" if service and service != "-" else proto
        protocols[key] = protocols.get(key, 0) + 1

    # DNS queries
    dns_queries = [
        {
            "query": r.get("query", ""),
            "qtype": r.get("qtype_name", ""),
            "answers": r.get("answers", "").split(","),
            "src": r.get("id.orig_h", ""),
        }
        for r in dns_rows
        if r.get("query") and r.get("query") != "-"
    ]

    # HTTP requests
    http_requests = [
        {
            "host": r.get("host", ""),
            "uri": r.get("uri", ""),
            "method": r.get("method", ""),
            "status": r.get("status_code", ""),
            "user_agent": r.get("user_agent", ""),
            "src": r.get("id.orig_h", ""),
        }
        for r in http_rows
        if r.get("host") and r.get("host") != "-"
    ]

    # Files
    files_summary = [
        {
            "filename": r.get("filename", ""),
            "mime": r.get("mime_type", ""),
            "md5": r.get("md5", ""),
            "sha1": r.get("sha1", ""),
            "sha256": r.get("sha256", ""),
            "size": r.get("total_bytes", ""),
        }
        for r in files_rows
    ]

    # Alerts from notice.log + weird.log
    alerts = [
        {"type": "notice", "note": r.get("note", ""), "msg": r.get("msg", ""), "src": r.get("src", "")}
        for r in notice_rows
    ] + [
        {"type": "weird", "name": r.get("name", ""), "src": r.get("id.orig_h", "")}
        for r in weird_rows
    ]

    return {
        "connections": len(conn_rows),
        "protocols": protocols,
        "dns_queries": dns_queries,
        "http_requests": http_requests,
        "files": files_summary,
        "alerts": alerts,
        "ssl_sessions": len(ssl_rows),
        "output_dir": output_dir,
    }


def suricata_analyze(
    pcap_file: str,
    rules_dir: str = "/etc/suricata/rules",
) -> dict:
    """
    Run Suricata on a PCAP file and parse the resulting eve.json.

    Parameters
    ----------
    pcap_file : Absolute path to the .pcap / .pcapng file.
    rules_dir : Directory containing Suricata rule files (unused directly;
                Suricata reads from its config).
    """
    if not _suricata_available():
        return {
            "error": (
                "suricata not installed. "
                "Install: sudo apt install suricata  "
                "or see https://suricata.io/download/"
            )
        }
    err = _pcap_exists(pcap_file)
    if err:
        return err

    out_dir = "/tmp/suricata_out"
    os.makedirs(out_dir, exist_ok=True)
    eve_path = os.path.join(out_dir, "eve.json")

    cmd = [
        "suricata",
        "-r", pcap_file,
        "-l", out_dir,
        "-c", "/etc/suricata/suricata.yaml",
    ]
    rc, stdout, stderr = _run(cmd)

    return suricata_parse_alerts(eve_path)


def suricata_parse_alerts(eve_log: str, limit: int = 100) -> dict:
    """
    Parse a Suricata eve.json file and return the top N alerts.

    Parameters
    ----------
    eve_log : Absolute path to an eve.json file produced by Suricata.
    limit   : Maximum number of alerts to return (default 100).
    """
    if not os.path.exists(eve_log):
        return {"error": f"eve.json not found: {eve_log}"}

    alert_events = _parse_eve_json(eve_log, event_types={"alert"})

    alerts: list[dict] = []
    sig_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}

    for ev in alert_events:
        alert_data = ev.get("alert", {})
        sig = alert_data.get("signature", "unknown")
        severity = alert_data.get("severity", 3)
        sev_label = {1: "high", 2: "medium", 3: "low"}.get(severity, "info")

        sig_counts[sig] = sig_counts.get(sig, 0) + 1
        severity_counts[sev_label] = severity_counts.get(sev_label, 0) + 1

        alerts.append(
            {
                "timestamp": ev.get("timestamp", ""),
                "src_ip": ev.get("src_ip", ""),
                "src_port": ev.get("src_port", ""),
                "dest_ip": ev.get("dest_ip", ""),
                "dest_port": ev.get("dest_port", ""),
                "proto": ev.get("proto", ""),
                "signature": sig,
                "category": alert_data.get("category", ""),
                "severity": severity,
                "action": alert_data.get("action", ""),
            }
        )

    # Sort by severity (ascending = highest first) then truncate
    alerts.sort(key=lambda a: a["severity"])
    top_alerts = alerts[:limit]

    # Top signatures by frequency
    top_sigs = sorted(sig_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "alerts": top_alerts,
        "total_alerts": len(alert_events),
        "by_severity": severity_counts,
        "top_sigs": [{"signature": s, "count": c} for s, c in top_sigs],
    }


def zeek_extract_iocs(pcap_file: str) -> dict:
    """
    Analyze a PCAP with Zeek and extract Indicators of Compromise (IOCs).

    Extracted IOCs:
    - External IP addresses (non-RFC1918)
    - Domain names from DNS queries
    - HTTP URLs
    - File hashes (MD5 / SHA256) from files.log

    Parameters
    ----------
    pcap_file : Absolute path to the .pcap / .pcapng file.
    """
    if not _zeek_available():
        return {
            "error": (
                "zeek not installed. "
                "Install: sudo apt install zeek  "
                "or see https://zeek.org/get-zeek/"
            )
        }
    err = _pcap_exists(pcap_file)
    if err:
        return err

    # Use a dedicated temp dir so logs don't collide
    tmp_dir = tempfile.mkdtemp(prefix="argos_zeek_ioc_")
    try:
        analysis = zeek_analyze(pcap_file, output_dir=tmp_dir)
    except Exception as exc:
        return {"error": f"Zeek analysis failed: {exc}"}

    # --- IPs ---
    external_ips: set[str] = set()
    conn_rows = _read_zeek_log(os.path.join(tmp_dir, "conn.log"))
    for row in conn_rows:
        for field in ("id.orig_h", "id.resp_h"):
            ip = row.get(field, "")
            if ip and ip != "-" and _is_public_ip(ip):
                external_ips.add(ip)

    # --- Domains ---
    domains: set[str] = set()
    for q in analysis.get("dns_queries", []):
        qname = q.get("query", "").strip()
        if qname and qname != "-":
            domains.add(qname)
    ssl_rows = _read_zeek_log(os.path.join(tmp_dir, "ssl.log"))
    for row in ssl_rows:
        sni = row.get("server_name", "").strip()
        if sni and sni != "-":
            domains.add(sni)

    # --- URLs ---
    urls: list[str] = []
    for req in analysis.get("http_requests", []):
        host = req.get("host", "").strip()
        uri = req.get("uri", "").strip()
        if host and host != "-":
            url = f"http://{host}{uri}" if uri and uri != "-" else f"http://{host}"
            urls.append(url)
    urls = list(dict.fromkeys(urls))  # deduplicate, preserve order

    # --- File hashes ---
    file_hashes: list[dict] = []
    for f in analysis.get("files", []):
        entry: dict = {}
        if f.get("md5") and f["md5"] != "-":
            entry["md5"] = f["md5"]
        if f.get("sha256") and f["sha256"] != "-":
            entry["sha256"] = f["sha256"]
        if f.get("filename") and f["filename"] != "-":
            entry["filename"] = f["filename"]
        if f.get("mime") and f["mime"] != "-":
            entry["mime"] = f["mime"]
        if entry:
            file_hashes.append(entry)

    return {
        "ips": sorted(external_ips),
        "domains": sorted(domains),
        "urls": urls,
        "file_hashes": file_hashes,
    }


# ---------------------------------------------------------------------------
# ARGOS TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "zeek_analyze": {
        "fn": zeek_analyze,
        "description": (
            "Run Zeek on a PCAP file and return parsed connection, DNS, HTTP, "
            "SSL, file, and alert data from the generated logs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pcap_file": {
                    "type": "string",
                    "description": "Absolute path to the PCAP/PCAPNG file to analyze.",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory where Zeek will write its log files.",
                    "default": "/tmp/zeek_out",
                },
            },
            "required": ["pcap_file"],
        },
    },
    "suricata_analyze": {
        "fn": suricata_analyze,
        "description": (
            "Run Suricata IDS on a PCAP file and return categorized alerts, "
            "severity breakdown, and top triggered signatures."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pcap_file": {
                    "type": "string",
                    "description": "Absolute path to the PCAP/PCAPNG file to analyze.",
                },
                "rules_dir": {
                    "type": "string",
                    "description": "Suricata rules directory (Suricata reads from its YAML config).",
                    "default": "/etc/suricata/rules",
                },
            },
            "required": ["pcap_file"],
        },
    },
    "suricata_parse_alerts": {
        "fn": suricata_parse_alerts,
        "description": (
            "Parse an existing Suricata eve.json log file and return the top N alerts "
            "with IP, port, signature, category, and severity fields."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "eve_log": {
                    "type": "string",
                    "description": "Absolute path to a Suricata eve.json file.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of alerts to return.",
                    "default": 100,
                },
            },
            "required": ["eve_log"],
        },
    },
    "zeek_extract_iocs": {
        "fn": zeek_extract_iocs,
        "description": (
            "Analyze a PCAP with Zeek and automatically extract IOCs: "
            "external IP addresses, domain names, HTTP URLs, and file hashes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pcap_file": {
                    "type": "string",
                    "description": "Absolute path to the PCAP/PCAPNG file.",
                },
            },
            "required": ["pcap_file"],
        },
    },
}
