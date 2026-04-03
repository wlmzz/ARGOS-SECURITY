"""
ARGOS Plugin: VirusTotal
Lookup file hashes, URLs, IPs, and domains on VirusTotal.
Requires: VIRUSTOTAL_API_KEY env var (free tier: 4 requests/min, 500/day)
Get key at: virustotal.com/gui/join-us
"""
from __future__ import annotations
import json, os, re, urllib.request

MANIFEST = {
    "id":          "virustotal",
    "name":        "VirusTotal",
    "description": "Scan hashes, URLs, IPs, and domains against 70+ antivirus engines via VirusTotal API.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

VT_API = "https://www.virustotal.com/api/v3"


def _vt_get(endpoint: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY env var not set. Get free key at virustotal.com/gui/join-us"}
    req = urllib.request.Request(
        f"{VT_API}{endpoint}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def vt_hash_scan(file_hash: str) -> dict:
    """Scan a file hash (MD5/SHA1/SHA256) against 70+ AV engines on VirusTotal."""
    h = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", h):
        return {"error": "Invalid hash format. Provide MD5 (32), SHA1 (40), or SHA256 (64) hex."}
    data = _vt_get(f"/files/{h}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "hash":           h,
        "source":         "VirusTotal",
        "malicious":      stats.get("malicious", 0),
        "suspicious":     stats.get("suspicious", 0),
        "undetected":     stats.get("undetected", 0),
        "total_engines":  sum(stats.values()),
        "verdict":        "MALICIOUS" if stats.get("malicious", 0) > 2 else "CLEAN",
        "file_type":      attrs.get("type_description", ""),
        "file_name":      attrs.get("meaningful_name", ""),
        "first_seen":     attrs.get("first_submission_date", ""),
        "tags":           attrs.get("tags", [])[:10],
        "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }


def vt_url_scan(url: str) -> dict:
    """Scan a URL against VirusTotal's 70+ engines and URL databases."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _vt_get(f"/urls/{url_id}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "url":           url,
        "source":        "VirusTotal",
        "malicious":     stats.get("malicious", 0),
        "suspicious":    stats.get("suspicious", 0),
        "undetected":    stats.get("undetected", 0),
        "total_engines": sum(stats.values()),
        "verdict":       "MALICIOUS" if stats.get("malicious", 0) > 2 else "CLEAN",
        "categories":    attrs.get("categories", {}),
        "final_url":     attrs.get("last_final_url", url),
    }


def vt_ip_scan(ip: str) -> dict:
    """Get VirusTotal report for an IP: detection count, country, ASN, last analysis."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    data = _vt_get(f"/ip_addresses/{ip}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip":            ip,
        "source":        "VirusTotal",
        "malicious":     stats.get("malicious", 0),
        "suspicious":    stats.get("suspicious", 0),
        "total_engines": sum(stats.values()),
        "verdict":       "MALICIOUS" if stats.get("malicious", 0) > 2 else "CLEAN",
        "country":       attrs.get("country", ""),
        "asn":           attrs.get("asn", ""),
        "as_owner":      attrs.get("as_owner", ""),
        "network":       attrs.get("network", ""),
        "reputation":    attrs.get("reputation", 0),
        "tags":          attrs.get("tags", []),
    }


TOOLS = {
    "vt_hash_scan": {
        "fn": vt_hash_scan,
        "description": "Scan a file hash (MD5/SHA1/SHA256) against 70+ AV engines on VirusTotal. Returns malicious/clean verdict and threat name.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "File hash to scan: MD5 (32 chars), SHA1 (40), or SHA256 (64)"}
            },
            "required": ["file_hash"]
        }
    },
    "vt_url_scan": {
        "fn": vt_url_scan,
        "description": "Scan a URL against VirusTotal's phishing, malware, and reputation databases.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to scan (e.g. 'https://suspicious-site.com/payload')"}
            },
            "required": ["url"]
        }
    },
    "vt_ip_scan": {
        "fn": vt_ip_scan,
        "description": "Get VirusTotal reputation report for an IP: detection count, ASN, country, tags.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up on VirusTotal"}
            },
            "required": ["ip"]
        }
    },
}
