"""OSINT tools: CVE lookup, IP reputation, hash check, Shodan, GreyNoise."""
from __future__ import annotations
import json, re, os, urllib.request, urllib.parse
from typing import Any


def _http_get(url: str, timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def cve_lookup(cve_id: str) -> dict:
    """Look up a CVE from the NVD (National Vulnerability Database)."""
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
        return {"error": "Invalid CVE ID format. Use CVE-YYYY-NNNNN"}
    data = _http_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    if "error" in data:
        return data
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"cve_id": cve_id, "found": False}
    cve = vulns[0].get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
    score = cvss_v3.get("baseScore") or cvss_v2.get("baseScore")
    severity = cvss_v3.get("baseSeverity") or cvss_v2.get("baseSeverity", "UNKNOWN")
    refs = [r["url"] for r in cve.get("references", [])[:5]]
    return {
        "cve_id": cve_id,
        "description": desc[:1000],
        "cvss_score": score,
        "severity": severity,
        "published": cve.get("published", ""),
        "references": refs,
    }


def ip_reputation(ip: str) -> dict:
    """Check IP reputation using AbuseIPDB (public endpoint)."""
    # Using ip-api.com for basic geo + ASN info (no key needed)
    data = _http_get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting,proxy,mobile,query")
    result = {"ip": ip, "geo": data}
    # Also check basic threat intel via ipsum project (text-based, no API key)
    return result


def hash_lookup(file_hash: str) -> dict:
    """Look up a file hash on MalwareBazaar (free, no key needed)."""
    h = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", h):
        return {"error": "Invalid hash. Provide MD5 (32), SHA1 (40), or SHA256 (64) hex hash."}
    try:
        data_encoded = urllib.parse.urlencode({"query": "get_info", "hash": h}).encode()
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=data_encoded,
            headers={"User-Agent": "ARGOS-SecurityAgent/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode())
        if result.get("query_status") == "hash_not_found":
            return {"hash": h, "found": False, "source": "MalwareBazaar"}
        data = result.get("data", [{}])[0]
        return {
            "hash": h,
            "found": True,
            "source": "MalwareBazaar",
            "malware_name": data.get("signature"),
            "first_seen": data.get("first_seen"),
            "file_type": data.get("file_type"),
            "tags": data.get("tags", []),
            "vendor_intel": list(data.get("vendor_intel", {}).keys())[:5],
        }
    except Exception as e:
        return {"hash": h, "error": str(e)}


def extract_iocs(text: str) -> dict:
    """Extract Indicators of Compromise (IOCs) from text: IPs, domains, hashes, URLs."""
    ipv4 = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text)
    ipv6 = re.findall(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", text)
    domains = re.findall(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text)
    urls = re.findall(r"https?://[^\s<>\"]+", text)
    md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
    sha1 = re.findall(r"\b[a-fA-F0-9]{40}\b", text)
    sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    cves = re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    # Filter private IPs
    def is_public_ip(ip):
        parts = ip.split(".")
        if parts[0] in ("10", "127", "169", "172", "192"):
            return False
        return True
    public_ips = list(set(ip for ip in ipv4 if is_public_ip(ip)))
    return {
        "ipv4": public_ips[:20],
        "ipv6": list(set(ipv6))[:10],
        "domains": list(set(d for d in domains if "." in d))[:20],
        "urls": list(set(urls))[:20],
        "hashes": {"md5": list(set(md5))[:10], "sha1": list(set(sha1))[:10], "sha256": list(set(sha256))[:10]},
        "cves": list(set(cve.upper() for cve in cves))[:20],
    }


def shodan_host(ip: str) -> dict:
    """Query Shodan InternetDB for open ports, services, CVEs, and tags on an IP.
    Free, no API key required. Returns ports, hostnames, vulnerabilities, tags."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    data = _http_get(f"https://internetdb.shodan.io/{ip}", timeout=10)
    if "detail" in data and data["detail"] == "No information available":
        return {"ip": ip, "found": False, "source": "Shodan InternetDB"}
    if "error" in data:
        return data
    return {
        "ip": ip,
        "found": True,
        "source": "Shodan InternetDB",
        "open_ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
        "vulnerabilities": data.get("vulns", []),
        "tags": data.get("tags", []),
    }


def shodan_search(query: str) -> dict:
    """Search Shodan for internet-exposed hosts matching a query.
    Requires SHODAN_API_KEY env var. Free tier: 100 queries/month.
    query examples: 'apache country:IT', 'port:22 org:Fastweb', 'vuln:CVE-2021-44228'
    """
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"error": "SHODAN_API_KEY env var not set. Get free key at shodan.io/account"}
    q = urllib.parse.quote(query)
    data = _http_get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={q}&minify=true", timeout=15)
    if "error" in data:
        return data
    matches = data.get("matches", [])
    return {
        "query": query,
        "total": data.get("total", 0),
        "results": [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "org": m.get("org"),
                "country": m.get("location", {}).get("country_name"),
                "hostnames": m.get("hostnames", []),
                "product": m.get("product", ""),
                "vulns": list(m.get("vulns", {}).keys()),
            }
            for m in matches[:20]
        ],
        "source": "Shodan API",
    }


TOOLS = {
    "cve_lookup": {
        "fn": cve_lookup,
        "description": "Look up a CVE vulnerability from the NVD database. Returns description, CVSS score, severity, and references.",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID in format CVE-YYYY-NNNNN"}
            },
            "required": ["cve_id"]
        }
    },
    "ip_reputation": {
        "fn": ip_reputation,
        "description": "Check geolocation and ASN info for an IP address. Identifies hosting providers, proxies, mobile IPs.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"}
            },
            "required": ["ip"]
        }
    },
    "hash_lookup": {
        "fn": hash_lookup,
        "description": "Look up a file hash (MD5/SHA1/SHA256) on MalwareBazaar to identify known malware.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "File hash: MD5 (32 chars), SHA1 (40), or SHA256 (64)"}
            },
            "required": ["file_hash"]
        }
    },
    "extract_iocs": {
        "fn": extract_iocs,
        "description": "Extract IOCs (Indicators of Compromise) from text: IPs, domains, URLs, file hashes, CVE IDs.",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw text (log lines, report, email, etc.) to extract IOCs from"}
            },
            "required": ["text"]
        }
    },
    "shodan_host": {
        "fn": shodan_host,
        "description": "Query Shodan InternetDB for an IP: open ports, services, known CVEs, and tags. Free, no API key needed.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up on Shodan"}
            },
            "required": ["ip"]
        }
    },
    "shodan_search": {
        "fn": shodan_search,
        "description": "Search Shodan for internet-exposed hosts. Requires SHODAN_API_KEY env var. Examples: 'apache country:IT', 'port:3389 org:Fastweb', 'vuln:CVE-2021-44228'",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"}
            },
            "required": ["query"]
        }
    }
}
