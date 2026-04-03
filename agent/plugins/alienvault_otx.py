"""
ARGOS Plugin: AlienVault OTX (Open Threat Exchange)
World's largest open threat intelligence community — 20M+ threat indicators.
Free API key at: otx.alienvault.com (just register)
Set OTX_API_KEY env var after registration.
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.parse

MANIFEST = {
    "id":          "alienvault_otx",
    "name":        "AlienVault OTX",
    "description": "Query 20M+ threat indicators (IPs, domains, hashes, URLs) from AlienVault OTX community.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://otx.alienvault.com/api/v1/indicators"


def _otx_get(path: str) -> dict:
    api_key = os.getenv("OTX_API_KEY", "")
    headers = {"Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    req = urllib.request.Request(f"{_BASE}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_pulses(data: dict) -> list[dict]:
    pulses = data.get("pulse_info", {}).get("pulses", [])
    return [
        {
            "name":        p.get("name", ""),
            "author":      p.get("author_name", ""),
            "tags":        p.get("tags", [])[:5],
            "tlp":         p.get("tlp", ""),
            "created":     p.get("created", ""),
            "description": p.get("description", "")[:200],
        }
        for p in pulses[:10]
    ]


def otx_ip(ip: str) -> dict:
    """Look up an IP address in AlienVault OTX threat intelligence. Returns pulse count, country, ASN, threat tags."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    data = _otx_get(f"/IPv4/{ip}/general")
    if "error" in data:
        return data
    rep = data.get("reputation", 0)
    pulses = _parse_pulses(data)
    geo = data.get("city", "")
    return {
        "ip":           ip,
        "source":       "AlienVault OTX",
        "pulse_count":  data.get("pulse_info", {}).get("count", 0),
        "reputation":   rep,
        "country":      data.get("country_name", ""),
        "city":         geo,
        "asn":          data.get("asn", ""),
        "verdict":      "MALICIOUS" if pulses else "CLEAN",
        "pulses":       pulses,
        "malware_families": list({t for p in pulses for t in p.get("tags", [])})[:10],
    }


def otx_domain(domain: str) -> dict:
    """Look up a domain in AlienVault OTX. Returns associated threat pulses, malware families, geo."""
    domain = domain.strip().lower()
    data = _otx_get(f"/domain/{domain}/general")
    if "error" in data:
        return data
    pulses = _parse_pulses(data)
    return {
        "domain":       domain,
        "source":       "AlienVault OTX",
        "pulse_count":  data.get("pulse_info", {}).get("count", 0),
        "verdict":      "MALICIOUS" if pulses else "CLEAN",
        "alexa":        data.get("alexa", ""),
        "pulses":       pulses,
        "malware_families": list({t for p in pulses for t in p.get("tags", [])})[:10],
    }


def otx_hash(file_hash: str) -> dict:
    """Look up a file hash (MD5/SHA1/SHA256) in AlienVault OTX malware database."""
    h = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", h):
        return {"error": "Invalid hash format (MD5=32, SHA1=40, SHA256=64 hex)"}
    data = _otx_get(f"/file/{h}/general")
    if "error" in data:
        return data
    pulses = _parse_pulses(data)
    analysis = data.get("analysis", {})
    return {
        "hash":         h,
        "source":       "AlienVault OTX",
        "pulse_count":  data.get("pulse_info", {}).get("count", 0),
        "verdict":      "MALICIOUS" if pulses else "CLEAN",
        "file_type":    analysis.get("info", {}).get("results", {}).get("file_type", ""),
        "file_size":    analysis.get("info", {}).get("results", {}).get("filesize", ""),
        "pulses":       pulses,
        "malware_families": list({t for p in pulses for t in p.get("tags", [])})[:10],
    }


def otx_url(url: str) -> dict:
    """Check a URL's reputation in AlienVault OTX phishing/malware databases."""
    encoded = urllib.parse.quote(url, safe="")
    data = _otx_get(f"/url/{encoded}/general")
    if "error" in data:
        return data
    pulses = _parse_pulses(data)
    return {
        "url":          url,
        "source":       "AlienVault OTX",
        "pulse_count":  data.get("pulse_info", {}).get("count", 0),
        "verdict":      "MALICIOUS" if pulses else "CLEAN",
        "domain":       data.get("domain", ""),
        "pulses":       pulses,
    }


TOOLS = {
    "otx_ip": {
        "fn": otx_ip,
        "description": "Query AlienVault OTX for IP threat intelligence: pulse count, country, ASN, associated malware campaigns.",
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IP address to look up"}},
            "required": ["ip"]
        }
    },
    "otx_domain": {
        "fn": otx_domain,
        "description": "Query AlienVault OTX for domain threat intelligence: associated pulses, malware families, Alexa rank.",
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain name to look up"}},
            "required": ["domain"]
        }
    },
    "otx_hash": {
        "fn": otx_hash,
        "description": "Query AlienVault OTX for file hash (MD5/SHA1/SHA256) — malware families, threat campaigns.",
        "parameters": {
            "type": "object",
            "properties": {"file_hash": {"type": "string", "description": "MD5, SHA1, or SHA256 hash"}},
            "required": ["file_hash"]
        }
    },
    "otx_url": {
        "fn": otx_url,
        "description": "Check a URL against AlienVault OTX phishing and malware URL databases.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Full URL to check"}},
            "required": ["url"]
        }
    },
}
