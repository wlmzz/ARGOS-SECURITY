"""
ARGOS Plugin: ThreatFox + URLHaus (abuse.ch)
Two free no-key APIs from abuse.ch:
  - ThreatFox: IOC database (IPs, domains, hashes, malware families)
  - URLHaus: malware distribution URL database (300K+ malicious URLs)
No API key required for read operations.
"""
from __future__ import annotations
import json, re, urllib.request, urllib.error

MANIFEST = {
    "id":          "threatfox_urlhaus",
    "name":        "ThreatFox + URLHaus",
    "description": "Free abuse.ch threat intelligence: IOC lookup (ThreatFox) and malware URL database (URLHaus). No API key needed.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/"


def _post(base_url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        base_url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ARGOS/1.0"},
        method="POST",
    )
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


# ─── ThreatFox ────────────────────────────────────────────────────────────────

def threatfox_ioc(search_term: str) -> dict:
    """Search ThreatFox IOC database for an IP, domain, hash, or URL.
    Returns malware family, confidence, threat type, and first/last seen."""
    data = _post(_THREATFOX_URL, {"query": "search_ioc", "search_term": search_term.strip()})
    if "error" in data:
        return data

    status = data.get("query_status", "")
    if status in ("no_result", "ok") and not data.get("data"):
        return {
            "ioc":     search_term,
            "source":  "ThreatFox",
            "found":   False,
            "verdict": "NOT_FOUND",
        }

    iocs = data.get("data", []) or []
    return {
        "ioc":     search_term,
        "source":  "ThreatFox",
        "found":   bool(iocs),
        "verdict": "MALICIOUS" if iocs else "CLEAN",
        "count":   len(iocs),
        "results": [
            {
                "ioc_value":      i.get("ioc_value", ""),
                "ioc_type":       i.get("ioc_type", ""),
                "threat_type":    i.get("threat_type", ""),
                "malware":        i.get("malware_printable", ""),
                "malware_malpedia": i.get("malware_malpedia", ""),
                "confidence":     i.get("confidence_level", 0),
                "first_seen":     i.get("first_seen", ""),
                "last_seen":      i.get("last_seen", ""),
                "tags":           i.get("tags", []),
            }
            for i in iocs[:10]
        ],
    }


def threatfox_hash(file_hash: str) -> dict:
    """Search ThreatFox for a file hash (MD5/SHA256). Returns malware family and samples."""
    h = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", h):
        return {"error": "Invalid hash (MD5=32 or SHA256=64 hex chars)"}
    data = _post(_THREATFOX_URL, {"query": "search_hash", "hash": h})
    if "error" in data:
        return data
    iocs = data.get("data", []) or []
    return {
        "hash":    h,
        "source":  "ThreatFox",
        "found":   bool(iocs),
        "verdict": "MALICIOUS" if iocs else "CLEAN",
        "results": [
            {
                "malware":     i.get("malware_printable", ""),
                "threat_type": i.get("threat_type", ""),
                "confidence":  i.get("confidence_level", 0),
                "first_seen":  i.get("first_seen", ""),
            }
            for i in iocs[:10]
        ],
    }


# ─── URLHaus ──────────────────────────────────────────────────────────────────

def urlhaus_lookup_url(url: str) -> dict:
    """Check if a URL is in the URLHaus malware distribution database (300K+ known malicious URLs)."""
    data = _post(_URLHAUS_URL + "url/", {"url": url})
    if "error" in data:
        return data

    if data.get("query_status") == "no_results":
        return {
            "url":     url,
            "source":  "URLHaus",
            "found":   False,
            "verdict": "NOT_FOUND",
        }

    return {
        "url":          url,
        "source":       "URLHaus",
        "found":        True,
        "verdict":      "MALICIOUS",
        "urlhaus_id":   data.get("id", ""),
        "urlhaus_ref":  data.get("urlhaus_reference", ""),
        "url_status":   data.get("url_status", ""),
        "date_added":   data.get("date_added", ""),
        "threat":       data.get("threat", ""),
        "tags":         data.get("tags", []),
        "payloads":     [
            {
                "filename":       p.get("filename", ""),
                "file_type":      p.get("file_type", ""),
                "md5":            p.get("response_md5", ""),
                "sha256":         p.get("response_sha256", ""),
                "virus_total":    p.get("virustotal", {}).get("result", "") if p.get("virustotal") else "",
            }
            for p in (data.get("payloads") or [])[:5]
        ],
        "host":         data.get("host", ""),
    }


def urlhaus_lookup_host(host: str) -> dict:
    """Check a hostname or IP in URLHaus — shows all known malicious URLs hosted there."""
    data = _post(_URLHAUS_URL + "host/", {"host": host})
    if "error" in data:
        return data

    if data.get("query_status") == "no_results":
        return {
            "host":    host,
            "source":  "URLHaus",
            "found":   False,
            "verdict": "NOT_FOUND",
        }

    urls = data.get("urls", []) or []
    return {
        "host":         host,
        "source":       "URLHaus",
        "found":        True,
        "verdict":      "MALICIOUS",
        "blacklists":   data.get("blacklists", {}),
        "url_count":    data.get("url_count", 0),
        "active_urls":  sum(1 for u in urls if u.get("url_status") == "online"),
        "urls":         [
            {
                "url":        u.get("url", ""),
                "status":     u.get("url_status", ""),
                "threat":     u.get("threat", ""),
                "date_added": u.get("date_added", ""),
            }
            for u in urls[:10]
        ],
    }


TOOLS = {
    "threatfox_ioc": {
        "fn": threatfox_ioc,
        "description": (
            "Search ThreatFox (abuse.ch) IOC database for an IP, domain, URL, or hash. "
            "Returns malware family, threat type, confidence level (0-100), first/last seen. "
            "Free, no API key required."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "search_term": {"type": "string", "description": "IP, domain, URL, or hash to look up"}
            },
            "required": ["search_term"]
        }
    },
    "threatfox_hash": {
        "fn": threatfox_hash,
        "description": "Search ThreatFox for a file hash (MD5 or SHA256). Returns malware family and threat type.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "MD5 (32 chars) or SHA256 (64 chars) hash"}
            },
            "required": ["file_hash"]
        }
    },
    "urlhaus_lookup_url": {
        "fn": urlhaus_lookup_url,
        "description": (
            "Check a URL against URLHaus malware distribution database (300K+ known malicious URLs). "
            "Returns threat type, payload hashes, file types, and VirusTotal results. Free, no key."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to check (e.g. 'http://evil.com/payload.exe')"}
            },
            "required": ["url"]
        }
    },
    "urlhaus_lookup_host": {
        "fn": urlhaus_lookup_host,
        "description": "Check a hostname or IP in URLHaus — shows all malicious URLs hosted there and blacklist status.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP address"}
            },
            "required": ["host"]
        }
    },
}
