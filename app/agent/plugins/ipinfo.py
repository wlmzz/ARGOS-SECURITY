"""
ARGOS Plugin: IPInfo
Detailed IP intelligence: ASN, organization, abuse contact, privacy/VPN/proxy/TOR detection.
Free tier: 50,000 requests/month with IPINFO_TOKEN.
Anonymous (no token): 1,000/day with limited data.
Get token at: ipinfo.io/signup
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.error

MANIFEST = {
    "id":          "ipinfo",
    "name":        "IPInfo",
    "description": "Detailed IP intelligence: ASN, org, country, city, abuse contact, VPN/TOR/proxy detection. 50K req/month free.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://ipinfo.io"


def _ipinfo_get(path: str) -> dict:
    token = os.getenv("IPINFO_TOKEN", "")
    url = f"{_BASE}{path}"
    if token:
        url += f"?token={token}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ARGOS/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def ipinfo_lookup(ip: str) -> dict:
    """Get detailed intelligence for an IP: geolocation, ISP, ASN, organization, abuse contact.
    With IPINFO_TOKEN also returns privacy flags (VPN, proxy, TOR, relay, hosting)."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    data = _ipinfo_get(f"/{ip}")
    if "error" in data:
        return data

    # Parse org field — format: "AS12345 Some ISP Name"
    org = data.get("org", "")
    asn, as_name = "", org
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        asn = parts[0]
        as_name = parts[1] if len(parts) > 1 else ""

    # Parse loc — format: "lat,lon"
    loc = data.get("loc", "")
    lat, lon = "", ""
    if "," in loc:
        lat, lon = loc.split(",", 1)

    result = {
        "ip":        ip,
        "source":    "IPInfo",
        "hostname":  data.get("hostname", ""),
        "city":      data.get("city", ""),
        "region":    data.get("region", ""),
        "country":   data.get("country", ""),
        "postal":    data.get("postal", ""),
        "timezone":  data.get("timezone", ""),
        "latitude":  lat,
        "longitude": lon,
        "asn":       asn,
        "org":       as_name,
        "company":   data.get("company", {}).get("name", "") if isinstance(data.get("company"), dict) else "",
    }

    # Abuse contact (available with token)
    abuse = data.get("abuse", {})
    if isinstance(abuse, dict):
        result["abuse_email"]   = abuse.get("email", "")
        result["abuse_phone"]   = abuse.get("phone", "")
        result["abuse_name"]    = abuse.get("name", "")
        result["abuse_country"] = abuse.get("country", "")

    # Privacy flags (paid tier or token)
    privacy = data.get("privacy", {})
    if isinstance(privacy, dict):
        result["is_vpn"]     = privacy.get("vpn", False)
        result["is_proxy"]   = privacy.get("proxy", False)
        result["is_tor"]     = privacy.get("tor", False)
        result["is_relay"]   = privacy.get("relay", False)
        result["is_hosting"] = privacy.get("hosting", False)
        flags = [k for k, v in {
            "VPN": result.get("is_vpn"), "PROXY": result.get("is_proxy"),
            "TOR": result.get("is_tor"), "RELAY": result.get("is_relay"),
            "HOSTING": result.get("is_hosting"),
        }.items() if v]
        result["privacy_flags"] = flags
        result["verdict"] = f"ANONYMIZED via {'+'.join(flags)}" if flags else "DIRECT — no anonymization detected"

    return result


def ipinfo_batch(ips: list[str]) -> dict:
    """Batch lookup for up to 1000 IPs at once. Returns dict of ip → info."""
    if not ips:
        return {"error": "No IPs provided"}
    if len(ips) > 1000:
        return {"error": "Maximum 1000 IPs per batch"}

    token = os.getenv("IPINFO_TOKEN", "")
    if not token:
        return {"error": "IPINFO_TOKEN required for batch lookups. Get free token at ipinfo.io/signup"}

    data = json.dumps(ips).encode()
    url = f"{_BASE}/batch?token={token}"
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ARGOS/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            results = json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}

    return {
        "source":  "IPInfo",
        "count":   len(results),
        "results": {
            ip: {
                "country": info.get("country", ""),
                "city":    info.get("city", ""),
                "org":     info.get("org", ""),
                "hostname": info.get("hostname", ""),
            }
            for ip, info in results.items()
            if isinstance(info, dict)
        },
    }


TOOLS = {
    "ipinfo_lookup": {
        "fn": ipinfo_lookup,
        "description": (
            "Get detailed intelligence for an IP: geolocation (city/country), ISP, ASN, "
            "organization, abuse contact email/phone, and privacy flags (VPN/proxy/TOR/hosting). "
            "No key needed for basic data; set IPINFO_TOKEN for 50K/month free with full data."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    "ipinfo_batch": {
        "fn": ipinfo_batch,
        "description": (
            "Batch lookup for up to 1000 IP addresses at once with IPInfo. "
            "Returns country, city, org, hostname for each IP. "
            "Requires IPINFO_TOKEN (free at ipinfo.io/signup)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IP addresses (max 1000)"
                }
            },
            "required": ["ips"]
        }
    },
}
