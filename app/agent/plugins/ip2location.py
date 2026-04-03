"""
ARGOS Plugin: IP2Location
Detailed IP geolocation with ISP, domain, usage type (residential/commercial/datacenter),
threat data (proxy/VPN/TOR/spammer), mobile carrier info.

Two modes:
1. ip2location.io REST API (recommended): get free API key at ip2location.io/sign-up
   Set IP2LOCATION_API_KEY env var (free: 30K queries/month)
2. ip2location.io without key: 500 queries/day anonymous

Repo: https://github.com/ip2location-com/ip2location-python (for local DB mode)
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.error, urllib.parse

MANIFEST = {
    "id":          "ip2location",
    "name":        "IP2Location",
    "description": "Detailed IP geolocation: ISP, domain, usage type (datacenter/residential/VPN), proxy/TOR/spammer detection.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_API_URL = "https://api.ip2location.io/"


def ip2location_lookup(ip: str) -> dict:
    """Get detailed geolocation and threat data for an IP address.
    Returns: country, city, ISP, domain, usage type (residential/commercial/datacenter/VPN/CDN),
    proxy type, threat level, and mobile carrier info.
    Free tier (no key): 500/day. With IP2LOCATION_API_KEY: 30K/month."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    api_key = os.getenv("IP2LOCATION_API_KEY", "")
    params = {"ip": ip, "format": "json"}
    if api_key:
        params["key"] = api_key

    url = _API_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "ARGOS/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"error": str(e)}

    if data.get("response") == "INVALID API KEY":
        return {"error": "Invalid IP2LOCATION_API_KEY. Get free key at ip2location.io/sign-up"}

    # Classify usage type
    usage = data.get("usage_type", "")
    usage_label = {
        "COM": "Commercial", "ORG": "Organization", "GOV": "Government",
        "MIL": "Military",   "EDU": "Education",    "LIB": "Library",
        "CDN": "CDN",        "ISP": "ISP",          "MOB": "Mobile ISP",
        "DCH": "Datacenter/Hosting", "SES": "Search Engine Spider",
        "RSV": "Reserved",   "VPN": "VPN",          "TOR": "TOR exit node",
        "PUB": "Public proxy",
    }.get(usage, usage)

    # Proxy type
    proxy_type = data.get("proxy", {}).get("proxy_type", "") if isinstance(data.get("proxy"), dict) else ""

    # Determine threat level
    proxy_data = data.get("proxy", {}) or {}
    is_proxy    = proxy_data.get("is_proxy", 0) == 1
    is_vpn      = proxy_data.get("is_vpn", 0) == 1
    is_tor      = proxy_data.get("is_tor", 0) == 1
    is_datacenter = proxy_data.get("is_datacenter", 0) == 1
    is_spam     = proxy_data.get("is_public_proxy", 0) == 1

    flags = [k for k, v in {
        "PROXY": is_proxy, "VPN": is_vpn, "TOR": is_tor,
        "DATACENTER": is_datacenter, "SPAM/PUBLIC_PROXY": is_spam,
    }.items() if v]

    return {
        "ip":           ip,
        "source":       "IP2Location",
        "country_code": data.get("country_code", ""),
        "country":      data.get("country_name", ""),
        "region":       data.get("region_name", ""),
        "city":         data.get("city_name", ""),
        "latitude":     data.get("latitude", ""),
        "longitude":    data.get("longitude", ""),
        "zip_code":     data.get("zip_code", ""),
        "time_zone":    data.get("time_zone", ""),
        "isp":          data.get("isp", ""),
        "domain":       data.get("domain", ""),
        "net_speed":    data.get("net_speed", ""),
        "idd_code":     data.get("idd_code", ""),
        "area_code":    data.get("area_code", ""),
        "usage_type":   usage_label,
        "asn":          data.get("asn", ""),
        "as_name":      data.get("as", ""),
        # Threat data (requires key)
        "is_proxy":     is_proxy,
        "is_vpn":       is_vpn,
        "is_tor":       is_tor,
        "is_datacenter": is_datacenter,
        "proxy_type":   proxy_type,
        "threat_flags": flags,
        "verdict":      f"ANONYMIZED: {'+'.join(flags)}" if flags else f"DIRECT — {usage_label}",
        # Mobile info
        "mobile_brand": data.get("mobile_brand", ""),
        "mobile_mcc":   data.get("mobile_mcc", ""),
        "mobile_mnc":   data.get("mobile_mnc", ""),
        "ads_category": data.get("ads_category", ""),
    }


TOOLS = {
    "ip2location_lookup": {
        "fn": ip2location_lookup,
        "description": (
            "Get detailed IP intelligence from IP2Location: country/city, ISP, domain name, "
            "usage type (residential/commercial/datacenter/CDN/VPN), proxy/TOR/spam detection, "
            "mobile carrier details. Free tier: 500 queries/day. "
            "Set IP2LOCATION_API_KEY for 30K/month (free at ip2location.io/sign-up)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
}
