"""
ARGOS Plugin: GreyNoise
Classify IPs as internet background noise, benign scanners, or targeted threats.
Community API is free (no key needed). Full context requires GREYNOISE_API_KEY.
Get key at: greynoise.io (free community plan available)
"""
from __future__ import annotations
import json, os, urllib.request, re

MANIFEST = {
    "id":          "greynoise",
    "name":        "GreyNoise",
    "description": "Classify IPs as internet background noise vs targeted threats. Free community API included.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_CONTEXT_URL   = "https://api.greynoise.io/v2/noise/context/{ip}"
_RIOT_URL      = "https://api.greynoise.io/v2/riot/{ip}"


def _gn_get(url: str, api_key: str = "") -> dict:
    headers = {"Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    if api_key:
        headers["key"] = api_key
    req = urllib.request.Request(url, headers=headers)
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


def greynoise_ip(ip: str) -> dict:
    """Check if an IP is internet background noise, a benign scanner, or a real threat.
    Uses free Community API — no key needed. Returns noise/riot/classification."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    # Try community API first (no key needed)
    data = _gn_get(_COMMUNITY_URL.format(ip=ip))
    if "message" in data and "not found" in data["message"].lower():
        return {
            "ip":             ip,
            "source":         "GreyNoise Community",
            "seen":           False,
            "noise":          False,
            "riot":           False,
            "classification": "unknown",
            "verdict":        "NOT_SEEN — not in GreyNoise database (likely targeted or new)",
        }
    if "error" not in data:
        return {
            "ip":             ip,
            "source":         "GreyNoise Community",
            "seen":           True,
            "noise":          data.get("noise", False),
            "riot":           data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name":           data.get("name", ""),
            "link":           data.get("link", ""),
            "verdict":        (
                "BACKGROUND_NOISE — mass internet scanner, low threat" if data.get("noise") and not data.get("riot")
                else "BENIGN — known good service (CDN, research, etc.)" if data.get("riot")
                else "MALICIOUS — targeted attacker" if data.get("classification") == "malicious"
                else "UNKNOWN"
            ),
        }

    # Fallback: full API with key
    api_key = os.getenv("GREYNOISE_API_KEY", "")
    if not api_key:
        return {"error": "GreyNoise Community API failed and GREYNOISE_API_KEY not set. Get free key at greynoise.io"}

    ctx = _gn_get(_CONTEXT_URL.format(ip=ip), api_key)
    riot = _gn_get(_RIOT_URL.format(ip=ip), api_key)
    return {
        "ip":             ip,
        "source":         "GreyNoise Full API",
        "seen":           ctx.get("seen", False),
        "noise":          ctx.get("noise", False),
        "riot":           riot.get("riot", False),
        "classification": ctx.get("classification", "unknown"),
        "name":           ctx.get("name", ""),
        "actor":          ctx.get("actor", ""),
        "tags":           ctx.get("tags", [])[:10],
        "os":             ctx.get("metadata", {}).get("os", ""),
        "country":        ctx.get("metadata", {}).get("country", ""),
        "asn":            ctx.get("metadata", {}).get("asn", ""),
        "last_seen":      ctx.get("last_seen", ""),
        "first_seen":     ctx.get("first_seen", ""),
        "verdict":        (
            "BACKGROUND_NOISE" if ctx.get("noise") and ctx.get("classification") != "malicious"
            else "MALICIOUS" if ctx.get("classification") == "malicious"
            else "BENIGN" if riot.get("riot")
            else "UNKNOWN"
        ),
    }


TOOLS = {
    "greynoise_ip": {
        "fn": greynoise_ip,
        "description": (
            "Check if an IP is internet background noise (mass scanners), a benign service, "
            "or a real targeted threat using GreyNoise. Community API works without a key. "
            "Essential for filtering out noisy scanners from real attackers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to classify"}
            },
            "required": ["ip"]
        }
    },
}
