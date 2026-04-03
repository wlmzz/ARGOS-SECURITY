"""
ARGOS Plugin: Censys
Internet-wide scan data — open ports, services, certificates, banners for any IP.
Free tier: 250 queries/month. Register at censys.io/register
Set CENSYS_API_ID and CENSYS_API_SECRET env vars.
"""
from __future__ import annotations
import base64, json, os, re, urllib.request, urllib.error, urllib.parse

MANIFEST = {
    "id":          "censys",
    "name":        "Censys",
    "description": "Internet-wide scan data: open ports, services, TLS certs, banners for any IP or domain. Free tier available.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://search.censys.io/api/v2"


def _auth_header() -> dict | None:
    api_id = os.getenv("CENSYS_API_ID", "")
    api_secret = os.getenv("CENSYS_API_SECRET", "")
    if not api_id or not api_secret:
        return None
    creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def _get(path: str, params: dict | None = None) -> dict:
    auth = _auth_header()
    if auth is None:
        return {"error": "CENSYS_API_ID and CENSYS_API_SECRET not set. Register at censys.io/register"}

    url = f"{_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    headers = {**auth, "Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def _post(path: str, body: dict) -> dict:
    auth = _auth_header()
    if auth is None:
        return {"error": "CENSYS_API_ID and CENSYS_API_SECRET not set. Register at censys.io/register"}

    data = json.dumps(body).encode()
    headers = {**auth, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    req = urllib.request.Request(f"{_BASE}{path}", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def censys_host(ip: str) -> dict:
    """Get full Censys scan data for an IP: open ports, service banners, TLS certificates, reverse DNS."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    data = _get(f"/hosts/{ip}")
    if "error" in data:
        return data

    result = data.get("result", {})
    services = result.get("services", [])

    parsed_services = []
    for svc in services:
        parsed_services.append({
            "port":         svc.get("port", ""),
            "transport":    svc.get("transport_protocol", ""),
            "service":      svc.get("service_name", ""),
            "banner":       svc.get("banner", "")[:200],
            "product":      svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
            "version":      svc.get("software", [{}])[0].get("version", "") if svc.get("software") else "",
            "tls_cert":     svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("subject_dn", "") if svc.get("tls") else "",
        })

    ip_data = result.get("ip", "")
    location = result.get("location", {})
    as_info = result.get("autonomous_system", {})

    return {
        "ip":             ip,
        "source":         "Censys",
        "last_updated":   result.get("last_updated_at", ""),
        "open_ports":     [s["port"] for s in parsed_services],
        "service_count":  len(parsed_services),
        "services":       parsed_services,
        "country":        location.get("country", ""),
        "city":           location.get("city", ""),
        "asn":            as_info.get("asn", ""),
        "as_name":        as_info.get("name", ""),
        "as_description": as_info.get("description", ""),
        "reverse_dns":    result.get("dns", {}).get("reverse_dns", {}).get("names", []),
    }


def censys_search(query: str, index: str = "hosts", per_page: int = 10) -> dict:
    """Search Censys internet scan database.
    index: 'hosts' or 'certificates'.
    Query examples: 'services.port=22 and services.service_name=SSH',
    'autonomous_system.name=DigitalOcean', 'same_service(services.port=80 and services.tls.certificate.parsed.subject.common_name=*.evil.com)'"""
    valid_indexes = {"hosts", "certificates"}
    if index not in valid_indexes:
        return {"error": f"index must be one of: {valid_indexes}"}

    data = _post(f"/{index}/search", {"q": query, "per_page": min(per_page, 100)})
    if "error" in data:
        return data

    hits = data.get("result", {}).get("hits", [])
    return {
        "query":   query,
        "index":   index,
        "source":  "Censys",
        "total":   data.get("result", {}).get("total", 0),
        "results": [
            {
                "ip":      h.get("ip", ""),
                "ports":   [s.get("port") for s in h.get("services", [])],
                "as_name": h.get("autonomous_system", {}).get("name", ""),
                "country": h.get("location", {}).get("country", ""),
                "labels":  h.get("labels", []),
            }
            for h in hits
        ],
    }


TOOLS = {
    "censys_host": {
        "fn": censys_host,
        "description": (
            "Get Censys internet scan data for an IP address: all open ports, service banners, "
            "TLS certificate details, reverse DNS, ASN, country. "
            "Requires CENSYS_API_ID and CENSYS_API_SECRET (free tier at censys.io/register, 250 queries/month)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    "censys_search": {
        "fn": censys_search,
        "description": (
            "Search Censys internet-wide scan database with structured queries. "
            "Find hosts by open port, service, ASN, certificate CN, banner text, country, etc. "
            "Example: 'services.port=3389 and location.country=RU' to find Russian RDP servers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Censys search query"},
                "index":    {"type": "string", "description": "Search index: 'hosts' (default) or 'certificates'"},
                "per_page": {"type": "integer", "description": "Results per page (default: 10, max: 100)"},
            },
            "required": ["query"]
        }
    },
}
