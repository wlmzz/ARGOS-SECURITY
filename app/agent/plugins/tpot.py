"""
ARGOS Plugin: T-Pot Honeypot Platform
Query your T-Pot installation's Elasticsearch backend for attack data.
T-Pot runs 20+ honeypot services simultaneously: Cowrie (SSH/Telnet),
Dionaea (SMB/FTP/HTTP/MSSQL), Suricata IDS, and many more.

Install T-Pot: https://github.com/telekom-security/tpotce
Default T-Pot Elasticsearch: http://<your-tpot-ip>:64298

Set TPOT_HOST env var (e.g. '192.168.1.100')
Set TPOT_ES_PORT env var (default: 64298)
Set TPOT_ES_USER / TPOT_ES_PASS for basic auth (default: elastic/changeme)
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone, timedelta

MANIFEST = {
    "id":          "tpot",
    "name":        "T-Pot Honeypot",
    "description": "Query T-Pot honeypot platform Elasticsearch: attack stats, top IPs, credentials captured, services hit.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}


def _es_url() -> str:
    host = os.getenv("TPOT_HOST", "")
    port = os.getenv("TPOT_ES_PORT", "64298")
    if not host:
        return ""
    return f"http://{host}:{port}"


def _es_query(index: str, body: dict) -> dict:
    base = _es_url()
    if not base:
        return {"error": "TPOT_HOST env var not set. Set to your T-Pot server IP."}

    user = os.getenv("TPOT_ES_USER", "elastic")
    pwd  = os.getenv("TPOT_ES_PASS", "changeme")

    import base64
    creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()

    url  = f"{base}/{index}/_search"
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Basic {creds}",
            "User-Agent":    "ARGOS/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def _time_filter(hours: int) -> dict:
    since = (datetime.now(tz=timezone.utc) - timedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": since}}}


def tpot_stats(hours: int = 24) -> dict:
    """Get attack statistics from T-Pot for the last N hours.
    Returns total events, top attacker IPs, top countries, top targeted ports/services."""
    index = "logstash-*"
    body = {
        "size": 0,
        "query": {"bool": {"filter": [_time_filter(hours)]}},
        "aggs": {
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": 20}
            },
            "top_countries": {
                "terms": {"field": "geoip.country_name.keyword", "size": 15}
            },
            "top_ports": {
                "terms": {"field": "dest_port", "size": 20}
            },
            "top_honeypots": {
                "terms": {"field": "type.keyword", "size": 20}
            },
        }
    }

    result = _es_query(index, body)
    if "error" in result:
        return result

    hits_total = result.get("hits", {}).get("total", {})
    total = hits_total.get("value", 0) if isinstance(hits_total, dict) else hits_total

    aggs = result.get("aggregations", {})

    def extract_buckets(agg_name: str) -> list[dict]:
        buckets = aggs.get(agg_name, {}).get("buckets", [])
        return [{"value": b.get("key"), "count": b.get("doc_count")} for b in buckets]

    return {
        "source":        "T-Pot",
        "hours_queried": hours,
        "total_events":  total,
        "top_attacker_ips": extract_buckets("top_ips"),
        "top_countries":    extract_buckets("top_countries"),
        "top_targeted_ports": extract_buckets("top_ports"),
        "top_honeypots":    extract_buckets("top_honeypots"),
    }


def tpot_credentials(hours: int = 24, limit: int = 50) -> dict:
    """Get captured login credentials from T-Pot honeypots (Cowrie SSH/Telnet).
    Returns most common username/password combinations attackers tried."""
    index = "logstash-*"
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    _time_filter(hours),
                    {"term": {"type.keyword": "cowrie"}},
                    {"exists": {"field": "username"}},
                ]
            }
        },
        "aggs": {
            "top_users": {
                "terms": {"field": "username.keyword", "size": limit}
            },
            "top_passwords": {
                "terms": {"field": "password.keyword", "size": limit}
            },
            "top_combos": {
                "composite": {
                    "size": limit,
                    "sources": [
                        {"user": {"terms": {"field": "username.keyword"}}},
                        {"pass": {"terms": {"field": "password.keyword"}}},
                    ]
                }
            },
        }
    }

    result = _es_query(index, body)
    if "error" in result:
        return result

    aggs = result.get("aggregations", {})
    top_users  = [{"username": b["key"], "count": b["doc_count"]} for b in aggs.get("top_users", {}).get("buckets", [])]
    top_passes = [{"password": b["key"], "count": b["doc_count"]} for b in aggs.get("top_passwords", {}).get("buckets", [])]
    top_combos = [
        {"username": b["key"]["user"], "password": b["key"]["pass"], "count": b["doc_count"]}
        for b in aggs.get("top_combos", {}).get("buckets", [])
    ]

    return {
        "source":       "T-Pot (Cowrie)",
        "hours_queried": hours,
        "top_usernames": top_users[:20],
        "top_passwords": top_passes[:20],
        "top_combos":   top_combos[:20],
    }


def tpot_search_ip(ip: str, hours: int = 168) -> dict:
    """Search T-Pot logs for all events from a specific attacker IP (default: last 7 days)."""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    index = "logstash-*"
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    _time_filter(hours),
                    {"term": {"src_ip.keyword": ip}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "type", "dest_port", "username", "password", "request", "eventid"],
    }

    result = _es_query(index, body)
    if "error" in result:
        return result

    hits = result.get("hits", {}).get("hits", [])
    events = []
    for h in hits:
        src = h.get("_source", {})
        events.append({
            "timestamp":  src.get("@timestamp", ""),
            "honeypot":   src.get("type", ""),
            "port":       src.get("dest_port", ""),
            "username":   src.get("username", ""),
            "password":   src.get("password", ""),
            "request":    src.get("request", "")[:200],
            "event_id":   src.get("eventid", ""),
        })

    total = result.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", 0)

    return {
        "ip":           ip,
        "source":       "T-Pot",
        "hours_queried": hours,
        "total_events": total,
        "events":       events,
    }


TOOLS = {
    "tpot_stats": {
        "fn": tpot_stats,
        "description": (
            "Get attack statistics from your T-Pot honeypot for the last N hours. "
            "Returns total events, top attacker IPs, countries, targeted ports, and most active honeypot services. "
            "Requires TPOT_HOST env var pointing to your T-Pot server."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "description": "Hours to look back (default: 24)"}
            },
            "required": []
        }
    },
    "tpot_credentials": {
        "fn": tpot_credentials,
        "description": (
            "Get credentials captured by T-Pot honeypots (Cowrie SSH/Telnet traps). "
            "Shows most common usernames, passwords, and username+password combinations attackers tried. "
            "Requires TPOT_HOST env var."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "description": "Hours to look back (default: 24)"},
                "limit": {"type": "integer", "description": "Max results per category (default: 50)"},
            },
            "required": []
        }
    },
    "tpot_search_ip": {
        "fn": tpot_search_ip,
        "description": (
            "Search T-Pot honeypot logs for all events from a specific attacker IP. "
            "Returns timeline of attacks, honeypot services hit, credentials tried, HTTP requests. "
            "Requires TPOT_HOST env var."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip":    {"type": "string",  "description": "Attacker IP to search for"},
                "hours": {"type": "integer", "description": "Hours to look back (default: 168 = 7 days)"},
            },
            "required": ["ip"]
        }
    },
}
