"""
ARGOS Plugin — MISP Threat Intelligence Integration
Communicates with a MISP instance via its REST API.
Only stdlib + subprocess. Timeout = 120 s per request.
"""

import json
import os
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "misp-threat-intel",
    "name": "MISP Threat Intelligence",
    "description": (
        "Full integration with MISP (Malware Information Sharing Platform). "
        "Search IOCs, manage events, add indicators, and look up threat intelligence."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Configuration (read from environment at import time)
# ---------------------------------------------------------------------------
_MISP_URL = os.environ.get("MISP_URL", "https://localhost").rstrip("/")
_MISP_KEY = os.environ.get("MISP_KEY", "")
_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "false").lower() not in ("false", "0", "no")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_THREAT_LEVEL_MAP = {
    1: "High",
    2: "Medium",
    3: "Low",
    4: "Undefined",
}

_VALID_IOC_TYPES = {
    "ip-src", "ip-dst", "domain", "url",
    "md5", "sha256", "sha1",
    "email-src", "email-dst",
    "filename", "hostname",
    "uri", "link",
}


def _ssl_context() -> ssl.SSLContext:
    if _VERIFY_SSL:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _headers() -> dict[str, str]:
    if not _MISP_KEY:
        raise RuntimeError(
            "MISP_KEY environment variable is not set. "
            "Obtain an API key from MISP Administration → Auth Keys."
        )
    return {
        "Authorization": _MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _get(path: str, timeout: int = 120) -> dict:
    """Perform a GET request to the MISP API."""
    url = "{}{}".format(_MISP_URL, path)
    try:
        req = urllib.request.Request(url, headers=_headers(), method="GET")
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except RuntimeError as exc:
        return {"error": str(exc)}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": "HTTP {} — {}".format(exc.code, body[:500])}
    except urllib.error.URLError as exc:
        return {"error": "Cannot reach MISP at {} — {}".format(_MISP_URL, exc.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _post(path: str, payload: dict, timeout: int = 120) -> dict:
    """Perform a POST request to the MISP API."""
    url = "{}{}".format(_MISP_URL, path)
    data = json.dumps(payload).encode()
    try:
        req = urllib.request.Request(url, data=data, headers=_headers(), method="POST")
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except RuntimeError as exc:
        return {"error": str(exc)}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": "HTTP {} — {}".format(exc.code, body[:500])}
    except urllib.error.URLError as exc:
        return {"error": "Cannot reach MISP at {} — {}".format(_MISP_URL, exc.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _extract_event_summary(event_obj: dict) -> dict:
    """Extract a concise summary from a MISP Event object."""
    evt = event_obj.get("Event", event_obj)
    return {
        "id": evt.get("id", ""),
        "uuid": evt.get("uuid", ""),
        "info": evt.get("info", ""),
        "threat_level": _THREAT_LEVEL_MAP.get(int(evt.get("threat_level_id", 4)), "Undefined"),
        "analysis": evt.get("analysis", ""),
        "date": evt.get("date", ""),
        "org": evt.get("Org", {}).get("name", ""),
        "orgc": evt.get("Orgc", {}).get("name", ""),
        "attribute_count": int(evt.get("attribute_count", 0)),
        "published": evt.get("published", False),
        "tags": [t.get("name", "") for t in evt.get("Tag", [])],
    }


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def misp_search(
    value: str,
    type_attribute: str = "",
    category: str = "",
    limit: int = 50,
) -> dict:
    """
    Search MISP attributes (IOCs) by value.

    Parameters
    ----------
    value : str
        The IOC value to search for (IP, domain, hash, URL, email, etc.).
    type_attribute : str
        MISP attribute type filter (e.g. 'ip-src', 'domain', 'md5').
    category : str
        MISP category filter (e.g. 'Network activity', 'Payload delivery').
    limit : int
        Maximum number of attributes to return (default 50).
    """
    payload: dict[str, Any] = {
        "returnFormat": "json",
        "value": value,
        "limit": limit,
        "enforceWarninglist": False,
    }
    if type_attribute:
        payload["type"] = type_attribute
    if category:
        payload["category"] = category

    resp = _post("/attributes/restSearch", payload)

    if "error" in resp:
        return resp

    # MISP wraps results in {"response": {"Attribute": [...]}}
    response_block = resp.get("response", resp)
    attributes = response_block.get("Attribute", [])

    # Collect related event IDs
    event_ids: set[str] = set()
    normalized: list[dict] = []
    for attr in attributes:
        event_ids.add(str(attr.get("event_id", "")))
        normalized.append({
            "id": attr.get("id", ""),
            "event_id": attr.get("event_id", ""),
            "type": attr.get("type", ""),
            "category": attr.get("category", ""),
            "value": attr.get("value", ""),
            "comment": attr.get("comment", ""),
            "to_ids": attr.get("to_ids", False),
            "timestamp": attr.get("timestamp", ""),
            "tags": [t.get("name", "") for t in attr.get("Tag", [])],
        })

    return {
        "attributes": normalized,
        "total": len(normalized),
        "events": sorted(event_ids - {""}),
        "search_value": value,
    }


def misp_get_event(event_id: str) -> dict:
    """
    Retrieve full details of a MISP event including all its attributes.

    Parameters
    ----------
    event_id : str
        MISP event ID or UUID.
    """
    resp = _get("/events/{}".format(event_id))

    if "error" in resp:
        return resp

    evt = resp.get("Event", resp)

    attributes = []
    for attr in evt.get("Attribute", []):
        attributes.append({
            "id": attr.get("id", ""),
            "type": attr.get("type", ""),
            "category": attr.get("category", ""),
            "value": attr.get("value", ""),
            "comment": attr.get("comment", ""),
            "to_ids": attr.get("to_ids", False),
            "timestamp": attr.get("timestamp", ""),
        })

    related_events = [
        {
            "id": rel.get("Event", {}).get("id", ""),
            "info": rel.get("Event", {}).get("info", ""),
        }
        for rel in evt.get("RelatedEvent", [])
    ]

    return {
        "event_id": evt.get("id", ""),
        "uuid": evt.get("uuid", ""),
        "title": evt.get("info", ""),
        "threat_level": _THREAT_LEVEL_MAP.get(int(evt.get("threat_level_id", 4)), "Undefined"),
        "analysis": evt.get("analysis", ""),
        "date": evt.get("date", ""),
        "published": evt.get("published", False),
        "org": evt.get("Org", {}).get("name", ""),
        "orgc": evt.get("Orgc", {}).get("name", ""),
        "tags": [t.get("name", "") for t in evt.get("Tag", [])],
        "attributes": attributes,
        "attribute_count": len(attributes),
        "related_events": related_events,
        "galaxies": [g.get("name", "") for g in evt.get("Galaxy", [])],
    }


def misp_add_event(
    title: str,
    threat_level: int = 2,
    attributes: list | None = None,
    tags: list | None = None,
) -> dict:
    """
    Create a new MISP event, optionally with initial attributes and tags.

    Parameters
    ----------
    title : str
        Short description / title of the event.
    threat_level : int
        1=High, 2=Medium, 3=Low, 4=Undefined.
    attributes : list
        List of attribute dicts: [{"type": "ip-src", "value": "1.2.3.4", "to_ids": true}].
    tags : list
        List of tag name strings to attach to the event.
    """
    if threat_level not in (1, 2, 3, 4):
        return {"error": "threat_level must be 1 (High), 2 (Medium), 3 (Low), or 4 (Undefined)."}

    event_payload: dict[str, Any] = {
        "info": title,
        "threat_level_id": threat_level,
        "analysis": 0,     # 0=Initial, 1=Ongoing, 2=Completed
        "distribution": 0,  # 0=Your organisation only
    }

    if attributes:
        event_payload["Attribute"] = [
            {
                "type": a.get("type", "other"),
                "value": a.get("value", ""),
                "category": a.get("category", "External analysis"),
                "to_ids": a.get("to_ids", True),
                "comment": a.get("comment", ""),
            }
            for a in attributes
            if a.get("value")
        ]

    resp = _post("/events", {"Event": event_payload})

    if "error" in resp:
        return resp

    created = resp.get("Event", resp)
    event_id = created.get("id", "")

    # Attach tags if provided
    tag_errors: list[str] = []
    if tags and event_id:
        for tag in tags:
            tag_resp = _post(
                "/events/addTag",
                {"event": event_id, "tag": tag},
            )
            if "error" in tag_resp:
                tag_errors.append("{}: {}".format(tag, tag_resp["error"]))

    return {
        "event_id": int(event_id) if event_id else None,
        "uuid": created.get("uuid", ""),
        "title": title,
        "threat_level": _THREAT_LEVEL_MAP.get(threat_level, "Undefined"),
        "status": "created",
        "attribute_count": len(attributes or []),
        "tags_added": tags or [],
        "tag_errors": tag_errors,
    }


def misp_add_ioc(
    event_id: str,
    ioc_type: str,
    value: str,
    comment: str = "",
    to_ids: bool = True,
) -> dict:
    """
    Add a single IOC attribute to an existing MISP event.

    Parameters
    ----------
    event_id : str
        MISP event ID to add the attribute to.
    ioc_type : str
        MISP attribute type: ip-src, ip-dst, domain, url, md5, sha256,
        sha1, email-src, email-dst, filename, hostname.
    value : str
        The IOC value (e.g. "1.2.3.4", "evil.com", "deadbeef...").
    comment : str
        Optional human-readable comment.
    to_ids : bool
        Whether this IOC should trigger IDS rules (default True).
    """
    if not value:
        return {"error": "IOC value cannot be empty."}

    if ioc_type not in _VALID_IOC_TYPES:
        return {
            "error": "Invalid ioc_type '{}'. Valid types: {}".format(
                ioc_type, ", ".join(sorted(_VALID_IOC_TYPES))
            )
        }

    # Map ioc_type to MISP category heuristic
    _CATEGORY_MAP = {
        "ip-src": "Network activity",
        "ip-dst": "Network activity",
        "domain": "Network activity",
        "hostname": "Network activity",
        "url": "Network activity",
        "uri": "Network activity",
        "md5": "Payload delivery",
        "sha256": "Payload delivery",
        "sha1": "Payload delivery",
        "filename": "Artifacts dropped",
        "email-src": "Payload delivery",
        "email-dst": "Payload delivery",
        "link": "External analysis",
    }
    category = _CATEGORY_MAP.get(ioc_type, "External analysis")

    payload = {
        "Attribute": {
            "event_id": event_id,
            "type": ioc_type,
            "category": category,
            "value": value,
            "comment": comment,
            "to_ids": to_ids,
            "distribution": 5,  # Inherit from event
        }
    }

    resp = _post("/attributes/add/{}".format(event_id), payload)

    if "error" in resp:
        return resp

    attr = resp.get("Attribute", resp)

    return {
        "attribute_id": attr.get("id", ""),
        "event_id": event_id,
        "type": ioc_type,
        "value": value,
        "category": category,
        "to_ids": to_ids,
        "status": "added",
        "uuid": attr.get("uuid", ""),
    }


def misp_recent_events(limit: int = 20, days: int = 7) -> dict:
    """
    List recent MISP events from the past N days.

    Parameters
    ----------
    limit : int
        Maximum number of events to return (default 20).
    days : int
        Look-back window in days (default 7).
    """
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
    # MISP timestamp filter uses Unix epoch
    from_ts = int(cutoff_dt.timestamp())

    payload = {
        "returnFormat": "json",
        "limit": limit,
        "timestamp": from_ts,
        "sort": "timestamp",
        "direction": "desc",
    }

    resp = _post("/events/restSearch", payload)

    if "error" in resp:
        return resp

    response_block = resp.get("response", resp)
    events_raw = response_block if isinstance(response_block, list) else []

    events = [_extract_event_summary(e) for e in events_raw]

    by_threat: dict[str, int] = {}
    for evt in events:
        tl = evt.get("threat_level", "Undefined")
        by_threat[tl] = by_threat.get(tl, 0) + 1

    return {
        "events": events,
        "total": len(events),
        "days": days,
        "from_date": cutoff_dt.strftime("%Y-%m-%d"),
        "by_threat_level": by_threat,
    }


def misp_lookup_ioc(value: str) -> dict:
    """
    Quickly look up a single IOC (IP, hash, domain, URL) across all MISP events.

    Parameters
    ----------
    value : str
        The IOC to look up (any type: IP, MD5, SHA256, domain, URL).
    """
    if not value:
        return {"error": "value cannot be empty."}

    # Auto-detect type hint for better search accuracy
    import re
    type_hint = ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        type_hint = "ip-src"
    elif re.match(r"^[0-9a-fA-F]{32}$", value):
        type_hint = "md5"
    elif re.match(r"^[0-9a-fA-F]{40}$", value):
        type_hint = "sha1"
    elif re.match(r"^[0-9a-fA-F]{64}$", value):
        type_hint = "sha256"
    elif value.startswith(("http://", "https://")):
        type_hint = "url"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        type_hint = "domain"

    search_result = misp_search(value=value, type_attribute=type_hint, limit=100)

    if "error" in search_result:
        return search_result

    attributes = search_result.get("attributes", [])
    event_ids = search_result.get("events", [])

    if not attributes:
        return {
            "found": False,
            "value": value,
            "events": [],
            "threat_level": "Unknown",
            "tags": [],
        }

    # Aggregate tags across all matching attributes
    all_tags: list[str] = []
    for attr in attributes:
        all_tags.extend(attr.get("tags", []))
    unique_tags = list(dict.fromkeys(all_tags))  # Deduplicate while preserving order

    # Determine highest threat level from associated events (requires additional lookup)
    # Use 'Undefined' as default to avoid N+1 API calls when many events match
    threat_levels_seen: list[str] = []
    event_summaries: list[dict] = []
    for eid in event_ids[:10]:   # Cap at 10 to keep response time reasonable
        evt_resp = _get("/events/{}".format(eid))
        if "error" not in evt_resp:
            summary = _extract_event_summary(evt_resp)
            event_summaries.append(summary)
            threat_levels_seen.append(summary.get("threat_level", "Undefined"))

    # Pick the most severe threat level seen
    _TL_ORDER = ["High", "Medium", "Low", "Undefined", "Unknown"]
    best_threat = min(
        threat_levels_seen,
        key=lambda t: _TL_ORDER.index(t) if t in _TL_ORDER else 99,
        default="Unknown",
    )

    return {
        "found": True,
        "value": value,
        "detected_type": type_hint or "unknown",
        "attribute_count": len(attributes),
        "events": event_summaries,
        "event_ids": event_ids,
        "threat_level": best_threat,
        "tags": unique_tags,
        "to_ids": any(a.get("to_ids") for a in attributes),
    }


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------
TOOLS = {
    "misp_search": {
        "fn": misp_search,
        "description": (
            "Search MISP for IOCs by value (IP, domain, hash, URL, email). "
            "Returns matching attributes and the events they belong to."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "IOC value to search for.",
                },
                "type_attribute": {
                    "type": "string",
                    "description": (
                        "MISP attribute type filter, e.g. 'ip-src', 'domain', "
                        "'md5', 'sha256', 'url', 'email-src'. Leave empty to search all types."
                    ),
                    "default": "",
                },
                "category": {
                    "type": "string",
                    "description": (
                        "MISP category filter, e.g. 'Network activity', 'Payload delivery'. "
                        "Leave empty for all categories."
                    ),
                    "default": "",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of attributes to return (default 50).",
                    "default": 50,
                },
            },
            "required": ["value"],
        },
    },
    "misp_get_event": {
        "fn": misp_get_event,
        "description": (
            "Retrieve full details of a MISP event including all attributes, "
            "tags, related events, and galaxy assignments."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "MISP event ID (numeric) or UUID.",
                },
            },
            "required": ["event_id"],
        },
    },
    "misp_add_event": {
        "fn": misp_add_event,
        "description": (
            "Create a new MISP threat intelligence event. "
            "Optionally seed it with initial IOC attributes and tags."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short title / description for the event.",
                },
                "threat_level": {
                    "type": "integer",
                    "description": "Threat level: 1=High, 2=Medium, 3=Low, 4=Undefined.",
                    "default": 2,
                    "enum": [1, 2, 3, 4],
                },
                "attributes": {
                    "type": "array",
                    "description": (
                        "Initial IOC attributes. Each item: "
                        '{"type": "ip-src", "value": "1.2.3.4", "to_ids": true, "comment": "..."}.'
                    ),
                    "items": {"type": "object"},
                    "default": [],
                },
                "tags": {
                    "type": "array",
                    "description": "Tag names to attach to the event (e.g. ['tlp:white', 'APT']).",
                    "items": {"type": "string"},
                    "default": [],
                },
            },
            "required": ["title"],
        },
    },
    "misp_add_ioc": {
        "fn": misp_add_ioc,
        "description": (
            "Add a single IOC attribute to an existing MISP event. "
            "Supports IP, domain, URL, hash, email, and filename types."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "MISP event ID to add the attribute to.",
                },
                "ioc_type": {
                    "type": "string",
                    "description": (
                        "MISP attribute type: ip-src, ip-dst, domain, url, "
                        "md5, sha256, sha1, email-src, email-dst, filename, hostname."
                    ),
                },
                "value": {
                    "type": "string",
                    "description": "The IOC value (e.g. '1.2.3.4', 'evil.com', 'deadbeef...').",
                },
                "comment": {
                    "type": "string",
                    "description": "Optional human-readable note about this IOC.",
                    "default": "",
                },
                "to_ids": {
                    "type": "boolean",
                    "description": "Whether this IOC should trigger IDS signatures (default true).",
                    "default": True,
                },
            },
            "required": ["event_id", "ioc_type", "value"],
        },
    },
    "misp_recent_events": {
        "fn": misp_recent_events,
        "description": (
            "List the most recent MISP events from the past N days. "
            "Returns event summaries grouped by threat level."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum events to return (default 20).",
                    "default": 20,
                },
                "days": {
                    "type": "integer",
                    "description": "Look-back window in days (default 7).",
                    "default": 7,
                },
            },
            "required": [],
        },
    },
    "misp_lookup_ioc": {
        "fn": misp_lookup_ioc,
        "description": (
            "Quickly look up a single IOC (IP, hash, domain, URL) across all MISP events. "
            "Auto-detects IOC type and returns threat level, tags, and related events."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "The IOC to look up (IP address, MD5/SHA256 hash, domain, or URL).",
                },
            },
            "required": ["value"],
        },
    },
}
