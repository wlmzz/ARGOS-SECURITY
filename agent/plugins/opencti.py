"""
ARGOS Plugin: OpenCTI
Integration with OpenCTI threat intelligence platform.
OpenCTI is an open-source CTI platform that stores and correlates threat data
using STIX 2.1 — IOCs, threat actors, malware, campaigns, attack patterns.

Self-hosted: https://github.com/opencti-platform/opencti
Cloud: https://filigran.io/solutions/opencti/

Set env vars:
  OPENCTI_URL      = http://your-opencti:4000  (or Filigran cloud URL)
  OPENCTI_TOKEN    = your-api-token (from OpenCTI Settings → Profile → API Access)
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.error

MANIFEST = {
    "id":          "opencti",
    "name":        "OpenCTI",
    "description": "Query OpenCTI threat intelligence platform: search IOCs, threat actors, malware, attack patterns (STIX 2.1).",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}


def _gql(query: str, variables: dict | None = None) -> dict:
    url   = os.getenv("OPENCTI_URL", "").rstrip("/")
    token = os.getenv("OPENCTI_TOKEN", "")

    if not url:
        return {"error": "OPENCTI_URL not set (e.g. http://your-opencti:4000)"}
    if not token:
        return {"error": "OPENCTI_TOKEN not set (Settings → Profile → API Access in OpenCTI)"}

    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        f"{url}/graphql",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent":    "ARGOS/1.0",
        },
    )
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


def opencti_search_ioc(value: str, entity_type: str = "all") -> dict:
    """Search OpenCTI for an IOC (IP, domain, URL, hash, email).
    entity_type: 'all', 'IPv4-Addr', 'Domain-Name', 'Url', 'File', 'Email-Addr'"""

    # Auto-detect type if not specified
    if entity_type == "all":
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            entity_type = "IPv4-Addr"
        elif re.match(r"^[a-f0-9]{32,64}$", value.lower()):
            entity_type = "File"
        elif re.match(r"^https?://", value):
            entity_type = "Url"
        elif re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", value):
            entity_type = "Domain-Name"

    query = """
    query SearchStixObservables($filters: FilterGroup, $first: Int) {
      stixCyberObservables(filters: $filters, first: $first) {
        edges {
          node {
            id
            entity_type
            observable_value
            created_at
            x_opencti_score
            ... on IPv4Addr { value }
            ... on DomainName { value }
            ... on Url { value }
            ... on StixFile { name hashes { MD5 SHA256 } }
            indicators { edges { node {
              name pattern confidence
              valid_from valid_until
              killChainPhases { edges { node { phase_name } } }
            }}}
            reports { edges { node { name published } } }
          }
        }
        pageInfo { globalCount }
      }
    }
    """

    type_filter = [] if entity_type == "all" else [
        {"key": "entity_type", "values": [entity_type], "operator": "eq"}
    ]

    variables = {
        "first": 10,
        "filters": {
            "mode": "and",
            "filters": [
                {"key": "value", "values": [value], "operator": "contains"},
                *type_filter,
            ],
            "filterGroups": []
        }
    }

    result = _gql(query, variables)
    if "error" in result:
        return result
    if "errors" in result:
        return {"error": str(result["errors"][0].get("message", result["errors"]))}

    edges = result.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
    total = result.get("data", {}).get("stixCyberObservables", {}).get("pageInfo", {}).get("globalCount", 0)

    observables = []
    for edge in edges:
        node = edge.get("node", {})
        indicators = [
            {
                "name":       i["node"]["name"],
                "pattern":    i["node"]["pattern"],
                "confidence": i["node"]["confidence"],
                "valid_from": i["node"]["valid_from"],
                "valid_until": i["node"]["valid_until"],
                "kill_chain": [kc["node"]["phase_name"] for kc in i["node"]["killChainPhases"]["edges"]],
            }
            for i in node.get("indicators", {}).get("edges", [])
        ]
        reports = [r["node"]["name"] for r in node.get("reports", {}).get("edges", [])]
        observables.append({
            "id":           node.get("id"),
            "type":         node.get("entity_type"),
            "value":        node.get("observable_value"),
            "score":        node.get("x_opencti_score"),
            "created_at":   node.get("created_at"),
            "indicators":   indicators,
            "reports":      reports,
        })

    return {
        "query":       value,
        "source":      "OpenCTI",
        "total_found": total,
        "found":       bool(observables),
        "verdict":     "KNOWN MALICIOUS" if observables else "NOT IN OPENCTI",
        "observables": observables,
    }


def opencti_get_threats(threat_type: str = "all", limit: int = 20) -> dict:
    """Get recent threat actors, malware families, or campaigns from OpenCTI.
    threat_type: 'all', 'Threat-Actor-Group', 'Malware', 'Campaign', 'Attack-Pattern'"""

    entity_map = {
        "all":                None,
        "Threat-Actor-Group": "threatActorsGroup",
        "Malware":            "malwares",
        "Campaign":           "campaigns",
        "Attack-Pattern":     "attackPatterns",
    }

    if threat_type not in entity_map:
        return {"error": f"threat_type must be one of: {list(entity_map.keys())}"}

    # Query all relevant entity types
    query = """
    query GetThreats($first: Int) {
      threatActorsGroup(first: $first, orderBy: modified, orderMode: desc) {
        edges { node { id name description modified
          aliases { value }
          externalReferences { edges { node { source_name url } } }
        }}
      }
      malwares(first: $first, orderBy: modified, orderMode: desc) {
        edges { node { id name description is_family modified
          malware_types
          aliases { value }
        }}
      }
    }
    """

    result = _gql(query, {"first": min(limit, 50)})
    if "error" in result:
        return result
    if "errors" in result:
        return {"error": str(result["errors"][0].get("message", result["errors"]))}

    data = result.get("data", {})
    actors = [
        {
            "id":          e["node"]["id"],
            "name":        e["node"]["name"],
            "type":        "Threat-Actor-Group",
            "description": (e["node"].get("description") or "")[:300],
            "modified":    e["node"]["modified"],
            "aliases":     [a["value"] for a in (e["node"].get("aliases") or [])],
        }
        for e in data.get("threatActorsGroup", {}).get("edges", [])
    ]
    malwares = [
        {
            "id":          e["node"]["id"],
            "name":        e["node"]["name"],
            "type":        "Malware" + (" Family" if e["node"].get("is_family") else ""),
            "description": (e["node"].get("description") or "")[:300],
            "modified":    e["node"]["modified"],
            "malware_types": e["node"].get("malware_types", []),
        }
        for e in data.get("malwares", {}).get("edges", [])
    ]

    all_threats = []
    if threat_type in ("all", "Threat-Actor-Group"):
        all_threats.extend(actors)
    if threat_type in ("all", "Malware"):
        all_threats.extend(malwares)

    return {
        "source":      "OpenCTI",
        "threat_type": threat_type,
        "count":       len(all_threats),
        "threats":     all_threats[:limit],
    }


TOOLS = {
    "opencti_search_ioc": {
        "fn": opencti_search_ioc,
        "description": (
            "Search your OpenCTI platform for an IOC (IP, domain, URL, file hash, email). "
            "Returns threat score, associated indicators, MITRE kill chain phases, and source reports. "
            "Requires OPENCTI_URL and OPENCTI_TOKEN env vars."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "value":       {"type": "string", "description": "IOC to search (IP, domain, URL, hash, email)"},
                "entity_type": {"type": "string", "description": "Type filter: 'all' (auto-detect), 'IPv4-Addr', 'Domain-Name', 'Url', 'File'"},
            },
            "required": ["value"]
        }
    },
    "opencti_get_threats": {
        "fn": opencti_get_threats,
        "description": (
            "Get recent threat intelligence from OpenCTI: threat actor groups, malware families, campaigns. "
            "Requires OPENCTI_URL and OPENCTI_TOKEN env vars."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "threat_type": {"type": "string",  "description": "Filter: 'all', 'Threat-Actor-Group', 'Malware', 'Campaign'"},
                "limit":       {"type": "integer", "description": "Max results (default: 20)"},
            },
            "required": []
        }
    },
}
