"""
ARGOS Plugin: EmailRep + Pulsedive
Two free threat intelligence APIs:
  - EmailRep.io: email address reputation (spam, phishing, breach history, age, deliverability)
  - Pulsedive: threat intelligence enrichment for IPs, domains, URLs (free tier, no key needed)
EmailRep: free anonymous (10 req/day) or with EMAILREP_API_KEY for 1000/day
Pulsedive: free with PULSEDIVE_API_KEY for 30 req/min (register at pulsedive.com)
"""
from __future__ import annotations
import json, os, urllib.request, urllib.error, urllib.parse

MANIFEST = {
    "id":          "emailrep_pulsedive",
    "name":        "EmailRep + Pulsedive",
    "description": "Email reputation (phishing/spam/breach history) via EmailRep, and IP/domain/URL threat intel via Pulsedive.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}


def _get(url: str, headers: dict | None = None) -> dict:
    h = {"Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
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


def _post(url: str, body: dict, headers: dict | None = None) -> dict:
    h = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:200]}"}
    except Exception as e:
        return {"error": str(e)}


# ─── EmailRep ─────────────────────────────────────────────────────────────────

def emailrep_check(email: str) -> dict:
    """Check email reputation: phishing/spam risk, data breach history, domain age, MX validity.
    Works without key (10 req/day). Set EMAILREP_API_KEY for 1000/day."""
    api_key = os.getenv("EMAILREP_API_KEY", "")
    headers = {}
    if api_key:
        headers["Key"] = api_key

    data = _get(f"https://emailrep.io/{urllib.parse.quote(email)}", headers)
    if "error" in data:
        return data

    flags = data.get("details", {})
    risk  = data.get("risk", "unknown")  # "none", "low", "medium", "high", "critical"

    return {
        "email":              email,
        "source":             "EmailRep.io",
        "reputation":         data.get("reputation", ""),
        "risk":               risk,
        "verdict":            f"{'HIGH RISK' if risk in ('high','critical') else 'MEDIUM RISK' if risk == 'medium' else 'LOW RISK'}: {risk}",
        "suspicious":         data.get("suspicious", False),
        "references":         data.get("references", 0),
        "domain_reputation":  flags.get("domain_reputation", ""),
        "new_domain":         flags.get("new_domain", False),
        "days_since_domain_creation": flags.get("days_since_domain_creation", None),
        "spam":               flags.get("spam", False),
        "free_provider":      flags.get("free_provider", False),
        "disposable":         flags.get("disposable", False),
        "deliverable":        flags.get("deliverable", False),
        "accept_all":         flags.get("accept_all", False),
        "valid_mx":           flags.get("valid_mx", False),
        "spoofable":          flags.get("spoofable", False),
        "spf_strict":         flags.get("spf_strict", False),
        "dmarc_enforced":     flags.get("dmarc_enforced", False),
        "profiles":           flags.get("profiles", [])[:10],
        "data_breach":        flags.get("data_breach", False),
        "malicious_activity": flags.get("malicious_activity", False),
        "credentials_leaked": flags.get("credentials_leaked", False),
    }


# ─── Pulsedive ────────────────────────────────────────────────────────────────

def pulsedive_lookup(ioc: str) -> dict:
    """Enrich an IP, domain, or URL with Pulsedive threat intelligence.
    Returns risk score, threat categories, feeds, linked threats.
    Set PULSEDIVE_API_KEY for higher rate limits (free at pulsedive.com)."""
    api_key = os.getenv("PULSEDIVE_API_KEY", "")

    params: dict = {"pretty": "1", "indicator": ioc}
    if api_key:
        params["key"] = api_key

    url = "https://pulsedive.com/api/info.php?" + urllib.parse.urlencode(params)
    data = _get(url)

    if data.get("error") or not isinstance(data, dict):
        return {"error": str(data.get("error", data))}

    risk = data.get("risk", "unknown")

    return {
        "ioc":        ioc,
        "source":     "Pulsedive",
        "risk":       risk,
        "verdict":    f"{'CRITICAL' if risk == 'critical' else 'HIGH' if risk == 'high' else 'MEDIUM' if risk == 'medium' else 'LOW'} RISK",
        "type":       data.get("type", ""),
        "stamp_seen": data.get("stamp_seen", ""),
        "stamp_updated": data.get("stamp_updated", ""),
        "retired":    data.get("retired", False),
        "attributes": data.get("attributes", {}),
        "threats":    [
            {"name": t.get("name", ""), "category": t.get("category", ""), "risk": t.get("risk", "")}
            for t in (data.get("threats", []) or [])[:10]
        ],
        "feeds":      [
            {"name": f.get("name", ""), "organization": f.get("organization", "")}
            for f in (data.get("feeds", []) or [])[:10]
        ],
        "properties": data.get("properties", {}),
    }


TOOLS = {
    "emailrep_check": {
        "fn": emailrep_check,
        "description": (
            "Check email address reputation: phishing/spam risk, data breach exposure, "
            "domain age, MX validity, disposable/free provider detection, spoofability, "
            "DMARC/SPF enforcement, and known malicious activity. "
            "Free (10 req/day anonymous); set EMAILREP_API_KEY for 1000/day."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "Email address to check reputation"}
            },
            "required": ["email"]
        }
    },
    "pulsedive_lookup": {
        "fn": pulsedive_lookup,
        "description": (
            "Enrich any IP, domain, or URL with Pulsedive threat intelligence: "
            "risk score (none/low/medium/high/critical), threat categories, "
            "associated threat actors, and intelligence feed sources. "
            "Set PULSEDIVE_API_KEY for higher limits (free at pulsedive.com)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IP address, domain, or URL to enrich"}
            },
            "required": ["ioc"]
        }
    },
}
