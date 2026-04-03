"""
ARGOS Plugin: Qualys SSL Labs
Deep TLS/SSL analysis — grade A-F, protocol versions, cipher suites, certificate details,
HSTS, HPKP, vulnerabilities (POODLE, BEAST, Heartbleed, etc.).
FREE — no API key needed.
Note: Analysis takes 60-120 seconds for first scan of a host.
"""
from __future__ import annotations
import json, time, urllib.request, urllib.error, urllib.parse

MANIFEST = {
    "id":          "ssl_labs",
    "name":        "Qualys SSL Labs",
    "description": "Deep TLS analysis: grade A-F, cipher suites, vulnerabilities (Heartbleed, POODLE, etc.). Free, no key needed.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://api.ssllabs.com/api/v3"


def _ssl_get(path: str, params: dict | None = None) -> dict:
    url = f"{_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "ARGOS/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def ssllabs_analyze(hostname: str, max_wait_seconds: int = 150) -> dict:
    """Run a full Qualys SSL Labs analysis on a hostname.
    Returns grade (A/B/C/D/E/F/T/M), protocol support, cipher suites, certificate details,
    and vulnerability flags (Heartbleed, POODLE, BEAST, FREAK, Logjam, DROWN, etc.).
    WARNING: Takes 60-120 seconds for first scan. Subsequent scans use cached results."""

    # Start scan
    data = _ssl_get("/analyze", {"host": hostname, "startNew": "on", "all": "done", "ignoreMismatch": "on"})
    if "error" in data:
        return data
    if "errors" in data:
        return {"error": str(data["errors"])}

    # Poll until ready
    start = time.time()
    while data.get("status") not in ("READY", "ERROR"):
        elapsed = time.time() - start
        if elapsed >= max_wait_seconds:
            return {
                "hostname": hostname,
                "source":   "Qualys SSL Labs",
                "status":   "IN_PROGRESS",
                "message":  f"Analysis still running after {max_wait_seconds}s. Call again to get cached results.",
                "progress": data.get("status", ""),
            }
        time.sleep(10)
        data = _ssl_get("/analyze", {"host": hostname, "all": "done"})
        if "error" in data:
            return data

    if data.get("status") == "ERROR":
        return {"error": f"SSL Labs analysis failed: {data.get('statusMessage', 'unknown')}"}

    endpoints = data.get("endpoints", [])
    parsed_endpoints = []

    for ep in endpoints:
        details = ep.get("details", {}) or {}

        # Protocol support
        protocols = details.get("protocols", [])
        proto_names = [f"{p.get('name')} {p.get('version')}" for p in protocols]

        # Cipher suites from first suite list
        suites = []
        for suite_list in (details.get("suites", []) or []):
            for s in (suite_list.get("list", []) or [])[:5]:
                suites.append(s.get("name", ""))

        # Certificate
        cert_chains = details.get("certChains", [])
        cert = {}
        if cert_chains:
            leaf = cert_chains[0].get("certIds", [])
            # Certificate is in data.certs
        # Get from top-level certs
        all_certs = data.get("certs", [])
        if all_certs:
            c = all_certs[0]
            cert = {
                "subject":    c.get("subject", ""),
                "issuer":     c.get("issuerSubject", ""),
                "not_before": c.get("notBefore", ""),
                "not_after":  c.get("notAfter", ""),
                "key_alg":    c.get("keyAlg", ""),
                "key_size":   c.get("keySize", 0),
                "sig_alg":    c.get("sigAlg", ""),
                "sha256":     c.get("sha256Hash", ""),
                "revoked":    c.get("revocationStatus", 0) != 0,
            }

        # Vulnerability flags
        vulns = {
            "heartbleed":    details.get("heartbleed", False),
            "poodle":        details.get("poodle", False),
            "poodle_tls":    details.get("poodleTls", 0) > 0,
            "freak":         details.get("freak", False),
            "logjam":        details.get("logjam", False),
            "drown":         details.get("drownVulnerable", False),
            "robot":         details.get("robotStatus", 0) not in (0, 4),
            "beast":         details.get("vulnBeast", False),
            "rc4":           details.get("rc4Only", False),
            "no_sni":        details.get("sniRequired", False),
            "zombie_poodle": details.get("zombiePoodle", 0) > 0,
            "golden_doodle": details.get("goldenDoodle", 0) > 0,
        }
        active_vulns = [k for k, v in vulns.items() if v]

        parsed_endpoints.append({
            "ip":               ep.get("ipAddress", ""),
            "grade":            ep.get("grade", "?"),
            "grade_ignore_trust": ep.get("gradeTrustIgnored", ""),
            "status_message":   ep.get("statusMessage", ""),
            "protocols":        proto_names,
            "cipher_suites":    suites[:10],
            "forward_secrecy":  details.get("forwardSecrecy", 0),
            "hsts":             details.get("hstsPolicy", {}).get("status", "") if details.get("hstsPolicy") else "",
            "vulnerabilities":  active_vulns,
            "certificate":      cert,
        })

    # Overall grade = worst grade across endpoints
    grade_order = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]
    grades = [ep["grade"] for ep in parsed_endpoints if ep["grade"]]
    overall_grade = "?"
    for g in grade_order:
        if g in grades:
            overall_grade = g
            break

    all_vulns = list({v for ep in parsed_endpoints for v in ep["vulnerabilities"]})

    return {
        "hostname":      hostname,
        "source":        "Qualys SSL Labs",
        "status":        "READY",
        "overall_grade": overall_grade,
        "verdict":       (
            "EXCELLENT — A+ grade, HSTS, no vulnerabilities" if overall_grade == "A+"
            else f"GRADE {overall_grade}" + (" — VULNERABLE: " + ", ".join(all_vulns).upper() if all_vulns else "")
        ),
        "vulnerabilities": all_vulns,
        "endpoints":     parsed_endpoints,
        "endpoint_count": len(parsed_endpoints),
    }


TOOLS = {
    "ssllabs_analyze": {
        "fn": ssllabs_analyze,
        "description": (
            "Run a full Qualys SSL Labs TLS analysis on a hostname. "
            "Returns grade (A+ to F), supported protocols, cipher suites, certificate details, "
            "and vulnerability flags (Heartbleed, POODLE, FREAK, BEAST, DROWN, Logjam, ROBOT, etc.). "
            "FREE — no API key needed. First scan takes 60-120 seconds."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "hostname":          {"type": "string",  "description": "Hostname to analyze (e.g. 'example.com')"},
                "max_wait_seconds":  {"type": "integer", "description": "Max seconds to wait for analysis (default: 150)"},
            },
            "required": ["hostname"]
        }
    },
}
