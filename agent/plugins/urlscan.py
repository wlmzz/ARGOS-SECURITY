"""
ARGOS Plugin: URLScan.io
Submit URLs for sandboxed scanning and retrieve full analysis (DOM, screenshots, requests, IPs).
Free API key at: urlscan.io/user/signup (100 scans/day free)
Set URLSCAN_API_KEY env var.
"""
from __future__ import annotations
import json, os, time, urllib.request, urllib.error

MANIFEST = {
    "id":          "urlscan",
    "name":        "URLScan.io",
    "description": "Submit URLs for sandboxed analysis: full DOM, page requests, IPs contacted, verdicts, screenshots.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_BASE = "https://urlscan.io/api/v1"


def _req(method: str, path: str, body: dict | None = None, api_key: str = "") -> dict:
    url = f"{_BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Accept": "application/json", "User-Agent": "ARGOS/1.0"}
    if api_key:
        headers["API-Key"] = api_key
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def urlscan_submit(url: str, visibility: str = "public", wait_seconds: int = 30) -> dict:
    """Submit a URL to URLScan.io for sandbox analysis. Waits up to wait_seconds for result.
    Visibility: 'public' (default), 'unlisted', or 'private' (requires paid plan)."""
    api_key = os.getenv("URLSCAN_API_KEY", "")
    if not api_key:
        return {"error": "URLSCAN_API_KEY env var not set. Get free key at urlscan.io/user/signup"}

    submit = _req("POST", "/scan/", {"url": url, "visibility": visibility}, api_key)
    if "error" in submit or "uuid" not in submit:
        return submit

    uuid = submit["uuid"]
    result_url = submit.get("result", f"https://urlscan.io/result/{uuid}/")

    # Poll for result
    waited = 0
    poll_interval = 5
    while waited < wait_seconds:
        time.sleep(poll_interval)
        waited += poll_interval
        result = _req("GET", f"/result/{uuid}/")
        if "error" not in result and "page" in result:
            break
    else:
        return {
            "status":       "pending",
            "uuid":         uuid,
            "result_url":   result_url,
            "message":      f"Scan submitted but not ready after {wait_seconds}s. Check result_url manually.",
        }

    page = result.get("page", {})
    verdicts = result.get("verdicts", {}).get("overall", {})
    stats = result.get("stats", {})
    lists = result.get("lists", {})

    return {
        "url":            url,
        "uuid":           uuid,
        "source":         "URLScan.io",
        "result_url":     result_url,
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
        "domain":         page.get("domain", ""),
        "ip":             page.get("ip", ""),
        "country":        page.get("country", ""),
        "server":         page.get("server", ""),
        "title":          page.get("title", ""),
        "verdict":        "MALICIOUS" if verdicts.get("malicious") else "CLEAN",
        "malicious_score": verdicts.get("score", 0),
        "tags":           verdicts.get("tags", []),
        "total_requests": stats.get("requests", {}).get("total", 0),
        "ips_contacted":  lists.get("ips", [])[:20],
        "domains_contacted": lists.get("domains", [])[:20],
        "urls_count":     len(lists.get("urls", [])),
    }


def urlscan_search(query: str, size: int = 10) -> dict:
    """Search URLScan.io historical scan database. Query examples: 'domain:evil.com', 'ip:1.2.3.4', 'page.title:phishing'"""
    import urllib.parse
    params = urllib.parse.urlencode({"q": query, "size": min(size, 100)})
    data = _req("GET", f"/search/?{params}")
    if "error" in data:
        return data
    results = data.get("results", [])
    return {
        "query":   query,
        "source":  "URLScan.io",
        "total":   data.get("total", {}).get("value", 0),
        "results": [
            {
                "url":         r.get("page", {}).get("url", ""),
                "domain":      r.get("page", {}).get("domain", ""),
                "ip":          r.get("page", {}).get("ip", ""),
                "country":     r.get("page", {}).get("country", ""),
                "score":       r.get("verdicts", {}).get("overall", {}).get("score", 0),
                "malicious":   r.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "scan_date":   r.get("task", {}).get("time", ""),
                "result_url":  r.get("result", ""),
            }
            for r in results
        ],
    }


TOOLS = {
    "urlscan_submit": {
        "fn": urlscan_submit,
        "description": (
            "Submit a suspicious URL to URLScan.io for full sandbox analysis: "
            "DOM inspection, all HTTP requests made, IPs contacted, page title, server, "
            "malicious verdict score, and screenshot. Waits up to wait_seconds for result."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url":          {"type": "string",  "description": "URL to scan"},
                "visibility":   {"type": "string",  "description": "Scan visibility: 'public' (default), 'unlisted'"},
                "wait_seconds": {"type": "integer", "description": "Seconds to wait for result (default: 30, max: 120)"},
            },
            "required": ["url"]
        }
    },
    "urlscan_search": {
        "fn": urlscan_search,
        "description": (
            "Search URLScan.io historical database for past scans. "
            "Query syntax: 'domain:evil.com', 'ip:1.2.3.4', 'page.title:phishing', 'hash:abc123'. "
            "Returns matching scans with verdicts and result URLs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string",  "description": "Search query (e.g. 'domain:evil.com')"},
                "size":  {"type": "integer", "description": "Max results to return (default: 10, max: 100)"},
            },
            "required": ["query"]
        }
    },
}
