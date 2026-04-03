"""
favicon_osint.py — ARGOS plugin
Favicon-based OSINT and asset discovery.
Searches for websites sharing the same favicon across Shodan, ZoomEye, Fofa, Censys.
Based on favicorn (https://github.com/sharsil/favicorn) + custom implementation.
"""

import hashlib
import base64
import json
import os
import re
import struct
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

MANIFEST = {
    "id": "favicon_osint",
    "name": "Favicon OSINT",
    "version": "1.0.0",
    "description": "Favicon hash-based asset discovery on Shodan, ZoomEye, Fofa, Censys",
    "author": "ARGOS",
    "category": "osint",
    "tools": [
        "favicon_hash",
        "favicon_search_shodan",
        "favicon_search_zoomeye",
        "favicon_search_fofa",
        "favicon_full_hunt",
    ],
}

RESULTS_DIR = "/opt/argos/logs/favicon_osint"
os.makedirs(RESULTS_DIR, exist_ok=True)


def _fetch(url: str, timeout: int = 10, headers: dict = None) -> tuple[bytes, int]:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), resp.getcode()
    except Exception as e:
        return b"", 0


def _mmh3_hash(data: bytes) -> int:
    """
    MurmurHash3 32-bit implementation for Shodan favicon hashing.
    Shodan uses MurmurHash3 of the base64-encoded favicon.
    """
    # Encode favicon data as base64 with newlines (Shodan format)
    b64 = base64.encodebytes(data).decode("utf-8")

    # Pure Python MurmurHash3 32-bit
    seed = 0
    key = b64.encode("utf-8")
    length = len(key)
    nblocks = length // 4

    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = (
            key[block_start + 3] << 24
            | key[block_start + 2] << 16
            | key[block_start + 1] << 8
            | key[block_start + 0]
        )
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF
        h1 = (5 * h1 + 0xe6546b64) & 0xFFFFFFFF

    tail_start = nblocks * 4
    tail_size = length & 3
    k1 = 0
    if tail_size >= 3:
        k1 ^= key[tail_start + 2] << 16
    if tail_size >= 2:
        k1 ^= key[tail_start + 1] << 8
    if tail_size >= 1:
        k1 ^= key[tail_start]
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1

    unsigned_val = h1 ^ length
    unsigned_val ^= unsigned_val >> 16
    unsigned_val = (unsigned_val * 0x85ebca6b) & 0xFFFFFFFF
    unsigned_val ^= unsigned_val >> 13
    unsigned_val = (unsigned_val * 0xc2b2ae35) & 0xFFFFFFFF
    unsigned_val ^= unsigned_val >> 16

    # Convert to signed 32-bit
    if unsigned_val >= 0x80000000:
        return unsigned_val - 0x100000000
    return unsigned_val


def _extract_favicon_url(html: str, base_url: str) -> str:
    """Extract favicon URL from HTML."""
    patterns = [
        r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            href = m.group(1)
            if href.startswith("http"):
                return href
            if href.startswith("//"):
                scheme = base_url.split("://")[0]
                return f"{scheme}:{href}"
            base = base_url.rstrip("/")
            return f"{base}/{href.lstrip('/')}"
    # Default
    base = base_url.rstrip("/")
    return f"{base}/favicon.ico"


def favicon_hash(target: str) -> dict:
    """
    Download and compute favicon hashes for a website.
    Returns MurmurHash3 (Shodan), MD5, and SHA256 of the favicon.

    Args:
        target: URL (https://example.com) or domain (example.com)

    Returns:
        Favicon hashes: mmh3 (for Shodan), md5, sha256, base64
    """
    if not target.startswith("http"):
        target = f"https://{target}"

    result = {
        "target": target,
        "analysis_time": datetime.utcnow().isoformat(),
        "favicon_url": None,
        "hashes": {},
        "size_bytes": 0,
    }

    # Fetch homepage to find favicon URL
    html_bytes, code = _fetch(target)
    if code == 0:
        # Try HTTP fallback
        target_http = target.replace("https://", "http://")
        html_bytes, code = _fetch(target_http)
        if code == 0:
            return {"error": f"Cannot reach {target}"}

    html = html_bytes.decode("utf-8", errors="ignore")
    favicon_url = _extract_favicon_url(html, target)
    result["favicon_url"] = favicon_url

    # Fetch favicon
    favicon_bytes, code = _fetch(favicon_url)
    if code == 0 or not favicon_bytes:
        # Try /favicon.ico directly
        base = "/".join(target.split("/")[:3])
        favicon_bytes, code = _fetch(f"{base}/favicon.ico")
        if not favicon_bytes:
            return {"error": "Cannot download favicon", "favicon_url": favicon_url}
        result["favicon_url"] = f"{base}/favicon.ico"

    result["size_bytes"] = len(favicon_bytes)
    result["hashes"] = {
        "mmh3": _mmh3_hash(favicon_bytes),
        "md5": hashlib.md5(favicon_bytes).hexdigest(),
        "sha256": hashlib.sha256(favicon_bytes).hexdigest(),
        "base64": base64.b64encode(favicon_bytes).decode("utf-8")[:100] + "...",
    }

    # Shodan search query
    result["shodan_query"] = f'http.favicon.hash:{result["hashes"]["mmh3"]}'
    result["search_hint"] = (
        f"Shodan: {result['shodan_query']}\n"
        f"ZoomEye: iconhash:{result['hashes']['mmh3']}\n"
        f"Fofa: icon_hash=\"{result['hashes']['mmh3']}\""
    )

    return result


def favicon_search_shodan(favicon_hash_value: int = None, target: str = None,
                           shodan_key: str = None) -> dict:
    """
    Search Shodan for servers sharing the same favicon.
    Useful for finding C2 panels, phishing infrastructure, and asset inventory.

    Args:
        favicon_hash_value: MurmurHash3 value from favicon_hash() (int)
        target: URL/domain to auto-compute hash from (if favicon_hash_value not provided)
        shodan_key: Shodan API key (uses env var SHODAN_API_KEY if not provided)

    Returns:
        Matching Shodan results with IP, port, organization, country
    """
    api_key = shodan_key or os.environ.get("SHODAN_API_KEY")

    # Compute hash if target provided
    if favicon_hash_value is None and target:
        fh = favicon_hash(target)
        if "error" in fh:
            return fh
        favicon_hash_value = fh["hashes"]["mmh3"]

    if favicon_hash_value is None:
        return {"error": "Provide favicon_hash_value or target"}

    if not api_key:
        return {
            "error": "SHODAN_API_KEY not set",
            "hint": "Set env SHODAN_API_KEY or pass shodan_key parameter",
            "manual_query": f"https://www.shodan.io/search?query=http.favicon.hash:{favicon_hash_value}",
            "favicon_hash_mmh3": favicon_hash_value,
        }

    # Query Shodan API
    query = f"http.favicon.hash:{favicon_hash_value}"
    encoded = urllib.parse.quote(query)
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={encoded}&minify=false"

    data, code = _fetch(url, timeout=20)
    if code == 0:
        return {"error": "Shodan API request failed"}

    try:
        resp = json.loads(data)
        matches = []
        for match in resp.get("matches", [])[:50]:
            matches.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org"),
                "country": match.get("location", {}).get("country_name"),
                "city": match.get("location", {}).get("city"),
                "hostnames": match.get("hostnames", []),
                "product": match.get("product"),
                "timestamp": match.get("timestamp"),
            })

        return {
            "favicon_hash_mmh3": favicon_hash_value,
            "query": query,
            "total": resp.get("total", 0),
            "matches": matches,
        }
    except Exception as e:
        return {"error": f"Parse error: {e}", "raw": data[:1000].decode(errors="ignore")}


def favicon_search_zoomeye(favicon_hash_value: int = None, target: str = None,
                            zoomeye_key: str = None) -> dict:
    """
    Search ZoomEye for servers sharing the same favicon.

    Args:
        favicon_hash_value: MurmurHash3 hash from favicon_hash() (int)
        target: URL/domain to auto-compute hash from
        zoomeye_key: ZoomEye API key (uses env ZOOMEYE_API_KEY if not provided)

    Returns:
        Matching ZoomEye results
    """
    api_key = zoomeye_key or os.environ.get("ZOOMEYE_API_KEY")

    if favicon_hash_value is None and target:
        fh = favicon_hash(target)
        if "error" in fh:
            return fh
        favicon_hash_value = fh["hashes"]["mmh3"]

    if favicon_hash_value is None:
        return {"error": "Provide favicon_hash_value or target"}

    if not api_key:
        return {
            "error": "ZOOMEYE_API_KEY not set",
            "manual_query": f"iconhash:{favicon_hash_value}",
            "favicon_hash_mmh3": favicon_hash_value,
        }

    # ZoomEye search
    query = f"iconhash:{favicon_hash_value}"
    encoded = base64.b64encode(query.encode()).decode()
    url = f"https://api.zoomeye.org/host/search?query={urllib.parse.quote(query)}&page=1"

    data, code = _fetch(url, timeout=20, headers={
        "API-KEY": api_key,
        "Content-Type": "application/json",
    })
    if code == 0:
        return {"error": "ZoomEye API request failed"}

    try:
        resp = json.loads(data)
        matches = []
        for match in resp.get("matches", [])[:50]:
            geoinfo = match.get("geoinfo", {})
            matches.append({
                "ip": match.get("ip"),
                "port": match.get("portinfo", {}).get("port"),
                "title": match.get("portinfo", {}).get("title"),
                "country": geoinfo.get("country", {}).get("names", {}).get("en"),
                "city": geoinfo.get("city", {}).get("names", {}).get("en"),
                "org": geoinfo.get("organization"),
            })

        return {
            "favicon_hash_mmh3": favicon_hash_value,
            "query": query,
            "total": resp.get("total", {}).get("value", 0),
            "matches": matches,
        }
    except Exception as e:
        return {"error": f"Parse error: {e}"}


def favicon_search_fofa(favicon_hash_value: int = None, target: str = None,
                         fofa_email: str = None, fofa_key: str = None) -> dict:
    """
    Search Fofa for servers sharing the same favicon.

    Args:
        favicon_hash_value: MurmurHash3 hash from favicon_hash() (int)
        target: URL/domain to auto-compute hash from
        fofa_email: Fofa account email (uses env FOFA_EMAIL if not provided)
        fofa_key: Fofa API key (uses env FOFA_KEY if not provided)

    Returns:
        Matching Fofa results
    """
    email = fofa_email or os.environ.get("FOFA_EMAIL")
    key = fofa_key or os.environ.get("FOFA_KEY")

    if favicon_hash_value is None and target:
        fh = favicon_hash(target)
        if "error" in fh:
            return fh
        favicon_hash_value = fh["hashes"]["mmh3"]

    if favicon_hash_value is None:
        return {"error": "Provide favicon_hash_value or target"}

    if not email or not key:
        return {
            "error": "FOFA_EMAIL and FOFA_KEY not set",
            "manual_query": f'icon_hash="{favicon_hash_value}"',
            "favicon_hash_mmh3": favicon_hash_value,
        }

    query = f'icon_hash="{favicon_hash_value}"'
    b64_query = base64.b64encode(query.encode()).decode()
    url = (f"https://fofa.info/api/v1/search/all?"
           f"email={urllib.parse.quote(email)}&key={key}"
           f"&qbase64={b64_query}&size=50&fields=ip,port,title,country,org")

    data, code = _fetch(url, timeout=20)
    if code == 0:
        return {"error": "Fofa API request failed"}

    try:
        resp = json.loads(data)
        if not resp.get("error"):
            results = resp.get("results", [])
            return {
                "favicon_hash_mmh3": favicon_hash_value,
                "query": query,
                "total": resp.get("size", 0),
                "matches": [
                    {"ip": r[0], "port": r[1], "title": r[2],
                     "country": r[3], "org": r[4]}
                    for r in results[:50] if len(r) >= 5
                ],
            }
        return {"error": resp.get("errmsg", "Unknown Fofa error")}
    except Exception as e:
        return {"error": f"Parse error: {e}"}


def favicon_full_hunt(target: str, shodan_key: str = None,
                       zoomeye_key: str = None) -> dict:
    """
    Full favicon intelligence hunt: compute hashes and search all available platforms.
    Identifies all servers using the same favicon as the target.
    Useful for finding related infrastructure, phishing clones, and C2 panels.

    Args:
        target: URL or domain to investigate
        shodan_key: Optional Shodan API key
        zoomeye_key: Optional ZoomEye API key

    Returns:
        Consolidated results from all search platforms with deduplication
    """
    result = {
        "target": target,
        "hunt_time": datetime.utcnow().isoformat(),
        "hashes": {},
        "platforms": {},
        "all_ips": [],
        "summary": {},
    }

    # Step 1: Get favicon hashes
    fh = favicon_hash(target)
    if "error" in fh:
        return fh

    result["hashes"] = fh["hashes"]
    result["favicon_url"] = fh.get("favicon_url")
    mmh3 = fh["hashes"]["mmh3"]

    # Step 2: Search all platforms
    result["platforms"]["shodan"] = favicon_search_shodan(
        mmh3, shodan_key=shodan_key
    )
    result["platforms"]["zoomeye"] = favicon_search_zoomeye(
        mmh3, zoomeye_key=zoomeye_key
    )

    # Step 3: Aggregate IPs
    all_ips = set()
    for platform, data in result["platforms"].items():
        for match in data.get("matches", []):
            if match.get("ip"):
                all_ips.add(match["ip"])

    result["all_ips"] = sorted(all_ips)

    # Step 4: Summary
    result["summary"] = {
        "favicon_hash_mmh3": mmh3,
        "total_unique_ips": len(all_ips),
        "shodan_query": f"http.favicon.hash:{mmh3}",
        "zoomeye_query": f"iconhash:{mmh3}",
        "fofa_query": f'icon_hash="{mmh3}"',
        "censys_hint": f'services.http.response.favicons.md5_hash={fh["hashes"]["md5"]}',
    }

    # Save report
    outfile = os.path.join(
        RESULTS_DIR,
        f"favicon_{target.replace('/', '_').replace(':', '_')}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    )
    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)
    result["report_file"] = outfile

    return result


TOOLS = {
    "favicon_hash": favicon_hash,
    "favicon_search_shodan": favicon_search_shodan,
    "favicon_search_zoomeye": favicon_search_zoomeye,
    "favicon_search_fofa": favicon_search_fofa,
    "favicon_full_hunt": favicon_full_hunt,
}
