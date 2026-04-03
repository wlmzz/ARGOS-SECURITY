"""Advanced OSINT tools: theHarvester, Sherlock, ipwhois, email/domain recon."""
from __future__ import annotations
import subprocess, json, re, os
from typing import Any


def _run(cmd: list[str], timeout: int = 60, env: dict | None = None) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return (r.stdout + r.stderr).strip()[:8000]
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return f"[TOOL NOT FOUND: {cmd[0]}] — run: installer/install.sh"
    except Exception as e:
        return f"[ERROR: {e}]"


def theharvester_scan(domain: str, sources: str = "all", limit: int = 200) -> dict:
    """Harvest emails, subdomains, hosts, and URLs for a domain using theHarvester.
    sources: comma-separated list or 'all'. Options: google, bing, linkedin, dnsdumpster,
             hackertarget, rapiddns, securitytrails, shodan, urlscan, etc.
    Returns emails, subdomains, IPs, and hosts found.
    """
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", domain):
        return {"error": "Invalid domain format"}
    safe_sources = re.sub(r"[^a-zA-Z0-9,_\-]", "", sources) or "all"
    limit = min(max(10, limit), 500)

    cmd = ["theHarvester", "-d", domain, "-b", safe_sources, "-l", str(limit), "-f", "/tmp/argos_harvest"]
    raw = _run(cmd, timeout=120)

    # Also try to read JSON output if written
    result = {"tool": "theHarvester", "domain": domain, "sources": safe_sources}
    try:
        import pathlib
        jf = pathlib.Path("/tmp/argos_harvest.json")
        if jf.exists():
            data = json.loads(jf.read_text())
            result["emails"] = data.get("emails", [])[:50]
            result["hosts"] = data.get("hosts", [])[:50]
            result["ips"] = data.get("ips", [])[:50]
            result["urls"] = data.get("urls", [])[:30]
            jf.unlink(missing_ok=True)
            return result
    except Exception:
        pass

    # Fallback: parse text output
    emails = list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw)))
    hosts = list(set(re.findall(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b", raw)))
    ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)))
    result.update({"emails": emails[:50], "hosts": hosts[:50], "ips": ips[:30], "raw": raw[:2000]})
    return result


def sherlock_search(username: str) -> dict:
    """Search for a username across 400+ social networks and websites using Sherlock.
    Returns list of sites where the username exists.
    Useful for attribution: find attacker's online presence from a handle/alias.
    """
    if not re.match(r"^[a-zA-Z0-9_\.\-]{1,50}$", username):
        return {"error": "Invalid username format"}

    cmd = ["python3", "-m", "sherlock", username, "--print-found", "--timeout", "10", "--output", "/tmp/sherlock_out.txt"]
    raw = _run(cmd, timeout=120)

    found_sites = []
    for line in raw.splitlines():
        if line.startswith("[+]"):
            url = line.replace("[+]", "").strip()
            found_sites.append(url)

    # Also try reading output file
    try:
        import pathlib
        of = pathlib.Path("/tmp/sherlock_out.txt")
        if of.exists():
            for line in of.read_text().splitlines():
                url = line.strip()
                if url.startswith("http") and url not in found_sites:
                    found_sites.append(url)
            of.unlink(missing_ok=True)
    except Exception:
        pass

    return {
        "tool": "sherlock",
        "username": username,
        "found_count": len(found_sites),
        "profiles": found_sites[:100],
    }


def ipwhois_lookup(ip: str) -> dict:
    """Full WHOIS/RDAP lookup for an IP: owner org, abuse contact, country, ASN, network range.
    More detailed than ip_reputation — returns abuse email for reporting to ISP.
    """
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        asn_data = {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country": result.get("asn_country_code"),
            "asn_cidr": result.get("asn_cidr"),
            "asn_registry": result.get("asn_registry"),
        }
        # Extract abuse contact emails
        abuse_emails = []
        for key, entity in result.get("objects", {}).items():
            roles = entity.get("roles", [])
            if "abuse" in roles or "technical" in roles:
                contact = entity.get("contact", {})
                for email_entry in contact.get("email", []):
                    if isinstance(email_entry, dict):
                        abuse_emails.append(email_entry.get("value", ""))
                    else:
                        abuse_emails.append(str(email_entry))
        return {
            "ip": ip,
            "tool": "ipwhois",
            "network_name": result.get("network", {}).get("name"),
            "network_cidr": result.get("network", {}).get("cidr"),
            "country": result.get("network", {}).get("country"),
            "abuse_contacts": list(set(e for e in abuse_emails if "@" in e))[:5],
            "asn": asn_data,
        }
    except ImportError:
        return {"error": "ipwhois not installed — run: pip install ipwhois"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains for a domain using passive DNS sources (crt.sh, hackertarget).
    No active scanning — purely passive OSINT.
    """
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", domain):
        return {"error": "Invalid domain format"}

    import urllib.request, urllib.error
    subdomains = set()

    # crt.sh (Certificate Transparency logs)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except Exception:
        pass

    # hackertarget
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            for line in r.read().decode().splitlines():
                parts = line.split(",")
                if parts and parts[0].endswith(domain):
                    subdomains.add(parts[0])
    except Exception:
        pass

    return {
        "tool": "subdomain_enum",
        "domain": domain,
        "sources": ["crt.sh", "hackertarget"],
        "subdomain_count": len(subdomains),
        "subdomains": sorted(subdomains)[:100],
    }


TOOLS = {
    "theharvester_scan": {
        "fn": theharvester_scan,
        "description": (
            "Harvest emails, subdomains, hosts, and IPs for a domain using theHarvester. "
            "Sources include Google, Bing, LinkedIn, DNSDumpster, Shodan, URLscan, and more. "
            "Useful for mapping the attack surface of a target or investigating a domain."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain to harvest (e.g. 'example.com')"},
                "sources": {"type": "string", "description": "Data sources: 'all' or comma-separated: 'google,bing,linkedin'. Default: all"},
                "limit": {"type": "integer", "description": "Max results per source (10-500). Default: 200"}
            },
            "required": ["domain"]
        }
    },
    "sherlock_search": {
        "fn": sherlock_search,
        "description": (
            "Search for a username across 400+ websites and social networks (Sherlock). "
            "Use for attacker attribution: if you have a handle/alias from a log or intrusion, "
            "find their online presence on GitHub, Twitter, Reddit, Telegram, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username or handle to search (e.g. 'h4cker_x99')"}
            },
            "required": ["username"]
        }
    },
    "ipwhois_lookup": {
        "fn": ipwhois_lookup,
        "description": (
            "Full WHOIS/RDAP lookup for an IP address: owning organization, network range, ASN, "
            "country, and abuse contact email. Use to find the ISP to report an attacker to."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    "subdomain_enum": {
        "fn": subdomain_enum,
        "description": (
            "Passively enumerate subdomains for a domain using Certificate Transparency logs (crt.sh) "
            "and hackertarget. No active scanning — safe to use for any domain."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to enumerate subdomains for"}
            },
            "required": ["domain"]
        }
    }
}
