"""
ARGOS Plugin: IP Investigator
Investigazione completa di IP ostili: geolocalizzazione, WHOIS, threat intel
multi-source, analisi pattern attacchi dai log di ARGOS.
Funziona senza API key (usa endpoint pubblici gratuiti).
"""
from __future__ import annotations
import json, re, os, subprocess, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import Any

MANIFEST = {
    "id":          "ip-investigator",
    "name":        "IP Investigator",
    "description": "Investigazione completa IP: geo, ASN, WHOIS, ThreatFox, URLHaus, MalwareBazaar, pattern analisi attacchi dai log ARGOS. Zero API key richieste.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_WATCHER_LOG = "/opt/argos/logs/watcher.log"
_PROFILES_LOG = "/opt/argos/logs/ip_profiles.jsonl"


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 12) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-Investigator/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}

def _post(url: str, payload: dict, timeout: int = 12) -> dict:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "ARGOS-Investigator/1.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


# ── Core enrichment ──────────────────────────────────────────────────────────

def _geo_asn(ip: str) -> dict:
    """ip-api.com — geo + ASN + proxy/hosting detection (no key, 45 req/min)."""
    fields = "status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile,query"
    data = _get(f"http://ip-api.com/json/{ip}?fields={fields}")
    if data.get("status") == "fail":
        return {"error": data.get("message", "ip-api failed")}
    return {
        "ip":       data.get("query", ip),
        "country":  f"{data.get('country', '?')} ({data.get('countryCode', '?')})",
        "city":     data.get("city", "?"),
        "region":   data.get("regionName", "?"),
        "isp":      data.get("isp", "?"),
        "org":      data.get("org", "?"),
        "asn":      data.get("as", "?"),
        "is_hosting": data.get("hosting", False),
        "is_proxy":   data.get("proxy", False),
        "is_mobile":  data.get("mobile", False),
    }

def _ipinfo(ip: str) -> dict:
    """ipinfo.io — hostname, org (no key, 50k/mese)."""
    data = _get(f"https://ipinfo.io/{ip}/json")
    return {
        "hostname": data.get("hostname", "-"),
        "org":      data.get("org", "-"),
        "abuse":    data.get("abuse", {}).get("email", "-") if isinstance(data.get("abuse"), dict) else "-",
    }

def _whois(ip: str) -> dict:
    """whois locale."""
    try:
        out = subprocess.check_output(["whois", ip], timeout=15,
                                      stderr=subprocess.DEVNULL).decode(errors="replace")
        relevant = {}
        for line in out.splitlines():
            for key in ["netname", "descr", "org-name", "country", "abuse-mailbox", "route", "mnt-by"]:
                if line.lower().startswith(key + ":"):
                    val = line.split(":", 1)[1].strip()
                    if val and key not in relevant:
                        relevant[key] = val
        return relevant
    except Exception as e:
        return {"error": str(e)}

def _threatfox(ip: str) -> dict:
    """ThreatFox (abuse.ch) — cerca IP nel database IOC."""
    res = _post("https://threatfox-api.abuse.ch/api/v1/", {"query": "search_ioc", "search_term": ip})
    iocs = res.get("data", [])
    if not iocs or res.get("query_status") == "no_result":
        return {"found": False}
    return {
        "found": True,
        "count": len(iocs),
        "malware": list({i.get("malware_printable", "?") for i in iocs[:5]}),
        "tags":    list({t for i in iocs[:5] for t in (i.get("tags") or [])}),
        "first_seen": iocs[-1].get("first_seen", "?"),
        "last_seen":  iocs[0].get("last_seen", "?"),
        "threat_type": iocs[0].get("threat_type_desc", "?"),
        "confidence": iocs[0].get("confidence_level", "?"),
    }

def _urlhaus(ip: str) -> dict:
    """URLHaus (abuse.ch) — cerca URL malware associati all'IP."""
    res = _post("https://urlhaus-api.abuse.ch/v1/host/", {"host": ip})
    if res.get("query_status") == "no_results":
        return {"found": False}
    urls = res.get("urls", [])
    return {
        "found": bool(urls),
        "count": len(urls),
        "urls":  [{"url": u.get("url", ""), "status": u.get("url_status", ""),
                   "threat": u.get("threat", ""), "tags": u.get("tags", [])}
                  for u in urls[:5]],
    }

def _abuseipdb(ip: str) -> dict:
    """AbuseIPDB — richiede API key ma prova lo stesso."""
    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return {"skipped": "No ABUSEIPDB_API_KEY set"}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.loads(r.read().decode()).get("data", {})
        return {
            "score":        d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", "-"),
            "usage_type":   d.get("usageType", "-"),
            "domain":       d.get("domain", "-"),
            "is_whitelisted": d.get("isWhitelisted", False),
        }
    except Exception as e:
        return {"error": str(e)}

def _virustotal(ip: str) -> dict:
    """VirusTotal — richiede API key."""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"skipped": "No VIRUSTOTAL_API_KEY set"}
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key})
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.loads(r.read().decode()).get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        return {
            "malicious":    stats.get("malicious", 0),
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless", 0),
            "as_owner":     d.get("as_owner", "-"),
            "reputation":   d.get("reputation", 0),
            "country":      d.get("country", "-"),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Analisi log ARGOS ────────────────────────────────────────────────────────

def _parse_watcher_log(hours: int = 24) -> list[dict]:
    """Legge watcher.log e restituisce tutti gli eventi HIT/BANNED."""
    events = []
    log_path = Path(_WATCHER_LOG)
    if not log_path.exists():
        return events
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - hours * 3600
    with open(log_path, "r", errors="replace") as f:
        for line in f:
            m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?(HIT|BANNED)\s+([\d\.]+)", line)
            if not m:
                continue
            ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if ts.timestamp() < cutoff:
                continue
            events.append({
                "timestamp": m.group(1),
                "type":      m.group(2),
                "ip":        m.group(3),
                "line":      line.strip(),
            })
    return events


# ── Tools pubblici ───────────────────────────────────────────────────────────

def investigate_ip(ip: str) -> dict:
    """
    Profilo completo di un IP: geolocalizzazione, ASN, WHOIS, ThreatFox,
    URLHaus, AbuseIPDB (se key), VirusTotal (se key).
    Funziona senza API key usando endpoint pubblici gratuiti.
    """
    ip = ip.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": f"IP non valido: {ip}"}

    profile = {
        "ip":         ip,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "geo":        _geo_asn(ip),
        "ipinfo":     _ipinfo(ip),
        "whois":      _whois(ip),
        "threatfox":  _threatfox(ip),
        "urlhaus":    _urlhaus(ip),
        "abuseipdb":  _abuseipdb(ip),
        "virustotal": _virustotal(ip),
    }

    # Verdetto automatico
    threat_score = 0
    reasons = []
    if profile["geo"].get("is_hosting"):
        threat_score += 20; reasons.append("VPS/hosting (tipico botnet)")
    if profile["geo"].get("is_proxy"):
        threat_score += 25; reasons.append("proxy/VPN rilevato")
    if profile["threatfox"].get("found"):
        threat_score += 40; reasons.append(f"ThreatFox: {profile['threatfox'].get('malware', [])}")
    if profile["urlhaus"].get("found"):
        threat_score += 35; reasons.append(f"URLHaus: {profile['urlhaus'].get('count', 0)} URL malware")
    abuse = profile["abuseipdb"]
    if isinstance(abuse, dict) and abuse.get("score", 0) > 50:
        threat_score += abuse["score"] // 2; reasons.append(f"AbuseIPDB score: {abuse['score']}")
    vt = profile["virustotal"]
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        threat_score += vt["malicious"] * 3; reasons.append(f"VirusTotal: {vt['malicious']} detection")

    profile["verdict"] = {
        "threat_score": min(threat_score, 100),
        "level": "CRITICAL" if threat_score >= 60 else "HIGH" if threat_score >= 30 else "MEDIUM" if threat_score >= 10 else "LOW",
        "reasons": reasons,
    }

    # Salva in profiles log
    try:
        with open(_PROFILES_LOG, "a") as f:
            f.write(json.dumps(profile) + "\n")
    except Exception:
        pass

    return profile


def investigate_attackers(hours: int = 24, top_n: int = 10) -> dict:
    """
    Legge i log ARGOS delle ultime N ore, identifica i principali attaccanti
    e fa enrichment completo su ognuno. Restituisce report investigativo.
    """
    events = _parse_watcher_log(hours)
    if not events:
        return {"message": f"Nessun evento nelle ultime {hours}h", "events": 0}

    # Conta attacchi per IP
    ip_counts: dict[str, int] = defaultdict(int)
    ip_banned: set[str] = set()
    ip_usernames: dict[str, set] = defaultdict(set)
    ip_types: dict[str, set] = defaultdict(set)

    for ev in events:
        ip = ev["ip"]
        ip_counts[ip] += 1
        if ev["type"] == "BANNED":
            ip_banned.add(ip)
        m_user = re.search(r"Invalid user (\S+)", ev["line"])
        if m_user:
            ip_usernames[ip].add(m_user.group(1))
        m_type = re.search(r"(BRUTE_FORCE|SQL_INJECTION|XSS|CMD_INJECTION|REVERSE_SHELL|PORT_SCAN)", ev["line"])
        if m_type:
            ip_types[ip].add(m_type.group(1))

    # Top N attaccanti
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    results = []
    for ip, count in top_ips:
        profile = investigate_ip(ip)
        results.append({
            "ip":        ip,
            "hits":      count,
            "banned":    ip in ip_banned,
            "usernames": list(ip_usernames.get(ip, set()))[:10],
            "attack_types": list(ip_types.get(ip, set())),
            "geo":       profile.get("geo", {}),
            "verdict":   profile.get("verdict", {}),
            "threatfox": profile.get("threatfox", {}),
            "urlhaus":   profile.get("urlhaus", {}),
            "whois":     profile.get("whois", {}),
        })

    return {
        "period_hours":   hours,
        "total_events":   len(events),
        "unique_ips":     len(ip_counts),
        "total_banned":   len(ip_banned),
        "top_attackers":  results,
    }


def analyze_attack_patterns(hours: int = 24) -> dict:
    """
    Analisi avanzata dei pattern di attacco: timing, username usati,
    subnet coordination, botnet detection, campagne coordinate.
    """
    events = _parse_watcher_log(hours)
    if not events:
        return {"message": f"Nessun evento nelle ultime {hours}h"}

    # Analisi username
    all_usernames: list[str] = []
    for ev in events:
        m = re.search(r"Invalid user (\S+)", ev["line"])
        if m:
            all_usernames.append(m.group(1))

    username_counts: dict[str, int] = defaultdict(int)
    for u in all_usernames:
        username_counts[u] += 1

    # Subnet analysis (/24)
    subnet_ips: dict[str, list[str]] = defaultdict(list)
    ip_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        ip = ev["ip"]
        ip_counts[ip] += 1
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        if ip not in subnet_ips[subnet]:
            subnet_ips[subnet].append(ip)

    coordinated_subnets = {s: ips for s, ips in subnet_ips.items() if len(ips) > 1}

    # ASN grouping via ip-api batch (max 100)
    top_ips = [ip for ip, _ in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]]
    asn_groups: dict[str, list[str]] = defaultdict(list)
    for ip in top_ips:
        geo = _geo_asn(ip)
        asn = geo.get("asn", "unknown")
        asn_groups[asn].append(ip)
    coordinated_asns = {asn: ips for asn, ips in asn_groups.items() if len(ips) > 1}

    # Timing: attacchi per ora
    hourly: dict[str, int] = defaultdict(int)
    for ev in events:
        hour = ev["timestamp"][:13]  # "2026-04-03 02"
        hourly[hour] += 1
    peak_hour = max(hourly.items(), key=lambda x: x[1]) if hourly else ("?", 0)

    # Top username categories
    crypto_users = [u for u in username_counts if any(k in u.lower() for k in ["sol", "eth", "btc", "crypto", "wallet", "trade", "defi", "ray", "fire"])]
    generic_users = [u for u in username_counts if any(k in u.lower() for k in ["user", "test", "admin", "root", "guest", "ubuntu", "pi", "ftp"])]
    service_users = [u for u in username_counts if any(k in u.lower() for k in ["mysql", "postgres", "redis", "nginx", "apache", "nagios", "jenkins"])]

    return {
        "period_hours":     hours,
        "total_events":     len(events),
        "unique_ips":       len(ip_counts),
        "top_usernames":    dict(sorted(username_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "username_categories": {
            "crypto_targeting": crypto_users[:10],
            "generic_bruteforce": generic_users[:10],
            "service_targeting": service_users[:10],
        },
        "peak_attack_hour": {"hour": peak_hour[0], "events": peak_hour[1]},
        "hourly_distribution": dict(sorted(hourly.items())),
        "coordinated_attacks": {
            "by_subnet_24": coordinated_subnets,
            "by_asn":       coordinated_asns,
        },
        "top_ips": dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def get_ip_profiles(limit: int = 20) -> dict:
    """
    Restituisce i profili IP salvati da precedenti investigazioni
    (da /opt/argos/logs/ip_profiles.jsonl).
    """
    path = Path(_PROFILES_LOG)
    if not path.exists():
        return {"message": "Nessun profilo salvato ancora", "profiles": []}
    profiles = []
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()
    for line in lines[-limit:]:
        try:
            profiles.append(json.loads(line))
        except Exception:
            pass
    return {"count": len(profiles), "profiles": profiles}


def enrich_banned_ips() -> dict:
    """
    Arricchisce con threat intel tutti gli IP attualmente bannati da fail2ban
    che non hanno ancora un profilo salvato.
    """
    # Legge IP bannati da fail2ban
    try:
        out = subprocess.check_output(
            ["fail2ban-client", "status", "ssh"], timeout=10,
            stderr=subprocess.DEVNULL).decode()
        m = re.search(r"Banned IP list:\s*(.+)", out)
        banned_ips = m.group(1).split() if m else []
    except Exception:
        banned_ips = []

    # Anche recidive
    try:
        out2 = subprocess.check_output(
            ["fail2ban-client", "status", "recidive"], timeout=10,
            stderr=subprocess.DEVNULL).decode()
        m2 = re.search(r"Banned IP list:\s*(.+)", out2)
        if m2:
            banned_ips.extend(m2.group(1).split())
    except Exception:
        pass

    # Carica profili già esistenti
    existing = set()
    path = Path(_PROFILES_LOG)
    if path.exists():
        with open(path, "r", errors="replace") as f:
            for line in f:
                try:
                    existing.add(json.loads(line)["ip"])
                except Exception:
                    pass

    results = []
    for ip in set(banned_ips):
        if ip in existing:
            results.append({"ip": ip, "status": "already_profiled"})
            continue
        profile = investigate_ip(ip)
        results.append({
            "ip":      ip,
            "verdict": profile.get("verdict", {}),
            "geo":     profile.get("geo", {}),
        })

    return {
        "total_banned": len(banned_ips),
        "newly_profiled": sum(1 for r in results if r.get("status") != "already_profiled"),
        "results": results,
    }


TOOLS = {
    "investigate_ip": {
        "fn": investigate_ip,
        "description": (
            "Profilo completo di un IP: geolocalizzazione, ASN, WHOIS, ThreatFox, URLHaus, "
            "AbuseIPDB (se key), VirusTotal (se key). Verdetto automatico con threat score. "
            "Funziona senza API key."
        ),
        "parameters": {
            "ip": {"type": "string", "description": "Indirizzo IP da investigare", "required": True},
        },
    },
    "investigate_attackers": {
        "fn": investigate_attackers,
        "description": (
            "Legge i log ARGOS delle ultime N ore, identifica i principali attaccanti "
            "e fa enrichment completo (geo, ASN, threat intel) su ognuno. "
            "Usa per rispondere a 'chi ci ha attaccato stanotte?'"
        ),
        "parameters": {
            "hours": {"type": "integer", "description": "Quante ore analizzare (default: 24)", "required": False},
            "top_n": {"type": "integer", "description": "Quanti top attaccanti investigare (default: 10)", "required": False},
        },
    },
    "analyze_attack_patterns": {
        "fn": analyze_attack_patterns,
        "description": (
            "Analisi avanzata dei pattern di attacco: username usati, campagne coordinate, "
            "subnet/ASN correlation, timing, distinzione botnet crypto vs generica."
        ),
        "parameters": {
            "hours": {"type": "integer", "description": "Finestra temporale in ore (default: 24)", "required": False},
        },
    },
    "get_ip_profiles": {
        "fn": get_ip_profiles,
        "description": "Restituisce i profili IP investigati e salvati in precedenza.",
        "parameters": {
            "limit": {"type": "integer", "description": "Quanti profili recenti restituire (default: 20)", "required": False},
        },
    },
    "enrich_banned_ips": {
        "fn": enrich_banned_ips,
        "description": (
            "Arricchisce con threat intel tutti gli IP attualmente bannati da fail2ban "
            "che non hanno ancora un profilo. Utile dopo un'ondata di attacchi."
        ),
        "parameters": {},
    },
}
