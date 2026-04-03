"""Attacker attribution tools: AbuseIPDB, ASN lookup, dossier builder, law enforcement report."""
from __future__ import annotations
import json, re, os, hashlib, urllib.request, urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _http_get(url: str, headers: dict | None = None, timeout: int = 10) -> dict | str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-SecurityAgent/1.0", **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "")
            raw = r.read().decode()
            if "json" in ct or raw.strip().startswith("{") or raw.strip().startswith("["):
                return json.loads(raw)
            return raw
    except Exception as e:
        return {"error": str(e)}


def abuseipdb_check(ip: str, max_age_days: int = 90) -> dict:
    """Check an IP on AbuseIPDB: abuse confidence score, total reports, categories, recent reports.
    Requires ABUSEIPDB_API_KEY env var (free tier: 1000 checks/day at abuseipdb.com).
    Returns: confidence score (0-100), country, ISP, usage type, attack categories.
    """
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        # Fallback: use free public check without key (limited)
        data = _http_get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={max_age_days}",
                        headers={"Key": "", "Accept": "application/json"})
        if isinstance(data, dict) and "errors" in data:
            return {"error": "ABUSEIPDB_API_KEY env var not set. Get free key at abuseipdb.com/register"}
    else:
        data = _http_get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose",
            headers={"Key": api_key, "Accept": "application/json"}
        )

    if isinstance(data, dict) and "data" in data:
        d = data["data"]
        # Category mapping (AbuseIPDB categories)
        cat_map = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
            5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
            9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
            13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
            17: "Spoofing", 18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
            21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
        }
        categories_seen = set()
        for report in d.get("reports", [])[:5]:
            for cat_id in report.get("categories", []):
                categories_seen.add(cat_map.get(cat_id, f"Cat-{cat_id}"))

        return {
            "ip": ip,
            "source": "AbuseIPDB",
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "distinct_users_reporting": d.get("numDistinctUsers"),
            "last_reported": d.get("lastReportedAt"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor"),
            "attack_categories": list(categories_seen),
            "recent_reports": [
                {"reported_at": r.get("reportedAt"), "comment": r.get("comment", "")[:200],
                 "categories": [cat_map.get(c, str(c)) for c in r.get("categories", [])]}
                for r in d.get("reports", [])[:5]
            ],
        }
    return {"ip": ip, "error": "Could not retrieve AbuseIPDB data", "raw": str(data)[:500]}


def abuseipdb_report(ip: str, categories: list[int], comment: str) -> dict:
    """Report a malicious IP to AbuseIPDB. Requires ABUSEIPDB_API_KEY env var.
    categories: list of category IDs. Common: 18=Brute-Force, 22=SSH, 15=Hacking, 21=Web App Attack.
    comment: description of the attack (timestamps, attack type, log snippets).
    This contributes to the global threat database used by 700,000+ organizations.
    """
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY env var not set. Get free key at abuseipdb.com/register"}
    if not categories or not comment:
        return {"error": "categories and comment are required"}
    comment = comment[:1024]
    try:
        payload = urllib.parse.urlencode({
            "ip": ip,
            "categories": ",".join(str(c) for c in categories),
            "comment": comment,
        }).encode()
        req = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/report",
            data=payload,
            headers={"Key": api_key, "Accept": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        if "data" in data:
            return {
                "success": True,
                "ip": ip,
                "new_score": data["data"].get("abuseConfidenceScore"),
                "message": "IP successfully reported to AbuseIPDB",
            }
        return {"success": False, "response": data}
    except Exception as e:
        return {"error": str(e)}


def build_attacker_dossier(ip: str) -> dict:
    """Build a complete attacker dossier for an IP address.
    Aggregates: geolocation, ASN, Shodan data, AbuseIPDB score, WHOIS/RDAP, abuse contacts.
    Returns a structured profile suitable for law enforcement reporting.
    """
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": "Invalid IP address"}

    dossier: dict = {"ip": ip, "generated_at": datetime.now(timezone.utc).isoformat(), "sources": []}

    # 1. Geo + ASN (ip-api.com)
    geo = _http_get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,hosting,proxy,mobile")
    if isinstance(geo, dict) and geo.get("status") == "success":
        dossier["geolocation"] = {
            "country": geo.get("country"),
            "country_code": geo.get("countryCode"),
            "region": geo.get("regionName"),
            "city": geo.get("city"),
            "coordinates": f"{geo.get('lat')}, {geo.get('lon')}",
            "isp": geo.get("isp"),
            "organization": geo.get("org"),
            "asn": geo.get("as"),
            "asn_name": geo.get("asname"),
            "is_hosting": geo.get("hosting"),
            "is_proxy_vpn": geo.get("proxy"),
        }
        dossier["sources"].append("ip-api.com")

    # 2. Shodan InternetDB (free)
    shodan = _http_get(f"https://internetdb.shodan.io/{ip}")
    if isinstance(shodan, dict) and "ports" in shodan:
        dossier["exposed_services"] = {
            "open_ports": shodan.get("ports", []),
            "hostnames": shodan.get("hostnames", []),
            "known_cves": shodan.get("vulns", []),
            "tags": shodan.get("tags", []),
            "cpes": shodan.get("cpes", []),
        }
        dossier["sources"].append("Shodan InternetDB")

    # 3. WHOIS/RDAP for abuse contact
    try:
        from ipwhois import IPWhois
        rdap = IPWhois(ip).lookup_rdap(depth=1)
        abuse_emails = []
        for _, entity in rdap.get("objects", {}).items():
            if "abuse" in entity.get("roles", []):
                for email in entity.get("contact", {}).get("email", []):
                    if isinstance(email, dict):
                        abuse_emails.append(email.get("value", ""))
                    else:
                        abuse_emails.append(str(email))
        dossier["network_registration"] = {
            "network_name": rdap.get("network", {}).get("name"),
            "network_cidr": rdap.get("network", {}).get("cidr"),
            "asn": rdap.get("asn"),
            "asn_description": rdap.get("asn_description"),
            "registry": rdap.get("asn_registry"),
            "abuse_contacts": list(set(e for e in abuse_emails if "@" in e)),
        }
        dossier["sources"].append("RDAP/WHOIS")
    except Exception:
        pass

    # 4. AbuseIPDB
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if api_key:
        abuse = abuseipdb_check(ip)
        if "abuse_confidence_score" in abuse:
            dossier["abuse_history"] = {
                "confidence_score": abuse.get("abuse_confidence_score"),
                "total_reports": abuse.get("total_reports"),
                "distinct_reporters": abuse.get("distinct_users_reporting"),
                "attack_types": abuse.get("attack_categories"),
                "last_reported": abuse.get("last_reported"),
            }
            dossier["sources"].append("AbuseIPDB")

    # 5. Threat assessment
    threat_score = 0
    indicators = []
    geo_data = dossier.get("geolocation", {})
    if geo_data.get("is_hosting"):
        threat_score += 20
        indicators.append("Hosted on datacenter/VPS infrastructure")
    if geo_data.get("is_proxy_vpn"):
        threat_score += 30
        indicators.append("Using proxy or VPN")
    exposed = dossier.get("exposed_services", {})
    if exposed.get("known_cves"):
        threat_score += 25
        indicators.append(f"Host has known CVEs: {', '.join(exposed['known_cves'][:3])}")
    abuse = dossier.get("abuse_history", {})
    if abuse.get("confidence_score", 0) > 50:
        threat_score += 25
        indicators.append(f"AbuseIPDB score: {abuse['confidence_score']}/100 ({abuse.get('total_reports')} reports)")

    dossier["threat_assessment"] = {
        "threat_score": min(threat_score, 100),
        "threat_level": "HIGH" if threat_score >= 60 else "MEDIUM" if threat_score >= 30 else "LOW",
        "indicators": indicators,
    }

    return dossier


def generate_leo_report(attack_summary: dict) -> dict:
    """Generate a formal incident report for law enforcement.
    attack_summary: dict with keys:
      - 'ips': list of attacker IPs
      - 'attack_types': list of attack type strings
      - 'start_time': ISO timestamp of first attack
      - 'end_time': ISO timestamp of last attack
      - 'total_attempts': int
      - 'log_excerpts': list of raw log lines (for evidence)
      - 'server_info': dict with 'hostname', 'ip', 'location'
    Returns a structured report with dossiers, evidence hashes, and reporting guidance.
    """
    now = datetime.now(timezone.utc)
    report_id = f"ARGOS-LEO-{now.strftime('%Y%m%d-%H%M%S')}"

    ips = attack_summary.get("ips", [])
    log_excerpts = attack_summary.get("log_excerpts", [])

    # Hash evidence for chain of custody
    evidence_hash = hashlib.sha256(
        json.dumps(log_excerpts, sort_keys=True).encode()
    ).hexdigest()

    # Build dossiers for top IPs
    dossiers = []
    for ip in ips[:10]:
        dossier = build_attacker_dossier(ip)
        dossiers.append(dossier)

    # Collect all abuse contacts
    abuse_contacts = set()
    for d in dossiers:
        for email in d.get("network_registration", {}).get("abuse_contacts", []):
            abuse_contacts.add(email)

    # MITRE ATT&CK mapping
    mitre_map = {
        "BRUTE_FORCE": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        "SQL_INJECTION": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "PATH_TRAVERSAL": {"technique": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        "XSS": {"technique": "T1059.007", "name": "JavaScript Injection", "tactic": "Execution"},
        "CMD_INJECTION": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "REVERSE_SHELL": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "RANSOMWARE": {"technique": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        "CREDENTIAL_DUMP": {"technique": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
        "DOWNLOAD_EXEC": {"technique": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    }
    attack_types = attack_summary.get("attack_types", [])
    mitre_techniques = [mitre_map[t] for t in attack_types if t in mitre_map]

    report = {
        "report_id": report_id,
        "classification": "INCIDENT REPORT — FOR LAW ENFORCEMENT USE",
        "generated_at": now.isoformat(),
        "generated_by": "ARGOS Autonomous Cybersecurity Agent",

        "incident_summary": {
            "type": "Unauthorized Access Attempt / Cyber Attack",
            "attack_types": attack_types,
            "period": {
                "start": attack_summary.get("start_time", "unknown"),
                "end": attack_summary.get("end_time", now.isoformat()),
            },
            "total_attempts": attack_summary.get("total_attempts", 0),
            "attacker_ips": ips,
            "victim_server": attack_summary.get("server_info", {}),
        },

        "mitre_attack_mapping": mitre_techniques,

        "attacker_profiles": dossiers,

        "evidence": {
            "log_excerpts": log_excerpts[:20],
            "evidence_sha256": evidence_hash,
            "chain_of_custody_note": (
                f"Evidence hash SHA256:{evidence_hash} generated at {now.isoformat()} "
                "by ARGOS automated system. Original logs retained at /var/log/ on victim server."
            ),
        },

        "isp_abuse_contacts": list(abuse_contacts),

        "recommended_actions": [
            "1. File a report with your national CERT (IT: CSIRT-IT cert.gov.it, EU: ENISA, US: CISA cisa.gov)",
            "2. Contact each ISP's abuse team via the emails listed in isp_abuse_contacts",
            "3. File a report at AbuseIPDB (abuseipdb.com) for each attacker IP",
            "4. If financial damage occurred, file with local cybercrime police unit",
            f"5. Share this report and log evidence — evidence hash: SHA256:{evidence_hash[:16]}...",
        ],

        "reporting_agencies": {
            "Italy": "CSIRT-IT — cert.gov.it | Polizia Postale — commissariatodips.it",
            "EU": "ENISA — enisa.europa.eu | Europol EC3 — europol.europa.eu/about-europol/european-cybercrime-centre-ec3",
            "International": "IC3 (FBI) — ic3.gov | Interpol cybercrime — interpol.int",
            "AbuseIPDB": "abuseipdb.com/report — community threat database",
        },
    }

    # Save report to disk
    report_dir = Path("/opt/argos/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{report_id}.json"
    try:
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        report["saved_to"] = str(report_path)
    except Exception:
        pass

    return report


TOOLS = {
    "abuseipdb_check": {
        "fn": abuseipdb_check,
        "description": (
            "Check an IP on AbuseIPDB: abuse confidence score (0-100), total reports from the global community, "
            "attack categories (brute force, SSH, web attack...), recent reports with comments. "
            "Requires ABUSEIPDB_API_KEY env var (free at abuseipdb.com)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
                "max_age_days": {"type": "integer", "description": "How many days back to look (default: 90)"}
            },
            "required": ["ip"]
        }
    },
    "abuseipdb_report": {
        "fn": abuseipdb_report,
        "description": (
            "Report a malicious IP to AbuseIPDB's global database (used by 700,000+ orgs). "
            "Categories: 18=Brute-Force, 22=SSH, 15=Hacking, 21=Web App Attack, 14=Port Scan. "
            "Requires ABUSEIPDB_API_KEY env var."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP to report"},
                "categories": {"type": "array", "items": {"type": "integer"},
                               "description": "AbuseIPDB category IDs: [18, 22] for SSH brute force"},
                "comment": {"type": "string", "description": "Attack description with timestamps and log snippets (max 1024 chars)"}
            },
            "required": ["ip", "categories", "comment"]
        }
    },
    "build_attacker_dossier": {
        "fn": build_attacker_dossier,
        "description": (
            "Build a complete attacker profile/dossier for an IP: geolocation, ASN, hosting provider, "
            "exposed services, known CVEs, AbuseIPDB history, RDAP abuse contacts, and threat assessment. "
            "Use this before generating a law enforcement report."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Attacker IP address to profile"}
            },
            "required": ["ip"]
        }
    },
    "generate_leo_report": {
        "fn": generate_leo_report,
        "description": (
            "Generate a formal incident report for law enforcement agencies (Polizia Postale, CSIRT-IT, "
            "Europol EC3, FBI IC3). Includes: attacker dossiers, MITRE ATT&CK mapping, evidence with "
            "SHA256 hash for chain of custody, ISP abuse contacts, and reporting guidance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "attack_summary": {
                    "type": "object",
                    "description": "Attack data: {ips: [...], attack_types: [...], start_time: ISO, end_time: ISO, total_attempts: int, log_excerpts: [...], server_info: {hostname, ip, location}}",
                    "properties": {
                        "ips": {"type": "array", "items": {"type": "string"}},
                        "attack_types": {"type": "array", "items": {"type": "string"}},
                        "start_time": {"type": "string"},
                        "end_time": {"type": "string"},
                        "total_attempts": {"type": "integer"},
                        "log_excerpts": {"type": "array", "items": {"type": "string"}},
                        "server_info": {"type": "object"}
                    }
                }
            },
            "required": ["attack_summary"]
        }
    }
}
