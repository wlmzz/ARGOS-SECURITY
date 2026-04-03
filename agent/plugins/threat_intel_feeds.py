"""
ARGOS Plugin: Threat Intel Feeds
Scarica e mantiene aggiornate blocklist IP da fonti multiple:
  - romainmarcoux/malicious-ip (14+ fonti threat intel aggregate)
  - ShadowWhisperer/IPs (honeypot-derived, categorie: threats/scanners/probes/etc.)
  - ipsum (stamparm) — IP reputation tier-based
  - Emergingthreats, Spamhaus DROP
Funziona completamente offline dopo il primo download.
"""
from __future__ import annotations
import json, os, re, time, subprocess, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST = {
    "id":          "threat-intel-feeds",
    "name":        "Threat Intel Feeds",
    "description": (
        "Blocklist IP aggregate da malicious-ip (14+ fonti), ShadowWhisperer honeypot, "
        "Ipsum, Emergingthreats, Spamhaus DROP. "
        "Check IP, apply a UFW/iptables, stats, aggiornamento automatico."
    ),
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_FEEDS_DIR   = Path("/opt/argos/threat_intel/feeds")
_MERGED_FILE = Path("/opt/argos/threat_intel/blocklist_merged.txt")
_META_FILE   = Path("/opt/argos/threat_intel/meta.json")

FEEDS = {
    "malicious_ip_all": {
        "url":         "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt",
        "description": "malicious-ip aggregated (40k+ IPs from 14+ sources)",
        "category":    "malicious",
    },
    "malicious_ip_extra": {
        "url":         "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k-extra.txt",
        "description": "malicious-ip extra extended set",
        "category":    "malicious",
    },
    "shadowwhisperer_threats": {
        "url":         "https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/Threats",
        "description": "ShadowWhisperer honeypot — confirmed threats",
        "category":    "threats",
    },
    "shadowwhisperer_scanners": {
        "url":         "https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/Scanners",
        "description": "ShadowWhisperer honeypot — port/vuln scanners",
        "category":    "scanners",
    },
    "shadowwhisperer_malware": {
        "url":         "https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/Malware",
        "description": "ShadowWhisperer honeypot — malware C2/distribution",
        "category":    "malware",
    },
    "ipsum_high": {
        "url":         "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
        "description": "Ipsum tier-6+ (reported 6+ times across threat feeds)",
        "category":    "reputation",
    },
    "emergingthreats_blocklist": {
        "url":         "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "description": "EmergingThreats block rules (C2, scanners, tor exit)",
        "category":    "emergingthreats",
    },
    "bitwire_blocklist": {
        "url":         "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/ip_blocklist.txt",
        "description": "bitwire-it aggregated blocklist (updated every 2h)",
        "category":    "malicious",
    },
    "datashield_ipv4": {
        "url":         "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/data_shield_ipv4_blocklist.txt",
        "description": "Data-Shield IPv4 blocklist — blocks ~95% bot traffic",
        "category":    "bots",
    },
    "firehol_level1": {
        "url":         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "description": "FireHOL Level 1 — highest confidence malicious IPs (attacks, exploits, malware)",
        "category":    "firehol",
    },
    "firehol_level2": {
        "url":         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "description": "FireHOL Level 2 — broader threat coverage",
        "category":    "firehol",
    },
    "firehol_level3": {
        "url":         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        "description": "FireHOL Level 3 — wide net (higher false positive rate)",
        "category":    "firehol",
    },
    "firehol_anonymous": {
        "url":         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset",
        "description": "FireHOL anonymous — Tor, VPN, proxies, anonymizers",
        "category":    "anonymizers",
    },
    "firehol_webclient": {
        "url":         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset",
        "description": "FireHOL webclient — IPs dangerous for web clients (phishing, malware, adware)",
        "category":    "webclient",
    },
    "spamhaus_drop": {
        "url":         "https://www.spamhaus.org/drop/drop.txt",
        "description": "Spamhaus DROP — hijacked/rogue netblocks",
        "category":    "spamhaus",
    },
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _load_meta() -> dict:
    if _META_FILE.exists():
        try:
            return json.loads(_META_FILE.read_text())
        except Exception:
            pass
    return {}

def _save_meta(meta: dict) -> None:
    _META_FILE.parent.mkdir(parents=True, exist_ok=True)
    _META_FILE.write_text(json.dumps(meta, indent=2))

def _download_feed(name: str, url: str) -> tuple[int, str]:
    """Scarica un feed e ritorna (n_ips, path)."""
    _FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    dest = _FEEDS_DIR / f"{name}.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ARGOS-ThreatIntel/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode(errors="replace")
        ips = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Estrai IP o CIDR
            m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", line)
            if m:
                ips.add(m.group(1))
        dest.write_text("\n".join(sorted(ips)))
        return len(ips), str(dest)
    except Exception as e:
        return 0, f"error: {e}"

def _load_all_ips() -> set[str]:
    """Carica tutti gli IP da tutti i feed scaricati."""
    all_ips: set[str] = set()
    for f in _FEEDS_DIR.glob("*.txt"):
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                all_ips.add(line)
    return all_ips

def _rebuild_merged() -> int:
    ips = _load_all_ips()
    _MERGED_FILE.parent.mkdir(parents=True, exist_ok=True)
    _MERGED_FILE.write_text("\n".join(sorted(ips)))
    return len(ips)

def _ip_in_set(ip: str, ip_set: set[str]) -> bool:
    if ip in ip_set:
        return True
    # Controlla CIDR /24 match base
    prefix24 = ".".join(ip.split(".")[:3]) + "."
    for entry in ip_set:
        if "/" in entry and entry.startswith(prefix24):
            return True
    return False

# ── Tools ────────────────────────────────────────────────────────────────────

def update_feeds(feeds: list[str] = None) -> dict:
    """
    Scarica/aggiorna i feed di threat intelligence.
    Se feeds=None aggiorna tutti. Passa lista di nomi per aggiornarne solo alcuni.
    Feed disponibili: malicious_ip_all, malicious_ip_extra, shadowwhisperer_threats,
    shadowwhisperer_scanners, shadowwhisperer_malware, ipsum_high,
    emergingthreats_blocklist, spamhaus_drop
    """
    targets = {k: v for k, v in FEEDS.items() if feeds is None or k in feeds}
    meta = _load_meta()
    results = {}

    for name, info in targets.items():
        count, path = _download_feed(name, info["url"])
        status = "ok" if not path.startswith("error") else "failed"
        results[name] = {
            "status":      status,
            "ip_count":    count,
            "category":    info["category"],
            "description": info["description"],
            "error":       path if status == "failed" else None,
        }
        if status == "ok":
            meta[name] = {
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "ip_count":     count,
                "category":     info["category"],
            }

    total = _rebuild_merged()
    meta["_merged"] = {
        "last_rebuilt": datetime.now(timezone.utc).isoformat(),
        "total_unique_ips": total,
    }
    _save_meta(meta)

    return {
        "feeds_updated": len(results),
        "total_unique_ips": total,
        "results": results,
    }


def check_ip(ip: str) -> dict:
    """
    Controlla se un IP è presente nelle blocklist.
    Ritorna quali feed lo segnalano e la categoria di minaccia.
    """
    ip = ip.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"error": f"IP non valido: {ip}"}

    if not _FEEDS_DIR.exists():
        return {"error": "Feed non ancora scaricati. Esegui update_feeds() prima."}

    found_in = []
    for feed_file in _FEEDS_DIR.glob("*.txt"):
        feed_name = feed_file.stem
        for line in feed_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            if line == ip or (line.startswith(ip + "/")) or \
               ("/" in line and line.rsplit("/", 1)[0].rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]):
                info = FEEDS.get(feed_name, {})
                found_in.append({
                    "feed":        feed_name,
                    "category":    info.get("category", "unknown"),
                    "description": info.get("description", ""),
                })
                break

    meta = _load_meta()
    return {
        "ip":          ip,
        "is_malicious": bool(found_in),
        "found_in":    found_in,
        "threat_level": "HIGH" if len(found_in) >= 3 else "MEDIUM" if found_in else "CLEAN",
        "checked_feeds": len(list(_FEEDS_DIR.glob("*.txt"))),
        "last_update": meta.get("_merged", {}).get("last_rebuilt", "unknown"),
    }


def check_ips_bulk(ips: list[str]) -> dict:
    """Controlla una lista di IP contro tutte le blocklist in un'unica operazione."""
    if not _MERGED_FILE.exists():
        return {"error": "Merged blocklist non trovata. Esegui update_feeds() prima."}

    all_blocked = set(_MERGED_FILE.read_text(errors="replace").splitlines())
    results = []
    malicious_count = 0

    for ip in ips:
        ip = ip.strip()
        is_bad = _ip_in_set(ip, all_blocked)
        if is_bad:
            malicious_count += 1
        results.append({"ip": ip, "is_malicious": is_bad})

    return {
        "total_checked":   len(ips),
        "malicious_found": malicious_count,
        "clean":           len(ips) - malicious_count,
        "results":         results,
    }


def get_feed_stats() -> dict:
    """Statistiche sui feed scaricati: conteggi, date aggiornamento, categorie."""
    meta = _load_meta()
    feeds_on_disk = {}
    if _FEEDS_DIR.exists():
        for f in _FEEDS_DIR.glob("*.txt"):
            lines = [l for l in f.read_text(errors="replace").splitlines() if l.strip() and not l.startswith("#")]
            feeds_on_disk[f.stem] = len(lines)

    categories: dict[str, int] = {}
    for name, info in (meta.get(k, {}) for k in FEEDS if k in meta):
        pass
    for name, info in meta.items():
        if name.startswith("_"):
            continue
        cat = info.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + info.get("ip_count", 0)

    return {
        "total_feeds_available":  len(FEEDS),
        "feeds_downloaded":       len(feeds_on_disk),
        "total_unique_ips":       meta.get("_merged", {}).get("total_unique_ips", 0),
        "last_update":            meta.get("_merged", {}).get("last_rebuilt", "mai"),
        "by_category":            categories,
        "feeds_detail":           {
            name: {
                "ip_count":     feeds_on_disk.get(name, 0),
                "last_updated": meta.get(name, {}).get("last_updated", "mai"),
                "description":  FEEDS.get(name, {}).get("description", ""),
            }
            for name in FEEDS
        },
    }


def apply_blocklist_to_firewall(dry_run: bool = True, max_rules: int = 5000) -> dict:
    """
    Applica le blocklist a UFW/iptables.
    dry_run=True (default) mostra cosa farebbe senza applicare.
    Attenzione: max_rules limita il numero di regole create (default 5000).
    """
    if not _MERGED_FILE.exists():
        return {"error": "Blocklist non trovata. Esegui update_feeds() prima."}

    all_ips = [l.strip() for l in _MERGED_FILE.read_text(errors="replace").splitlines()
               if l.strip() and not l.startswith("#")]

    # Escludi CIDR complessi per ora, prendi solo IP singoli
    single_ips = [ip for ip in all_ips if "/" not in ip][:max_rules]

    if dry_run:
        return {
            "dry_run":    True,
            "would_block": len(single_ips),
            "total_in_list": len(all_ips),
            "sample":     single_ips[:10],
            "command_example": f"ufw deny from {single_ips[0]} to any" if single_ips else "",
            "message":    "Imposta dry_run=False per applicare le regole.",
        }

    # Applica via ipset (più efficiente di singole regole UFW)
    applied = 0
    errors  = []
    try:
        subprocess.run(["ipset", "create", "argos_blocklist", "hash:ip", "--exist"],
                       check=True, capture_output=True)
        subprocess.run(["ipset", "flush", "argos_blocklist"], check=True, capture_output=True)
        for ip in single_ips:
            try:
                subprocess.run(["ipset", "add", "argos_blocklist", ip, "--exist"],
                               check=True, capture_output=True, timeout=2)
                applied += 1
            except Exception as e:
                errors.append(str(e))
        # Assicura che iptables usi l'ipset
        subprocess.run(
            ["iptables", "-I", "INPUT", "-m", "set", "--match-set", "argos_blocklist", "src", "-j", "DROP", "--exist"],
            capture_output=True)
        return {
            "applied": applied,
            "errors":  len(errors),
            "method":  "ipset + iptables",
            "set_name": "argos_blocklist",
        }
    except FileNotFoundError:
        # Fallback: UFW
        for ip in single_ips[:500]:
            try:
                subprocess.run(["ufw", "deny", "from", ip, "to", "any"],
                               check=True, capture_output=True, timeout=3)
                applied += 1
            except Exception as e:
                errors.append(str(e))
        return {
            "applied": applied,
            "errors":  len(errors),
            "method":  "ufw (fallback — ipset non disponibile)",
        }


def search_blocklist(query: str) -> dict:
    """
    Cerca in tutte le blocklist per IP parziale, subnet, o keyword.
    Es: search_blocklist('195.178') trova tutti gli IP che iniziano con 195.178
    """
    if not _FEEDS_DIR.exists():
        return {"error": "Feed non scaricati. Esegui update_feeds() prima."}

    matches = []
    seen: set[str] = set()
    for feed_file in sorted(_FEEDS_DIR.glob("*.txt")):
        feed_name = feed_file.stem
        for line in feed_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and query in line and line not in seen:
                seen.add(line)
                matches.append({
                    "ip":       line,
                    "feed":     feed_name,
                    "category": FEEDS.get(feed_name, {}).get("category", "unknown"),
                })
            if len(matches) >= 200:
                break

    return {
        "query":   query,
        "matches": len(matches),
        "results": matches[:100],
    }


TOOLS = {
    "update_feeds": {
        "fn": update_feeds,
        "description": (
            "Scarica/aggiorna i feed threat intel: malicious-ip (14+ fonti), "
            "ShadowWhisperer honeypot (threats/scanners/malware), Ipsum tier-6, "
            "EmergingThreats, Spamhaus DROP. Chiama senza argomenti per aggiornarli tutti."
        ),
        "parameters": {
            "feeds": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Lista di feed da aggiornare (default: tutti). Opzioni: malicious_ip_all, malicious_ip_extra, shadowwhisperer_threats, shadowwhisperer_scanners, shadowwhisperer_malware, ipsum_high, emergingthreats_blocklist, spamhaus_drop",
                "required": False,
            },
        },
    },
    "check_ip": {
        "fn": check_ip,
        "description": "Controlla se un IP è in una delle blocklist threat intel. Risponde con quali feed lo segnalano e il livello di minaccia.",
        "parameters": {
            "ip": {"type": "string", "description": "IP da controllare", "required": True},
        },
    },
    "check_ips_bulk": {
        "fn": check_ips_bulk,
        "description": "Controlla una lista di IP in bulk contro le blocklist merge. Più veloce di check_ip ripetuto.",
        "parameters": {
            "ips": {"type": "array", "items": {"type": "string"}, "description": "Lista di IP da controllare", "required": True},
        },
    },
    "get_feed_stats": {
        "fn": get_feed_stats,
        "description": "Statistiche sui feed: quanti IP per fonte, date aggiornamento, breakdown per categoria (malicious/scanners/malware/reputation).",
        "parameters": {},
    },
    "apply_blocklist_to_firewall": {
        "fn": apply_blocklist_to_firewall,
        "description": "Applica le blocklist a UFW/iptables (via ipset se disponibile). Default dry_run=True — mostra cosa farebbe senza applicare.",
        "parameters": {
            "dry_run": {"type": "boolean", "description": "Se True (default) mostra solo il preview senza applicare", "required": False},
            "max_rules": {"type": "integer", "description": "Numero massimo di regole da creare (default: 5000)", "required": False},
        },
    },
    "search_blocklist": {
        "fn": search_blocklist,
        "description": "Cerca in tutte le blocklist per IP parziale o subnet. Es: '195.178' trova tutti gli IP di quel blocco.",
        "parameters": {
            "query": {"type": "string", "description": "IP parziale, subnet, o stringa da cercare", "required": True},
        },
    },
}
