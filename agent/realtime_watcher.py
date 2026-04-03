"""
ARGOS Realtime Watcher — monitors logs live and neutralizes threats immediately.

Runs as a persistent background process (systemd service or screen).
Reacts within seconds of an attack — no waiting for nightly cron.

Usage:
    python3 realtime_watcher.py
    python3 realtime_watcher.py --telegram-token TOKEN --telegram-chat-id 123456

Systemd: see installer/argos-watcher.service
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import threading
import subprocess
import urllib.request
import urllib.parse

import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from tools.analysis import ban_ip
from tools.osint import ip_reputation

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.watcher")

# --- Configuration ---
LOGS_TO_WATCH = [
    "/var/log/auth.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/syslog",
]

# Ban thresholds
BAN_AFTER_N_HITS        = 5    # ban after N pattern matches from same IP
BAN_AFTER_N_CRITICAL    = 1    # ban immediately on CRITICAL patterns
WINDOW_SECONDS          = 120  # sliding window to count hits

# Patterns: (regex, attack_type, severity)
PATTERNS = [
    (re.compile(r"Failed password.*from\s+([\d\.]+)",           re.I), "BRUTE_FORCE",      "HIGH"),
    (re.compile(r"Invalid user.*from\s+([\d\.]+)",              re.I), "BRUTE_FORCE",      "MEDIUM"),
    (re.compile(r"(?:UNION|SELECT|DROP|INSERT).*from\s+([\d\.]+)", re.I), "SQL_INJECTION", "CRITICAL"),
    (re.compile(r"(?:\.\./|%2e%2e).*[\s\"]+([\d\.]+)",         re.I), "PATH_TRAVERSAL",   "HIGH"),
    (re.compile(r"(?:<script|onerror=|javascript:).*from\s*([\d\.]+)", re.I), "XSS",       "HIGH"),
    (re.compile(r"(?:/etc/passwd|cmd\.exe|powershell).*\s([\d\.]+)", re.I), "CMD_INJECTION","CRITICAL"),
    (re.compile(r"(?:wget|curl)\s+https?://\S+\s*\|.*\s([\d\.]+)", re.I), "DOWNLOAD_EXEC","CRITICAL"),
    (re.compile(r"(?:mimikatz|lsass|sekurlsa).*\s([\d\.]+)",    re.I), "CREDENTIAL_DUMP", "CRITICAL"),
    (re.compile(r"(?:nc\s+-|/dev/tcp/).*\s([\d\.]+)",           re.I), "REVERSE_SHELL",   "CRITICAL"),
]

# Whitelist — never ban these IPs
WHITELIST = {"127.0.0.1", "::1", "localhost", os.getenv("ARGOS_SERVER_IP", "")}
_whitelist_env = os.getenv("ARGOS_WHITELIST_IPS", "")
if _whitelist_env:
    WHITELIST.update(_whitelist_env.split(","))

# ── Enrichment automatico post-ban ───────────────────────────────────────────

def _geo_quick(ip: str) -> dict:
    """Geo + ASN rapido (ip-api.com, no key)."""
    try:
        fields = "status,country,countryCode,city,isp,org,as,hosting,proxy,query"
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields={fields}",
            headers={"User-Agent": "ARGOS/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def _threatfox_quick(ip: str) -> dict:
    """ThreatFox IOC check (abuse.ch, no key)."""
    try:
        payload = json.dumps({"query": "search_ioc", "search_term": ip}).encode()
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "ARGOS/1.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        iocs = data.get("data", [])
        if not iocs:
            return {"known_threat": False}
        return {
            "known_threat": True,
            "malware":    list({i.get("malware_printable", "?") for i in iocs[:3]}),
            "tags":       list({t for i in iocs[:3] for t in (i.get("tags") or [])}),
            "confidence": iocs[0].get("confidence_level", "?"),
        }
    except Exception as e:
        return {"error": str(e)}


def _whois_quick(ip: str) -> dict:
    """WHOIS rapido per netname/org."""
    try:
        out = subprocess.check_output(["whois", ip], timeout=10,
                                      stderr=subprocess.DEVNULL).decode(errors="replace")
        result = {}
        for line in out.splitlines():
            for key in ["netname", "org-name", "country", "abuse-mailbox"]:
                if line.lower().startswith(key + ":") and key not in result:
                    result[key] = line.split(":", 1)[1].strip()
        return result
    except Exception as e:
        return {"error": str(e)}


def _enrich_and_log(ip: str, reason: str, attack_stats: dict) -> None:
    """Arricchisce un IP bannato con threat intel e salva il profilo."""
    try:
        geo    = _geo_quick(ip)
        tfox   = _threatfox_quick(ip)
        whois  = _whois_quick(ip)

        country  = geo.get("country", "?") + " / " + geo.get("city", "?")
        org      = geo.get("org", geo.get("isp", "?"))
        asn      = geo.get("as", "?")
        is_vps   = geo.get("hosting", False)
        is_proxy = geo.get("proxy", False)

        flags = []
        if is_vps:    flags.append("VPS/hosting")
        if is_proxy:  flags.append("proxy/VPN")
        if tfox.get("known_threat"):
            flags.append(f"ThreatFox:{','.join(tfox.get('malware', []))}")

        profile = {
            "ip":        ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ban_reason": reason,
            "attack_stats": attack_stats,
            "geo":       {"country": country, "org": org, "asn": asn,
                          "is_hosting": is_vps, "is_proxy": is_proxy},
            "whois":     whois,
            "threatfox": tfox,
            "flags":     flags,
        }

        # Salva profilo
        profile_path = "/opt/argos/logs/ip_profiles.jsonl"
        with open(profile_path, "a") as f:
            f.write(json.dumps(profile) + "\n")

        # Log arricchito
        log.warning(
            "PROFILE %s | %s | %s | %s%s",
            ip, country, org, asn,
            f" | ⚠ {', '.join(flags)}" if flags else ""
        )

        # Alert Telegram arricchito (se configurato)
        msg = (
            f"🔍 *Profilo attaccante*\n"
            f"IP: `{ip}`\n"
            f"Paese: {country}\n"
            f"Org: {org}\n"
            f"ASN: {asn}\n"
            f"Motivo ban: {reason}\n"
        )
        if flags:
            msg += f"⚠ Flag: {', '.join(flags)}\n"
        if tfox.get("known_threat"):
            msg += f"☠ ThreatFox: {tfox.get('malware', [])}\n"
        _send_telegram(msg)

    except Exception as e:
        log.error("Enrichment failed for %s: %s", ip, e)



# State
_ip_hits: dict[str, list[float]] = defaultdict(list)   # ip → [timestamps]
_banned: set[str] = set()
_lock = threading.Lock()

# Optional Telegram alert
_telegram_token: str = ""
_telegram_chat_id: str = ""


def _send_telegram(message: str) -> None:
    if not _telegram_token or not _telegram_chat_id:
        return
    try:
        import urllib.request, urllib.parse
        payload = json.dumps({
            "chat_id": _telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{_telegram_token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.warning("Telegram alert failed: %s", e)


def _alert(message: str) -> None:
    log.warning(message)
    _send_telegram(f"🚨 *ARGOS ALERT*\n{message}")


def _try_ban(ip: str, reason: str, severity: str) -> None:
    if ip in WHITELIST or ip in _banned:
        return
    with _lock:
        if ip in _banned:
            return
        _banned.add(ip)

    result = ban_ip(ip, reason=reason)
    if result.get("success"):
        _alert(f"🚫 *Banned* `{ip}`\nReason: {reason}\nSeverity: {severity}")
        log.info("BANNED %s — %s", ip, reason)
        # Enrichment asincrono — non blocca il watcher
        with _lock:
            stats = {"hits": len(_ip_hits.get(ip, [])), "severity": severity}
        t = threading.Thread(
            target=_enrich_and_log, args=(ip, reason, stats),
            daemon=True, name=f"enrich-{ip}")
        t.start()
    else:
        log.error("Ban FAILED for %s: %s", ip, result)


def _extract_ip(line: str, match_group: str | None) -> str | None:
    """Extract IP from regex group or fallback scan of the line."""
    if match_group and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", match_group):
        return match_group
    # Fallback: find any public IP in the line
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    for ip in ips:
        if ip not in WHITELIST and not ip.startswith(("10.", "192.168.", "172.")):
            return ip
    return None


def _process_line(line: str, source: str) -> None:
    now = time.time()

    for pattern, attack_type, severity in PATTERNS:
        m = pattern.search(line)
        if not m:
            continue

        ip = _extract_ip(line, m.group(1) if m.lastindex and m.lastindex >= 1 else None)
        if not ip or ip in WHITELIST:
            continue

        # Immediate ban for CRITICAL
        if severity == "CRITICAL":
            _try_ban(ip, f"Realtime: {attack_type} detected in {source}", severity)
            return

        # Sliding window counter for HIGH/MEDIUM
        with _lock:
            _ip_hits[ip] = [t for t in _ip_hits[ip] if now - t < WINDOW_SECONDS]
            _ip_hits[ip].append(now)
            hits = len(_ip_hits[ip])

        log.info("HIT %s [%s/%d] %s — %s", ip, hits, BAN_AFTER_N_HITS, attack_type, line.strip()[:80])

        if hits >= BAN_AFTER_N_HITS:
            reason = f"Realtime: {hits} {attack_type} attempts in {WINDOW_SECONDS}s (source: {source})"
            _try_ban(ip, reason, severity)


def _tail_file(path: str) -> None:
    """Tail a log file from the end, yielding new lines as they appear."""
    log.info("Watching: %s", path)
    try:
        with open(path, "r", errors="replace") as f:
            f.seek(0, 2)  # Seek to end
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.2)
                    # Re-check if file was rotated
                    try:
                        if os.stat(path).st_ino != os.fstat(f.fileno()).st_ino:
                            log.info("Log rotated, reopening: %s", path)
                            break
                    except OSError:
                        break
    except FileNotFoundError:
        log.warning("Log not found (will retry): %s", path)
        time.sleep(10)


def _watch_file(path: str) -> None:
    """Thread: continuously tail a log file and process each line."""
    while True:
        try:
            for line in _tail_file(path):
                _process_line(line, path)
        except Exception as e:
            log.error("Watcher error on %s: %s", path, e)
            time.sleep(5)


def _cleanup_loop() -> None:
    """Periodically clean up old hit counters."""
    while True:
        time.sleep(60)
        now = time.time()
        with _lock:
            for ip in list(_ip_hits.keys()):
                _ip_hits[ip] = [t for t in _ip_hits[ip] if now - t < WINDOW_SECONDS]
                if not _ip_hits[ip]:
                    del _ip_hits[ip]


def run(telegram_token: str = "", telegram_chat_id: str = "") -> None:
    global _telegram_token, _telegram_chat_id
    _telegram_token = telegram_token
    _telegram_chat_id = telegram_chat_id

    log.info("=" * 60)
    log.info("ARGOS Realtime Watcher starting — %s", datetime.now(timezone.utc).isoformat())
    log.info("Watching %d log files | Ban threshold: %d hits / %ds window",
             len(LOGS_TO_WATCH), BAN_AFTER_N_HITS, WINDOW_SECONDS)
    log.info("Whitelist: %s", WHITELIST)
    log.info("=" * 60)

    if telegram_token:
        _send_telegram(
            f"✅ *ARGOS Realtime Watcher* online\n"
            f"Monitoring {len(LOGS_TO_WATCH)} log files\n"
            f"Ban threshold: {BAN_AFTER_N_HITS} hits in {WINDOW_SECONDS}s"
        )

    # Start one thread per log file
    threads = []
    for path in LOGS_TO_WATCH:
        t = threading.Thread(target=_watch_file, args=(path,), daemon=True, name=f"watcher-{Path(path).name}")
        t.start()
        threads.append(t)

    # Cleanup thread
    threading.Thread(target=_cleanup_loop, daemon=True, name="cleanup").start()

    log.info("All watchers active. Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(30)
            with _lock:
                active = sum(1 for hits in _ip_hits.values() if hits)
            log.info("Status: %d IPs tracked, %d banned this session", active, len(_banned))
    except KeyboardInterrupt:
        log.info("ARGOS Realtime Watcher stopped.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="ARGOS Realtime Threat Watcher")
    p.add_argument("--telegram-token",   default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    p.add_argument("--telegram-chat-id", default=os.getenv("TELEGRAM_CHAT_ID", ""))
    args = p.parse_args()
    run(args.telegram_token, args.telegram_chat_id)
