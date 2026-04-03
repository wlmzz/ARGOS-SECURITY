"""
ARGOS Nightly Security Analysis — scheduled batch job.
Runs every night: analyzes server logs, generates threat report.

Usage: python3 nightly_analysis.py
Cron:  0 2 * * * cd /opt/argos/agent && python3 nightly_analysis.py >> /opt/argos/logs/nightly.log 2>&1
"""
from __future__ import annotations
import sys, os, json, logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)s %(message)s")
log = logging.getLogger("argos.nightly")

from tools.analysis import read_log_file, generate_report, analyze_log, ban_ip
from tools.osint import extract_iocs, ip_reputation

LOGS_TO_CHECK = [
    "/var/log/auth.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/syslog",
]

REPORT_DIR = Path("/opt/argos/reports")


def run_nightly_analysis() -> None:
    log.info("=" * 60)
    log.info("ARGOS Nightly Security Analysis — %s", datetime.utcnow().isoformat())
    log.info("=" * 60)

    all_findings = []
    all_iocs = {"ipv4": set(), "domains": set(), "hashes": {"md5": set(), "sha1": set(), "sha256": set()}}

    for log_path in LOGS_TO_CHECK:
        if not Path(log_path).exists():
            log.info("Skipping (not found): %s", log_path)
            continue

        log.info("Analyzing: %s", log_path)
        result = read_log_file(log_path, lines=2000)

        if "error" in result:
            log.warning("Error reading %s: %s", log_path, result["error"])
            continue

        n = result.get("total_findings", 0)
        crit = result.get("critical", 0)
        high = result.get("high", 0)
        log.info("  → %d findings (%d CRITICAL, %d HIGH)", n, crit, high)

        for f in result.get("findings", []):
            f["log_source"] = log_path
            all_findings.append(f)

        for ip in result.get("unique_ips", []):
            all_iocs["ipv4"].add(ip)

    # Deduplicate findings by attack type
    by_type: dict = {}
    for f in all_findings:
        t = f["attack_type"]
        if t not in by_type:
            by_type[t] = {"attack_type": t, "severity": f["severity"],
                          "count": 0, "source_ips": set(), "sources": set()}
        by_type[t]["count"] += 1
        by_type[t]["source_ips"].update(f.get("source_ips", []))
        by_type[t]["sources"].add(f.get("log_source", ""))

    summary_findings = []
    for t, info in by_type.items():
        summary_findings.append({
            "attack_type": t,
            "severity": info["severity"],
            "occurrences": info["count"],
            "source_ips": list(info["source_ips"])[:10],
            "log_sources": list(info["sources"]),
        })

    # Check IP reputations + auto-ban confirmed threats
    top_ips = list(all_iocs["ipv4"])[:10]
    ip_intel = []
    auto_banned = []
    for ip in top_ips:
        rep = ip_reputation(ip)
        geo = rep.get("geo", {})
        ip_intel.append({"ip": ip, "info": geo})

        # Auto-ban IPs from known hosting/VPN providers with many attacks
        ip_findings = [f for f in all_findings if ip in f.get("source_ips", [])]
        n_attacks = sum(f.get("occurrences", 1) if isinstance(f, dict) else 1 for f in ip_findings)
        is_hosting = geo.get("hosting", False)
        is_proxy   = geo.get("proxy", False)
        if n_attacks >= 10 or (n_attacks >= 3 and (is_hosting or is_proxy)):
            result = ban_ip(ip, reason=f"Auto-ban: {n_attacks} attacks detected by ARGOS nightly analysis")
            if result.get("success"):
                auto_banned.append(ip)
                log.info("  🚫 Auto-banned: %s (%d attacks, hosting=%s)", ip, n_attacks, is_hosting)

    # Overall severity
    crit_total = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_total  = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    if crit_total > 0:
        overall = "CRITICAL"
    elif high_total > 5:
        overall = "HIGH"
    elif len(all_findings) > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    recommendations = []
    attack_types = set(f["attack_type"] for f in all_findings)
    if "BRUTE_FORCE" in attack_types:
        recommendations.append("Enable fail2ban for SSH and web services. Consider key-only SSH auth.")
    if "SQL_INJECTION" in attack_types:
        recommendations.append("Review web application input validation. Enable WAF rules for SQLi.")
    if "PATH_TRAVERSAL" in attack_types:
        recommendations.append("Audit web server configuration. Disable directory traversal.")
    if "RANSOMWARE" in attack_types:
        recommendations.append("URGENT: Isolate affected systems. Check backup integrity immediately.")
    if "REVERSE_SHELL" in attack_types:
        recommendations.append("URGENT: Investigate outbound connections. Possible active compromise.")
    if not recommendations:
        recommendations.append("No immediate actions required. Continue monitoring.")

    if auto_banned:
        recommendations.insert(0, f"Auto-banned {len(auto_banned)} IPs: {', '.join(auto_banned)}")

    report = generate_report(
        title=f"ARGOS Nightly Security Report — {datetime.utcnow().strftime('%Y-%m-%d')}",
        findings=summary_findings + [{"ip_intelligence": ip_intel}],
        recommendations=recommendations,
        severity=overall,
    )

    log.info("Report generated: %s", report.get("saved_to"))
    log.info("Summary: %d findings, %d CRITICAL, overall=%s",
             len(all_findings), crit_total, overall)
    log.info("=" * 60)

    return report


if __name__ == "__main__":
    run_nightly_analysis()
