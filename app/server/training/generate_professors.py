"""
ARGOS — Generatore training data con professori locali
Carica ogni modello professore via llama.cpp su porta 8090,
genera esempi di cybersecurity, salva JSONL, poi carica il prossimo.

Gira in parallelo con Seneca-32B (porta 8080) senza conflitti.

Usage:
    python generate_professors.py
    python generate_professors.py --examples-per-model 3000
    python generate_professors.py --model lily  # solo un modello
    python generate_professors.py --loop        # cicla all'infinito
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import subprocess
import time
from datetime import datetime
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.professors")

LLAMA_BIN     = "/opt/llama.cpp/build/bin/llama-server"
PROF_DIR      = Path("/opt/argos/models/professors")
OUTPUT_DIR    = Path("/opt/argos/training/datasets/foundational")
PROF_PORT     = 8090
PROF_API      = f"http://localhost:{PROF_PORT}"

PROFESSORS = [
    {"name": "zysec",       "file": "SecurityLLM.Q4_K_S.gguf",                          "threads": 16},
    {"name": "pentesting",  "file": "Pentesting-GPT-v1.0.Q4_K_S.gguf",                  "threads": 16},
    {"name": "cai",         "file": "qwen2.5-coder-7b-instruct.Q4_0.gguf",              "threads": 16},
    {"name": "elisar",      "file": "ELISARCyberAIEdge7B-LoRA.gguf",                    "threads": 16},
    {"name": "mitre",       "file": "security-attacks-MITRE.gguf",                       "threads": 20},
    {"name": "lily",        "file": "Lily-Uncensored-Q4_K_M.gguf",                       "threads": 24},
    {"name": "pentest_ai",  "file": "Pentest_AI.gguf",                                   "threads": 24},
    {"name": "gpt_oss",     "file": "GPT-OSS-Cybersecurity-20B-Merged.i1-Q4_K_S.gguf",  "threads": 28},
]

# ── Scenari cybersecurity ────────────────────────────────────────────────────

RANDOM_IPS = [
    "185.220.101.47", "45.33.32.156", "23.129.64.131", "91.108.4.1",
    "77.247.181.165", "198.51.100.42", "193.32.162.50", "87.236.176.135",
    "5.188.62.140", "213.109.202.45", "104.21.64.0", "172.64.155.200",
]

CYBER_SCENARIOS = [
    ("brute_force_ssh",      "HIGH",     "{n} failed SSH login attempts in {t}s from {ip}, usernames: root, admin, ubuntu"),
    ("brute_force_rdp",      "HIGH",     "{n} failed RDP auth attempts from {ip} on port 3389 in {t}s"),
    ("port_scan_syn",        "MEDIUM",   "TCP SYN scan from {ip}: {n} ports probed in {t}s"),
    ("port_scan_stealth",    "HIGH",     "XMAS/NULL scan from {ip}, targeting ports 22,80,443,8080,3306"),
    ("sql_injection",        "CRITICAL", "SQL injection from {ip}: UNION SELECT, DROP TABLE in POST /login"),
    ("xss_attack",           "HIGH",     "XSS from {ip}: <script>alert() in form field, target /dashboard"),
    ("path_traversal",       "HIGH",     "Path traversal from {ip}: ../../etc/passwd in URL param"),
    ("command_injection",    "CRITICAL", "Command injection from {ip}: ; cat /etc/shadow in web form"),
    ("c2_beacon",            "CRITICAL", "Periodic encrypted outbound to {ip} every {t}s from internal host"),
    ("dns_tunneling",        "HIGH",     "DNS tunneling to {ip}: {n} unusually long TXT queries in {t}s"),
    ("malware_download",     "CRITICAL", "PE executable download from {ip} via HTTP to internal host"),
    ("ransomware",           "CRITICAL", "{n} files renamed .encrypted in {t}s, shadow copies deleted"),
    ("data_exfiltration",    "CRITICAL", "{n}MB sent to {ip} via HTTPS at 03:00 AM, outside business hours"),
    ("lateral_movement",     "CRITICAL", "SMB connections from compromised host to {n} internal IPs"),
    ("pass_the_hash",        "CRITICAL", "NTLM hash reuse from {ip} to domain controller"),
    ("privilege_escalation", "CRITICAL", "www-data executed sudo su, new root shell spawned"),
    ("dir_enumeration",      "MEDIUM",   "{n} 404s from {ip} in {t}s, dirbuster UA detected"),
    ("credential_stuffing",  "HIGH",     "{n} logins with breached credentials from {ip} to /api/auth"),
    ("ddos_syn_flood",       "CRITICAL", "SYN flood: {n} pps from distributed IPs, CPU at 98%"),
    ("insider_threat",       "HIGH",     "Employee accessing {n} sensitive files at 03:00 AM, USB activity"),
]

MITRE_TECHNIQUES = [
    "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter",
    "T1053 Scheduled Task", "T1548 Abuse Elevation Control",
    "T1055 Process Injection", "T1036 Masquerading",
    "T1027 Obfuscated Files", "T1105 Ingress Tool Transfer",
    "T1071 Application Layer Protocol", "T1041 Exfiltration Over C2",
    "T1110 Brute Force", "T1190 Exploit Public-Facing Application",
    "T1566 Phishing", "T1486 Data Encrypted for Impact",
    "T1562 Impair Defenses",
]

CVE_TYPES = [
    "buffer overflow in web server", "SQL injection in login form",
    "RCE via deserialization", "privilege escalation via SUID binary",
    "path traversal in file upload", "SSRF in API endpoint",
    "XXE injection in XML parser", "race condition in authentication",
    "hardcoded credentials in firmware", "insecure direct object reference",
]

PENTEST_TASKS = [
    "enumerate subdomains of a target domain",
    "detect open ports and running services",
    "test for SQL injection in a web app (manual + sqlmap)",
    "perform password spraying against Active Directory with lockout bypass",
    "identify misconfigured S3 buckets and exposed cloud storage",
    "test for SSRF vulnerabilities in an API endpoint",
    "enumerate SMB shares and find sensitive files on a network",
    "detect and exploit JWT token weaknesses and signature bypass",
    "perform DNS zone transfer and subdomain enumeration",
    "fingerprint and bypass a web application firewall",
    "perform ARP spoofing MITM on a /24 network segment",
    "exploit a stack-based buffer overflow step by step",
    "perform Linux privilege escalation via SUID/sudo/cron",
    "perform Windows privilege escalation via unquoted service paths",
    "enumerate Active Directory with BloodHound and ldapdomaindump",
    "perform Kerberoasting to extract and crack service account hashes",
    "bypass antivirus with payload obfuscation and encoding",
    "perform lateral movement using PsExec, WMI, or Pass-the-Hash",
    "extract Windows credentials using mimikatz techniques",
    "stabilize a reverse shell and perform post-exploitation",
    "exploit insecure deserialization (Java ysoserial, Python pickle)",
    "exploit log4shell CVE-2021-44228 step by step",
    "perform Docker container escape via misconfigured socket",
    "enumerate and exploit Kubernetes RBAC misconfigurations",
    "perform subdomain takeover on expired DNS CNAME records",
    "crack WPA2 handshake with hashcat and rockyou.txt",
    "implement covert C2 channel via DNS tunneling (Python code)",
    "exploit XXE injection to read /etc/passwd",
    "perform VLAN hopping via double tagging",
    "evade Snort/Suricata IDS using fragmentation and timing",
    "perform network forensics to trace attacker lateral movement",
    "craft custom packets with Scapy for network testing",
]

NETWORK_SCENARIOS = [
    ("network_scan",    "Stealthy Nmap scan of 192.168.1.0/24: OS fingerprint, service versions, NSE scripts — show commands and interpret output"),
    ("firewall_bypass", "Bypass stateful firewall filtering ports 22,80,443 using fragmentation, decoys, and protocol tunneling"),
    ("ids_evasion",     "Evade Snort/Suricata during pentest: fragmentation, encoding, timing, and decoy techniques with examples"),
    ("wifi_pentest",    "WPA2 full attack: airodump-ng capture + deauth + hashcat crack — complete walkthrough with commands"),
    ("mitm_arp",        "ARP poisoning MITM on /24: arpspoof/bettercap commands, SSL stripping, credential capture"),
    ("dns_attack",      "DNS cache poisoning (Kaminsky attack): how it works, Scapy PoC, detection, DNSSEC protection"),
    ("packet_crafting", "Write Scapy Python code to: SYN scan, spoofed ICMP, custom TCP flags — with explanations"),
    ("covert_c2",       "Build DNS-based C2 channel in Python: server encodes commands in TXT records, client polls and executes"),
    ("net_forensics",   "Wireshark filters and tshark commands to detect: port scan, data exfil, C2 beacon, lateral movement"),
    ("ddos_defend",     "DDoS attack types (SYN flood, HTTP flood, amplification) + iptables/nginx/Cloudflare mitigation rules"),
    ("zero_trust",      "Zero Trust Architecture for 500-user org: microsegmentation, identity-aware proxy, continuous validation"),
    ("bgp_hijack",      "BGP route hijacking: mechanics, real examples (Amazon Route 53, Pakistan Telecom), RPKI fix"),
    ("vpn_weaknesses",  "Common VPN misconfigurations: split tunneling leaks, weak ciphers, certificate pinning bypass"),
    ("snmp_enum",       "SNMP enumeration and exploitation: community string brute force, MIB walking, snmpwalk commands"),
    ("802_bypass",      "802.1X NAC bypass during pentest: MAC spoofing, RADIUS vulnerabilities, rogue AP techniques"),
]

def rand_scenario() -> tuple[str, str, str]:
    sc = random.choice(CYBER_SCENARIOS)
    desc = sc[2].format(
        ip=random.choice(RANDOM_IPS),
        n=random.randint(10, 500),
        t=random.randint(5, 300),
    )
    return sc[0], sc[1], desc


# ── llama.cpp server ─────────────────────────────────────────────────────────

_server_proc: subprocess.Popen | None = None


def start_professor(prof: dict) -> bool:
    global _server_proc
    gguf = PROF_DIR / prof["file"]
    if not gguf.exists():
        log.error("File non trovato: %s", gguf)
        return False

    stop_professor()

    log.info("Avvio professore: %s (%s)", prof["name"], prof["file"])
    cmd = [
        LLAMA_BIN,
        "--model",   str(gguf),
        "--port",    str(PROF_PORT),
        "--threads", str(prof["threads"]),
        "--ctx-size", "4096",
        "--no-mmap",
        "-np", "1",
    ]
    _server_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Aspetta che il server sia pronto
    for _ in range(60):
        try:
            r = requests.get(f"{PROF_API}/health", timeout=2)
            if r.status_code == 200:
                log.info("Professore %s pronto (PID %d)", prof["name"], _server_proc.pid)
                return True
        except Exception:
            pass
        time.sleep(2)

    log.error("Professore %s non risponde dopo 120s", prof["name"])
    stop_professor()
    return False


def stop_professor() -> None:
    global _server_proc
    if _server_proc:
        try:
            _server_proc.terminate()
            _server_proc.wait(timeout=10)
        except Exception:
            try:
                _server_proc.kill()
            except Exception:
                pass
        _server_proc = None
        time.sleep(3)


def ask_professor(prompt: str, max_tokens: int = 800) -> str | None:
    try:
        r = requests.post(
            f"{PROF_API}/completion",
            json={
                "prompt":      prompt,
                "n_predict":   max_tokens,
                "temperature": 0.4,
                "stop":        ["###", "\n\n\n"],
            },
            timeout=120,
        )
        if r.status_code == 200:
            return r.json().get("content", "").strip()
    except Exception as e:
        log.warning("API error: %s", e)
    return None


# ── Generatori ───────────────────────────────────────────────────────────────

def gen_threat_analysis() -> dict | None:
    threat, severity, desc = rand_scenario()
    prompt = (
        f"You are an expert cybersecurity analyst. Analyze this threat and respond with JSON.\n\n"
        f"Threat: {threat}\nSeverity: {severity}\nEvent: {desc}\n\n"
        f"Respond ONLY with valid JSON:\n"
        f'{{"threat_level":"{severity}","attack_type":"{threat}","confidence":0.95,'
        f'"actions":["action1"],"reasoning":"explanation","escalate_to_human":false}}\n\n'
        f"JSON response:"
    )
    resp = ask_professor(prompt)
    if not resp:
        return None
    try:
        start = resp.find("{")
        end   = resp.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(resp[start:end])
            return {
                "instruction": "Analyze this cybersecurity threat and return a JSON decision.",
                "input": f"Threat Type: {threat}\nSeverity: {severity}\nDescription: {desc}",
                "output": json.dumps(parsed, ensure_ascii=False),
            }
    except Exception:
        pass
    if len(resp) > 80:
        return {
            "instruction": "Analyze this cybersecurity threat and return a JSON decision.",
            "input": f"Threat Type: {threat}\nSeverity: {severity}\nDescription: {desc}",
            "output": resp[:2000],
        }
    return None


def gen_mitre() -> dict | None:
    tech = random.choice(MITRE_TECHNIQUES)
    prompt = (
        f"Explain the MITRE ATT&CK technique: {tech}\n"
        f"Include: description, attacker usage, detection methods, mitigation.\n\n"
        f"Answer:"
    )
    resp = ask_professor(prompt, max_tokens=600)
    if resp and len(resp) > 100:
        return {
            "instruction": f"Explain MITRE ATT&CK technique {tech}: how attackers use it, how to detect it, and how to mitigate it.",
            "input": "",
            "output": resp[:3000],
        }
    return None


def gen_cve() -> dict | None:
    cve_type = random.choice(CVE_TYPES)
    year = random.randint(2020, 2025)
    cvss = round(random.uniform(6.0, 10.0), 1)
    prompt = (
        f"Describe a realistic CVE ({year}) for a {cve_type}.\n"
        f"Include: affected software, CVSS {cvss}, exploitation steps, patch/workaround.\n\n"
        f"CVE Description:"
    )
    resp = ask_professor(prompt, max_tokens=600)
    if resp and len(resp) > 100:
        return {
            "instruction": f"Describe a CVE vulnerability involving {cve_type}. Include CVSS score, exploitation, and mitigation.",
            "input": "",
            "output": resp[:3000],
        }
    return None


def gen_pentest() -> dict | None:
    task = random.choice(PENTEST_TASKS)
    lang = random.choice(["Python", "Bash", "Python"])
    prompt = (
        f"Write a {lang} script to {task} for authorized penetration testing.\n"
        f"Add comments explaining each step.\n\n"
        f"```{lang.lower()}"
    )
    resp = ask_professor(prompt, max_tokens=700)
    if resp and len(resp) > 100:
        return {
            "instruction": f"Write a {lang} script to {task} for authorized penetration testing.",
            "input": "",
            "output": (f"```{lang.lower()}\n" + resp)[:4000],
        }
    return None


def gen_network() -> dict | None:
    sc = random.choice(NETWORK_SCENARIOS)
    name, task = sc[0], sc[1]
    task_f = task.format(
        ip=random.choice(RANDOM_IPS),
        n=random.randint(10, 500),
        t=random.randint(5, 300),
    ) if "{" in task else task
    prompt = (
        f"You are an expert penetration tester and network security engineer.\n"
        f"Task: {task_f}\n\n"
        f"Provide a detailed technical answer with commands, code, or step-by-step instructions:\n"
    )
    resp = ask_professor(prompt, max_tokens=800)
    if resp and len(resp) > 100:
        return {
            "instruction": task_f,
            "input": "",
            "output": resp[:4000],
        }
    return None


GENERATORS = [gen_threat_analysis, gen_mitre, gen_cve, gen_pentest, gen_network]
GEN_WEIGHTS = [3, 2, 2, 5, 5]  # pentest e network priorità massima


# ── Main loop ────────────────────────────────────────────────────────────────

def run_professor(prof: dict, n_examples: int) -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"prof_{prof['name']}_{timestamp}.jsonl"

    if not start_professor(prof):
        return 0

    written = 0
    failed  = 0

    log.info("Generazione %d esempi con %s → %s", n_examples, prof["name"], output_path.name)

    with open(output_path, "w") as f:
        while written < n_examples:
            gen_fn = random.choices(GENERATORS, weights=GEN_WEIGHTS, k=1)[0]
            ex = gen_fn()
            if ex and ex.get("output", "").strip():
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
                f.flush()
                written += 1
                if written % 100 == 0:
                    log.info("  [%s] %d/%d esempi generati", prof["name"], written, n_examples)
            else:
                failed += 1
                if failed > 50 and written == 0:
                    log.warning("  Troppi fail consecutivi — skip %s", prof["name"])
                    break

    stop_professor()
    log.info("Professore %s: %d esempi → %s", prof["name"], written, output_path)
    return written


def main():
    p = argparse.ArgumentParser(description="ARGOS Professor Data Generator")
    p.add_argument("--examples-per-model", type=int, default=3000)
    p.add_argument("--model",  default=None, help="Solo questo professore (es: zysec)")
    p.add_argument("--loop",   action="store_true", default=True, help="Cicla all'infinito (default: on)")
    args = p.parse_args()

    professors = PROFESSORS
    if args.model:
        professors = [p for p in PROFESSORS if p["name"] == args.model]
        if not professors:
            log.error("Modello '%s' non trovato. Disponibili: %s",
                      args.model, [p["name"] for p in PROFESSORS])
            raise SystemExit(1)

    log.info("=" * 60)
    log.info("ARGOS Professor Generator")
    log.info("Professori: %d | Esempi/modello: %d | Loop: %s",
             len(professors), args.examples_per_model, args.loop)
    log.info("Output: %s", OUTPUT_DIR)
    log.info("=" * 60)

    total_generated = 0
    round_num = 1

    while True:
        log.info("=== Round %d ===", round_num)
        random.shuffle(professors)  # ordine casuale ogni round

        for prof in professors:
            n = run_professor(prof, args.examples_per_model)
            total_generated += n
            log.info("Totale generato finora: %d esempi", total_generated)

        log.info("=== Round %d completato: %d esempi totali ===", round_num, total_generated)

        if not args.loop:
            break
        round_num += 1
        log.info("Pausa 60s prima del prossimo round...")
        time.sleep(60)

    log.info("DONE. Totale: %d esempi generati.", total_generated)


if __name__ == "__main__":
    main()
