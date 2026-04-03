"""
ARGOS — Generatore di training data con modelli locali (LM Studio / Ollama)
Usa i tuoi modelli locali per generare esempi di alta qualità per addestrare ARGOS.

Usage:
    # Avvia LM Studio e carica un modello, poi:
    python generate_training_data.py
    python generate_training_data.py --model seneca --count 10000
    python generate_training_data.py --model qwen-coder --category code --count 5000
    python generate_training_data.py --list-models

Prerequisiti:
    pip install requests tqdm
    LM Studio aperto con un modello caricato (porta 1234)
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import time
from datetime import datetime
from pathlib import Path

import requests
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.generate")

LM_STUDIO_URL = "http://localhost:1234/v1"
OLLAMA_URL    = "http://localhost:11434/v1"
OUTPUT_DIR    = Path("./generated_training")


# ── Scenari di cybersecurity ─────────────────────────────────────────────────

CYBER_SCENARIOS = [
    # Brute Force
    {"threat": "brute_force_ssh", "severity": "HIGH",
     "desc": "{n} failed SSH login attempts in {t} seconds from {ip}, usernames tried: root, admin, ubuntu, pi"},
    {"threat": "brute_force_rdp", "severity": "HIGH",
     "desc": "{n} failed RDP authentication attempts from {ip} targeting port 3389"},
    {"threat": "brute_force_ftp", "severity": "MEDIUM",
     "desc": "{n} failed FTP login attempts from {ip} in {t} seconds"},
    # Port Scan
    {"threat": "port_scan_full", "severity": "MEDIUM",
     "desc": "Full TCP SYN scan detected from {ip}, {n} ports probed in {t} seconds"},
    {"threat": "port_scan_stealth", "severity": "HIGH",
     "desc": "Stealth XMAS scan from {ip}, targeting ports 22,80,443,8080,3306,5432"},
    {"threat": "port_scan_udp", "severity": "LOW",
     "desc": "UDP port scan from {ip}, {n} ports in {t} seconds"},
    # Web Attacks
    {"threat": "sql_injection", "severity": "CRITICAL",
     "desc": "SQL injection attempt detected in web request from {ip}: payload contains UNION SELECT, DROP TABLE patterns"},
    {"threat": "xss_attack", "severity": "HIGH",
     "desc": "XSS attack from {ip}: <script>alert() patterns in HTTP POST body targeting /login endpoint"},
    {"threat": "path_traversal", "severity": "HIGH",
     "desc": "Path traversal attempt from {ip}: ../../etc/passwd in URL parameter"},
    {"threat": "command_injection", "severity": "CRITICAL",
     "desc": "Command injection in web form from {ip}: ; cat /etc/shadow patterns detected"},
    {"threat": "lfi_attack", "severity": "HIGH",
     "desc": "Local File Inclusion attempt from {ip}: ?page=../../../../etc/passwd"},
    # Malware / C2
    {"threat": "c2_beacon", "severity": "CRITICAL",
     "desc": "Suspicious periodic outbound connection from internal host to {ip} every {t} seconds, encrypted traffic"},
    {"threat": "dns_tunneling", "severity": "HIGH",
     "desc": "DNS tunneling detected: unusually long TXT records to {ip}, {n} queries in {t} seconds"},
    {"threat": "malware_download", "severity": "CRITICAL",
     "desc": "Malicious file download detected: {ip} serving PE executable via HTTP to internal host"},
    {"threat": "ransomware_activity", "severity": "CRITICAL",
     "desc": "Mass file encryption detected: {n} files renamed with .encrypted extension in {t} seconds"},
    # Exfiltration
    {"threat": "data_exfiltration", "severity": "CRITICAL",
     "desc": "Unusual outbound data transfer: {n}MB sent to {ip} over HTTPS in {t} minutes, outside business hours"},
    {"threat": "email_exfiltration", "severity": "HIGH",
     "desc": "Large email attachment ({n}MB) sent to external address, contains compressed archive"},
    # Privilege Escalation
    {"threat": "privilege_escalation", "severity": "CRITICAL",
     "desc": "Privilege escalation attempt: process running as www-data executed sudo su, new root shell spawned"},
    {"threat": "sudo_abuse", "severity": "HIGH",
     "desc": "Unusual sudo command from user on {ip}: sudo chmod 777 /etc/sudoers"},
    # Reconnaissance
    {"threat": "directory_enumeration", "severity": "MEDIUM",
     "desc": "Web directory enumeration from {ip}: {n} 404 requests in {t} seconds using dirbuster patterns"},
    {"threat": "smb_enumeration", "severity": "MEDIUM",
     "desc": "SMB share enumeration from {ip}: net use, net share commands detected"},
    {"threat": "ldap_enumeration", "severity": "HIGH",
     "desc": "LDAP reconnaissance from {ip}: bulk query for all user accounts and groups"},
    # DDoS
    {"threat": "ddos_syn_flood", "severity": "CRITICAL",
     "desc": "SYN flood attack: {n} packets/sec from multiple IPs, server resources at 98%"},
    {"threat": "ddos_http_flood", "severity": "HIGH",
     "desc": "HTTP flood: {n} requests/sec to /api/login from {n} different IPs"},
    # Insider Threat
    {"threat": "insider_threat", "severity": "HIGH",
     "desc": "Employee accessing {n} sensitive files at 03:00 AM, downloading to USB device"},
    {"threat": "credential_stuffing", "severity": "HIGH",
     "desc": "Credential stuffing attack: {n} login attempts with known breached credentials from {ip}"},
    # Lateral Movement
    {"threat": "lateral_movement", "severity": "CRITICAL",
     "desc": "Lateral movement detected: compromised host {ip} attempting SMB connections to {n} internal hosts"},
    {"threat": "pass_the_hash", "severity": "CRITICAL",
     "desc": "Pass-the-hash attack: NTLM authentication with reused hash from {ip} to internal domain controller"},
]

CODE_SCENARIOS = [
    {"task": "vulnerability_review", "lang": "python",
     "prompt": "Review this Python code for security vulnerabilities:\n\n```python\n{code}\n```"},
    {"task": "secure_code", "lang": "python",
     "prompt": "Write a secure Python function to {task} following OWASP best practices"},
    {"task": "exploit_analysis", "lang": "bash",
     "prompt": "Explain what this bash script does and identify any malicious patterns:\n\n```bash\n{code}\n```"},
    {"task": "cve_analysis",
     "prompt": "Analyze CVE-{year}-{num}: describe the vulnerability, affected systems, CVSS score, and mitigation"},
    {"task": "pentest_tool",
     "prompt": "Write a Python script to {task} for authorized penetration testing purposes"},
    {"task": "mitre_attack",
     "prompt": "Describe the MITRE ATT&CK technique {technique} with examples and detection strategies"},
]

RANDOM_IPS = [
    "185.220.101.47", "45.33.32.156", "192.168.1.100", "10.0.0.55",
    "23.129.64.131", "198.51.100.42", "203.0.113.99", "91.108.4.1",
    "77.247.181.165", "104.21.64.0", "172.64.155.200", "5.188.62.140",
    "193.32.162.50", "213.109.202.45", "87.236.176.135"
]

MITRE_TECHNIQUES = [
    "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter",
    "T1053 Scheduled Task/Job", "T1548 Abuse Elevation Control Mechanism",
    "T1055 Process Injection", "T1036 Masquerading",
    "T1027 Obfuscated Files or Information", "T1105 Ingress Tool Transfer",
    "T1071 Application Layer Protocol", "T1041 Exfiltration Over C2 Channel",
]


def random_scenario() -> dict:
    sc = random.choice(CYBER_SCENARIOS).copy()
    sc["desc"] = sc["desc"].format(
        ip=random.choice(RANDOM_IPS),
        n=random.randint(10, 500),
        t=random.randint(5, 300),
    )
    return sc


# ── API call ─────────────────────────────────────────────────────────────────

def call_model(prompt: str, api_url: str, model: str, temperature: float = 0.7) -> str | None:
    try:
        r = requests.post(
            f"{api_url}/chat/completions",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": 1024,
                "stream": False,
            },
            timeout=120,
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
        log.warning("API error %d: %s", r.status_code, r.text[:100])
        return None
    except Exception as e:
        log.warning("Request failed: %s", e)
        return None


def list_models(api_url: str) -> list[str]:
    try:
        r = requests.get(f"{api_url}/models", timeout=10)
        if r.status_code == 200:
            return [m["id"] for m in r.json().get("data", [])]
    except Exception:
        pass
    return []


# ── Generators ───────────────────────────────────────────────────────────────

def generate_cyber_example(api_url: str, model: str) -> dict | None:
    sc = random_scenario()
    prompt = f"""You are an expert cybersecurity AI. Analyze this threat event and respond with a JSON decision.

Threat Type: {sc['threat']}
Severity: {sc['severity']}
Description: {sc['desc']}

Respond ONLY with valid JSON in this exact format:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_type": "{sc['threat']}",
  "confidence": 0.0-1.0,
  "actions": ["action1", "action2"],
  "reasoning": "detailed explanation",
  "escalate_to_human": true/false,
  "ioc": ["indicator1", "indicator2"]
}}

Actions must be chosen from: block_ip, deploy_honeypot, alert_human, monitor, isolate_host, rate_limit, blackhole_route, capture_traffic, notify_soc"""

    response = call_model(prompt, api_url, model, temperature=0.3)
    if not response:
        return None

    # Estrai JSON dalla risposta
    try:
        start = response.find("{")
        end   = response.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(response[start:end])
            return {
                "instruction": "Analyze this cybersecurity threat and return a JSON decision.",
                "input": f"Threat Type: {sc['threat']}\nSeverity: {sc['severity']}\nDescription: {sc['desc']}",
                "output": json.dumps(parsed, ensure_ascii=False),
            }
    except Exception:
        pass

    # Fallback: usa la risposta raw
    if len(response) > 50:
        return {
            "instruction": "Analyze this cybersecurity threat and return a JSON decision.",
            "input": f"Threat Type: {sc['threat']}\nSeverity: {sc['severity']}\nDescription: {sc['desc']}",
            "output": response[:2000],
        }
    return None


def generate_mitre_example(api_url: str, model: str) -> dict | None:
    technique = random.choice(MITRE_TECHNIQUES)
    prompt = f"""Explain the MITRE ATT&CK technique {technique}.
Include: description, how attackers use it, detection methods, and mitigation strategies.
Be specific and technical."""

    response = call_model(prompt, api_url, model, temperature=0.5)
    if response and len(response) > 100:
        return {
            "instruction": f"Explain the MITRE ATT&CK technique {technique} with detection and mitigation strategies.",
            "input": "",
            "output": response[:3000],
        }
    return None


def generate_cve_example(api_url: str, model: str) -> dict | None:
    year = random.randint(2020, 2025)
    num  = random.randint(1000, 99999)
    prompt = f"""Describe a realistic CVE-{year}-{num} style vulnerability.
Include: affected software, vulnerability type, CVSS score (3.x), exploitation method, patch/mitigation.
Make it technically accurate and educational."""

    response = call_model(prompt, api_url, model, temperature=0.6)
    if response and len(response) > 100:
        return {
            "instruction": f"Analyze CVE-{year}-{num}: describe the vulnerability, impact, and mitigation.",
            "input": "",
            "output": response[:3000],
        }
    return None


def generate_code_security_example(api_url: str, model: str) -> dict | None:
    tasks = [
        "implement JWT authentication with proper signature validation",
        "write a rate limiter to prevent brute force attacks",
        "create a SQL query builder that prevents SQL injection",
        "implement input sanitization for a web form",
        "write a secure file upload handler",
        "create a password hashing function using bcrypt",
        "implement CSRF token validation",
        "write a secure random token generator",
        "create a function to detect XSS in user input",
        "implement 2FA verification logic",
    ]
    task = random.choice(tasks)
    lang = random.choice(["Python", "JavaScript", "Go", "Bash"])

    prompt = f"""Write a secure {lang} implementation to {task}.
Follow security best practices and add comments explaining the security measures."""

    response = call_model(prompt, api_url, model, temperature=0.4)
    if response and len(response) > 100:
        return {
            "instruction": f"Write a secure {lang} function to {task} following security best practices.",
            "input": "",
            "output": response[:4000],
        }
    return None


# ── Main ─────────────────────────────────────────────────────────────────────

GENERATORS = {
    "cyber":  generate_cyber_example,
    "mitre":  generate_mitre_example,
    "cve":    generate_cve_example,
    "code":   generate_code_security_example,
}


def detect_api() -> tuple[str, list[str]]:
    """Trova LM Studio o Ollama automaticamente."""
    for url in [LM_STUDIO_URL, OLLAMA_URL]:
        models = list_models(url)
        if models:
            log.info("API trovata: %s (%d modelli)", url, len(models))
            return url, models
    return LM_STUDIO_URL, []


def main():
    p = argparse.ArgumentParser(description="ARGOS training data generator")
    p.add_argument("--count",    type=int, default=5000,
                   help="Numero di esempi da generare (default: 5000)")
    p.add_argument("--category", choices=list(GENERATORS.keys()) + ["all"],
                   default="all", help="Categoria di esempi")
    p.add_argument("--model",    default=None,
                   help="Nome modello (auto-detect se non specificato)")
    p.add_argument("--api",      default=None,
                   help="URL API (default: auto-detect LM Studio/Ollama)")
    p.add_argument("--list-models", action="store_true",
                   help="Mostra modelli disponibili ed esci")
    p.add_argument("--output",   default=None,
                   help="File output JSONL (default: auto)")
    args = p.parse_args()

    # Detect API
    api_url, available_models = detect_api()
    if args.api:
        api_url = args.api
        available_models = list_models(api_url)

    if args.list_models:
        print("\nModelli disponibili:")
        for m in available_models:
            print(f"  {m}")
        return

    if not available_models:
        log.error("Nessun modello trovato. Assicurati che LM Studio sia aperto con un modello caricato.")
        log.error("LM Studio → Local Server → Start Server")
        raise SystemExit(1)

    # Scegli modello
    model = args.model or available_models[0]
    log.info("Modello selezionato: %s", model)

    # Output file
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = Path(args.output) if args.output else (
        OUTPUT_DIR / f"generated_{args.category}_{timestamp}.jsonl"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Scegli generatori
    if args.category == "all":
        gen_funcs = list(GENERATORS.values())
    else:
        gen_funcs = [GENERATORS[args.category]]

    log.info("=" * 60)
    log.info("ARGOS Training Data Generator")
    log.info("Modello:   %s", model)
    log.info("Categoria: %s", args.category)
    log.info("Obiettivo: %d esempi", args.count)
    log.info("Output:    %s", output_path)
    log.info("=" * 60)

    written  = 0
    failed   = 0
    start_t  = time.time()

    with open(output_path, "w") as f, tqdm(total=args.count, unit="esempi") as pbar:
        while written < args.count:
            gen_fn = random.choice(gen_funcs)
            example = gen_fn(api_url, model)

            if example and example.get("output", "").strip():
                f.write(json.dumps(example, ensure_ascii=False) + "\n")
                f.flush()
                written += 1
                pbar.update(1)

                # ETA
                elapsed  = time.time() - start_t
                rate     = written / elapsed if elapsed > 0 else 0
                remaining = (args.count - written) / rate if rate > 0 else 0
                pbar.set_postfix({
                    "ok": written,
                    "fail": failed,
                    "rate": f"{rate:.1f}/min" if rate > 0 else "...",
                    "ETA": f"{remaining/3600:.1f}h" if remaining > 3600 else f"{remaining/60:.0f}min"
                })
            else:
                failed += 1

    elapsed_h = (time.time() - start_t) / 3600
    log.info("=" * 60)
    log.info("Completato: %d esempi generati in %.1f ore", written, elapsed_h)
    log.info("Falliti: %d", failed)
    log.info("Output: %s (%.1f MB)", output_path, output_path.stat().st_size / 1e6)
    log.info("=" * 60)
    log.info("Prossimo step: copia su server e aggiungi al training")
    log.info("  rsync %s root@<SERVER_IP>:/opt/argos/training/datasets/foundational/", output_path)


if __name__ == "__main__":
    main()
