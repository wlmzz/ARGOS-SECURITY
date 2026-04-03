#!/usr/bin/env python3
"""
ARGOS — Attack Simulation
Sends realistic threat events to the server so you can watch the AI decide in real-time.
Usage: python simulate.py
"""

import json
import time
import random
import requests

SERVER = "http://localhost:8443"

# ─── Palette of realistic attack scenarios ────────────────────────────────────

SCENARIOS = [
    {
        "label": "🔴  SSH Brute Force (Tor exit node)",
        "threat_type": "brute_force",
        "severity": "critical",
        "source_ip": "185.220.101.42",
        "target_port": 22,
        "protocol": "ssh",
        "description": "2341 failed SSH login attempts in 4 minutes from known Tor exit node",
    },
    {
        "label": "🟠  Port Scan (reconnaissance)",
        "threat_type": "port_scan",
        "severity": "high",
        "source_ip": "92.118.39.22",
        "target_port": 0,
        "protocol": "tcp",
        "description": "SYN scan across 1450 ports in under 60 seconds",
    },
    {
        "label": "🔴  Ransomware detected",
        "threat_type": "ransomware",
        "severity": "critical",
        "source_ip": "127.0.0.1",
        "target_port": 0,
        "protocol": "process",
        "description": "Process encrypting 1200 files in /Users with .locked extension — 30 sec window",
    },
    {
        "label": "🟡  Suspicious outbound connection",
        "threat_type": "data_exfiltration",
        "severity": "high",
        "source_ip": "10.0.0.5",
        "target_port": 443,
        "protocol": "https",
        "description": "2.3 GB outbound transfer to unknown server in Romania over 10 minutes",
    },
    {
        "label": "🟠  Cryptominer process",
        "threat_type": "cryptominer",
        "severity": "medium",
        "source_ip": "127.0.0.1",
        "target_port": 3333,
        "protocol": "tcp",
        "description": "Process 'chrome_helper' connecting to known mining pool stratum+tcp://pool.minexmr.com:3333",
    },
    {
        "label": "🔴  DDoS — volumetric UDP flood",
        "threat_type": "ddos",
        "severity": "critical",
        "source_ip": "0.0.0.0",
        "target_port": 53,
        "protocol": "udp",
        "description": "14 Gbps UDP flood on port 53 from 3200 spoofed source IPs — amplification attack",
    },
    {
        "label": "🟡  FTP scan on legacy port",
        "threat_type": "port_scan",
        "severity": "medium",
        "source_ip": "45.83.64.1",
        "target_port": 21,
        "protocol": "tcp",
        "description": "Repeated connection attempts to FTP port 21 — possible legacy service exploit attempt",
    },
    {
        "label": "🟠  SSH brute force (LAN)",
        "threat_type": "brute_force",
        "severity": "high",
        "source_ip": "192.168.1.55",
        "target_port": 22,
        "protocol": "ssh",
        "description": "Internal host attempting 400+ SSH logins against domain controller",
    },
    {
        "label": "🔴  Malware process (reverse shell)",
        "threat_type": "malware",
        "severity": "critical",
        "source_ip": "127.0.0.1",
        "target_port": 4444,
        "protocol": "tcp",
        "description": "Process '/tmp/.x' opening outbound connection to C2 server on port 4444 — Meterpreter signature",
    },
    {
        "label": "🟡  Anomalous DNS queries",
        "threat_type": "dns_anomaly",
        "severity": "medium",
        "source_ip": "10.0.0.12",
        "target_port": 53,
        "protocol": "dns",
        "description": "Host resolving 800 unique domains in 2 minutes — possible DNS tunneling or C2 beaconing",
    },
]

# ─── Setup ────────────────────────────────────────────────────────────────────

def register():
    r = requests.post(f"{SERVER}/api/devices/register",
                      json={"name": "simulator", "platform": "darwin"},
                      timeout=5)
    r.raise_for_status()
    d = r.json()
    print(f"  Registered device: {d['device_id'][:16]}...")
    return d["device_id"], d["token"]


def send_event(device_id, token, scenario):
    payload = {
        "device_id": device_id,
        "threat_type": scenario["threat_type"],
        "severity": scenario["severity"],
        "source_ip": scenario["source_ip"],
        "target_port": scenario.get("target_port", 0),
        "protocol": scenario.get("protocol", "tcp"),
        "description": scenario["description"],
        "raw_data": {},
    }
    r = requests.post(
        f"{SERVER}/api/events",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=90,
    )
    return r.json()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n\033[36m╔══════════════════════════════════════╗\033[0m")
    print("\033[36m║      ARGOS Attack Simulator          ║\033[0m")
    print("\033[36m╚══════════════════════════════════════╝\033[0m\n")
    print("  Dashboard → http://localhost:3000\n")

    device_id, token = register()

    scenarios = SCENARIOS.copy()
    random.shuffle(scenarios)

    for i, scenario in enumerate(scenarios, 1):
        print(f"[{i:02d}/{len(scenarios)}] {scenario['label']}")
        print(f"        source: {scenario['source_ip']}  →  port {scenario['target_port']}")

        try:
            result = send_event(device_id, token, scenario)
            decision = result.get("ai_decision", {})
            action = decision.get("action", "?")
            confidence = decision.get("confidence", 0)
            reasoning = decision.get("reasoning", "")[:80]
            escalate = decision.get("escalate_to_human", False)
            layer = "AI" if len(reasoning) > 40 else "rules"

            color = "\033[31m" if action in ("block_ip", "isolate_process") else \
                    "\033[33m" if action in ("deploy_honeypot", "close_port") else "\033[32m"

            print(f"        {color}→ {action}\033[0m  (confidence: {confidence:.2f}, layer: {layer})")
            print(f"        {reasoning}")
            if escalate:
                print("        \033[35m⚠ Escalation to human requested\033[0m")
        except Exception as e:
            print(f"        \033[31m✗ Error: {e}\033[0m")

        print()

        # Pause between events (shorter for last one)
        if i < len(scenarios):
            delay = random.uniform(4, 8)
            time.sleep(delay)

    print("\033[32m✓ Simulation complete — check the dashboard!\033[0m\n")


if __name__ == "__main__":
    main()
