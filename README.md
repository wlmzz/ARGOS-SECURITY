<p align="center">
  <img src="assets/logo.png" alt="ARGOS Logo" width="500"/>
</p>

# ARGOS — Open Source AI Security Platform

> **Security is a right, not a privilege.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Status](https://img.shields.io/badge/status-alpha-orange)]()
[![Tools](https://img.shields.io/badge/tools-332%20total-green)]()
[![Plugins](https://img.shields.io/badge/plugins-84-green)]()

ARGOS is a free, open-source, AI-powered cybersecurity platform that protects any device or infrastructure — from a single laptop to a complex server network — without requiring enterprise budgets or cloud vendor lock-in.

Named after Argos Panoptes, the giant of Greek mythology with a hundred eyes who never slept, ARGOS watches everything, reasons about threats in real time, and responds autonomously so you don't have to.

---

## Table of Contents

- [Why ARGOS](#why-argos)
- [Features](#features)
- [Architecture](#architecture)
- [Agent Architecture](#agent-architecture)
- [Deployment Modes](#deployment-modes)
- [Hardware Requirements](#hardware-requirements)
- [Installation](#installation)
- [Running the Agent](#running-the-agent)
- [Configuration](#configuration)
- [The AI Engine](#the-ai-engine)
- [Threat Detection](#threat-detection)
- [Autonomous Response](#autonomous-response)
- [Realtime Defense](#realtime-defense)
- [Honeypot System](#honeypot-system)
- [Built-in Tools (37)](#built-in-tools)
- [Plugin System (84 plugins, 332 tools)](#plugin-system)
- [Subagent Orchestration](#subagent-orchestration)
- [Complete Pentest Workflow](#complete-pentest-workflow)
- [Dashboard](#dashboard)
- [Mobile App](#mobile-app)
- [Community Intelligence](#community-intelligence)
- [Development Roadmap](#development-roadmap)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)
- [Manifesto](#manifesto)

---

## Why ARGOS

The cybersecurity industry is broken. Enterprise-grade protection — the kind that actually works against modern threats — costs tens of thousands of euros per year. CrowdStrike, Darktrace, Palo Alto Networks: tools that are genuinely excellent, but priced exclusively for large organizations.

Everyone else — small businesses, freelancers, journalists, activists, nonprofits, individuals — is left with basic antivirus software that matches known signatures and misses everything else.

ARGOS exists to close that gap permanently.

- **Free forever.** The software costs nothing. No subscriptions, no tiers, no paywalls.
- **Open source.** Every line of code is public. Audit it, improve it, fork it.
- **Self-hostable.** No mandatory cloud. Your data stays on your hardware.
- **AI-powered.** Reasoning, not just pattern matching. Detects what signatures can't.
- **Cross-platform.** One agent runs on Linux, macOS, and Windows identically.

---

## Features

### Detection
- Real-time network traffic analysis and anomaly detection
- Port scan detection with automatic honeypot deployment
- Brute force and credential stuffing detection
- DDoS identification and mitigation
- Process monitoring — ransomware, cryptominers, rootkits, privilege escalation
- Filesystem integrity monitoring
- Lateral movement detection
- Behavioral analysis — detects threats even without known signatures
- Repeat offender tracking across sessions
- Geolocation and ASN attribution of attack sources

### Response (Autonomous)
- Immediate IP blocking via native OS firewall (iptables / pf / Windows Firewall)
- Realtime watcher — bans within seconds, 24/7 (systemd service)
- Nightly analysis — aggregated report + ban at 02:00 via cron
- Dynamic honeypot deployment on attacked ports
- Process suspension and isolation
- Evidence collection (forensic-grade, ready for law enforcement)
- Formal law enforcement reports (Polizia Postale, CSIRT-IT, Europol, FBI IC3)
- Automated incident reports in `/opt/argos/reports/`

### Intelligence (282 tools total)
- **37 built-in tools**: nmap, masscan, nuclei, CVE lookup, Shodan, AbuseIPDB, theHarvester, Sherlock, Lynis, UFW, fail2ban, honeypot engine, log analysis, attribution reports
- **241 plugin tools across 76 hot-loadable plugins: VirusTotal, GreyNoise, AlienVault OTX, Censys, Hybrid Analysis, SpiderFoot, and much more
- WHOIS, RDAP, ASN attribution + abuse contacts
- Community threat sharing (opt-in)

### Pentesting (authorized use only)
- **Autonomous 84-phase pentest pipeline**: white-box code analysis → recon → 5 parallel vuln specialists → 5 parallel exploit agents → executive report (inspired by Shannon/Keygraph)
- AI pentest agents: PentestGPT, PentAGI, Pentest Copilot, Nebula AI, Pentest-Swarm (5 AI agents)
- Offensive CLI: Sn1per, NetExec (SMB/SSH/LDAP/WinRM), Gobuster, Nettacker (200+ modules)
- Web recon: rapidscan, Vaile, Astra REST API, skipfish (10,000+ checks)
- Payload library: XSS/SQLi/CMDi/XXE, reverse shells (11 types), LFI/RFI, SSTI (8 engines)
- Red team infrastructure: C2 frameworks (emp3r0r), phishing infra (Overlord + Terraform)
- MITRE ATT&CK simulation: Red Canary Atomic Red Team
- DoS resilience testing: MHDDoS (57 methods), Impulse, DDoS-Ripper, Kraken
- Social engineering testing: seeker, Storm-Breaker, maskphish
- WordPress scanning: WPScan (vulnerabilities, user enum, brute-force)
- IoT pentesting: MQTT, CoAP, Modbus, BACnet, default credential testing

### AI Engine
- **Seneca-Cybersecurity-LLM-x-QwQ-32B** — custom fine-tuned model running via llama.cpp
- No threat data leaves your network during analysis
- Falls back to rule-based engine if AI is offline
- Escalates unprecedented threats to Claude API (optional)
- Custom fine-tuning pipeline: 8 professor models generating training examples
- Model improves continuously with incident feedback

### Interfaces
- **CLI** — full control from the terminal
- **Telegram bot** — remote access, real-time alerts, commands from anywhere
- **Discord bot** — WebSocket gateway + HTTP fallback
- **Webhook** — HTTP server with rate limiting + auth
- **React web dashboard** — real-time monitoring, threat history, device management, WebSocket

---

## Architecture

ARGOS uses a three-layer defense architecture. Each layer handles what it does best, and every unresolved event escalates to the next.

```
┌─────────────────────────────────────────────────────────┐
│                    PROTECTED DEVICES                     │
│          Windows · macOS · Linux · Servers               │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                  LAYER 1 — AGENT                         │
│                                                          │
│  • Network traffic monitor (psutil + Scapy)              │
│  • Process monitor                                       │
│  • Filesystem monitor                                    │
│  • Authentication log parser                             │
│  • Instant response to known/simple threats              │
│  • Evidence collection                                   │
│  • Realtime watcher (systemd, 24/7)                      │
└──────────────────────┬──────────────────────────────────┘
                       │  Complex or unknown threats
┌──────────────────────▼──────────────────────────────────┐
│              LAYER 2 — AI CORE (LOCAL)                   │
│                                                          │
│  • Seneca-Cybersecurity-LLM-x-QwQ-32B via llama.cpp      │
│  • Behavioral analysis and contextual reasoning          │
│  • Honeypot orchestration                                │
│  • Multi-device correlation                              │
│  • Continuous fine-tuning on your environment            │
│  • 254 tools + 76 hot-loadable plugins                   │
└──────────────────────┬──────────────────────────────────┘
                       │  Unprecedented / high-stakes cases
┌──────────────────────▼──────────────────────────────────┐
│              LAYER 84 — ESCALATION                        │
│                                                          │
│  • Telegram / Discord → human decision                   │
│  • Claude API → advanced reasoning on complex threats    │
│  • All decisions returned as training data to Layer 2    │
└─────────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│               FEEDBACK & INTELLIGENCE                    │
│                                                          │
│  • Every resolved incident improves the local model      │
│  • Community threat sharing (opt-in)                     │
│  • Incident reports generated for authorities            │
└─────────────────────────────────────────────────────────┘
```

---

## Agent Architecture

```
main.py
  ├── channels/telegram.py    ← remote access via Telegram bot
  ├── channels/discord.py     ← Discord bot (WebSocket gateway + HTTP fallback)
  ├── channels/webhook.py     ← HTTP webhook server with rate limiting + auth
  ├── orchestrator.py         ← parallel subagent execution (ThreadPoolExecutor)
  ├── plugin_loader.py        ← dynamic plugin discovery + hot-reload
  ├── audit.py                ← tamper-evident audit log (SHA256 chain)
  └── agent.py                ← core agentic loop (tool-calling)
        ├── session.py        ← conversation history + compaction
        ├── tools/
        │     ├── network.py       ← nmap, masscan, ping, DNS, WHOIS
        │     ├── osint.py         ← CVE lookup, IP rep, Shodan, hash check, IOC extraction
        │     ├── osint_advanced.py← theHarvester, Sherlock, ipwhois, subdomain enum
        │     ├── analysis.py      ← log analysis, threat detection, report generation, ban_ip
        │     ├── vuln.py          ← nuclei vulnerability scan, whatweb, SSL check
        │     ├── attribution.py   ← AbuseIPDB, attacker dossier, law enforcement report
        │     ├── hardening.py     ← Lynis audit, SSH hardening, UFW firewall, auto-harden
        │     └── honeypot.py      ← deploy/manage honeypots, read attacker captures
        └── plugins/               ← hot-loadable plugin modules (84 plugins, 332 tools)
              ├── example_virustotal.py  ← VirusTotal hash/URL/IP scans
              ├── greynoise.py           ← GreyNoise noise vs. targeted threat classification
              ├── alienvault_otx.py      ← AlienVault OTX — 20M+ threat indicators
              ├── urlscan.py             ← URLScan.io URL sandbox analysis
              ├── threatfox_urlhaus.py   ← ThreatFox IOCs + URLHaus malware URLs (abuse.ch)
              ├── hibp.py                ← Have I Been Pwned (passwords + email breaches)
              ├── censys.py              ← Censys internet scan data (ports, certs, banners)
              ├── hybrid_analysis.py     ← Falcon Sandbox malware analysis
              ├── ipinfo.py              ← IPInfo geo/ASN/abuse/VPN/TOR detection
              ├── ssl_labs.py            ← Qualys SSL Labs deep TLS analysis (grade A-F)
              ├── emailrep.py            ← EmailRep + Pulsedive threat enrichment
              ├── sn1per.py              ← Sn1per automated attack surface management
              ├── netexec.py             ← NetExec: SMB/SSH/LDAP/WinRM pentest (authorized)
              ├── gobuster.py            ← Gobuster dir/DNS brute-force
              ├── tpot.py                ← T-Pot honeypot Elasticsearch queries
              ├── ip2location.py         ← IP2Location: ISP/usage type/VPN/TOR detection
              ├── opencti.py             ← OpenCTI threat intelligence platform
              ├── pentestgpt.py          ← PentestGPT autonomous AI pentest agent (USENIX 2024)
              ├── pentagi.py             ← PentAGI multi-agent pentest platform (REST/GraphQL)
              ├── offensive_payloads.py  ← Payload library for WAF testing (XSS/SQLi/CMDi/XXE)
              ├── reverse_shells.py      ← Reverse shell generator (PHP obfuscated, bash, Python, PS)
              ├── pentest_copilot.py     ← Pentest Copilot AI agent (real Kali + Burp Suite)
              ├── pentest_report.py      ← Professional pentest report generator (HTML/Markdown/JSON)
              ├── stress_test.py         ← DoS resilience: MHDDoS (57 methods) + Impulse + Kraken
              ├── power_pwn.py           ← Microsoft 365 / Power Platform pentesting
              ├── cloakify.py            ← DLP evasion testing: data exfil obfuscation
              ├── llm_redteam.py         ← LLM adversarial: jailbreaks, prompt injection, L1B3RT4S
              ├── pentest_swarm.py       ← Pentest-Swarm-AI: 5-agent swarm (subfinder/httpx/nuclei)
              ├── emp3r0r.py             ← emp3r0r C2 framework: Linux/Windows implants
              ├── nettacker.py           ← OWASP Nettacker: 200+ scan modules, REST API
              ├── web_recon.py           ← rapidscan + Vaile + Astra REST API + skipfish
              ├── overlord.py            ← Red team infra: C2/redirectors/phishing via Terraform
              ├── pentest_frameworks.py  ← fsociety + DarkSpiritz + KaliIntelligenceSuite
              ├── iot_pentest.py         ← IoT: MQTT/CoAP/Modbus/BACnet + default creds
              ├── atomic_red_team.py     ← MITRE ATT&CK atomic test execution (Red Canary)
              ├── spiderfoot.py          ← SpiderFoot OSINT: 400+ modules
              ├── hak5_payloads.py       ← Hak5: OMG Cable, BashBunny, KeyCroc, SharkJack
              ├── username_osint.py      ← Username recon across 200+ platforms + Instagram
              ├── wordpress_scan.py      ← WPScan: WordPress vuln scanner
              ├── social_engineering.py  ← seeker + Storm-Breaker + maskphish
              ├── nebula.py              ← Nebula AI pentesting assistant (natural language)
              └── hacktools.py           ← LFI/RFI, SSTI (8 engines), encoders, headers
```

---

## Deployment Modes

ARGOS supports three deployment modes. You choose at installation and can switch at any time.

### Standalone
Everything runs on the device being protected. No external connections. No account required. Ideal for privacy-conscious individuals and air-gapped environments.

- AI model runs locally on the device
- No data leaves the machine, ever
- Works completely offline

### Self-Hosted (Recommended)
You run an ARGOS server on your own infrastructure. All your devices connect to it. The heavy AI computation happens on your server, keeping device agents lightweight.

- Full control over all data
- One server protects unlimited devices
- Shared intelligence across your own network
- Best performance — server handles all AI workload
- Ideal for businesses, home labs, multi-device setups

### Cloud
Devices connect to the community ARGOS server. You pay only the real infrastructure cost — no markup, no profit.

- Minimal device hardware requirements
- Community-powered threat intelligence
- Pay-as-you-go infrastructure cost only

---

## Hardware Requirements

### Agent (device being protected)
Any device capable of running Python 3.10+. The agent is intentionally lightweight.

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | Any dual-core | Any modern CPU |
| RAM | 256 MB free | 512 MB free |
| Disk | 100 MB | 500 MB (for logs) |
| OS | Linux / macOS / Windows | Linux (best firewall support) |

### Server (self-hosted mode)

| Component | Minimum (8B model) | Recommended (32B model) | High-end (70B+) |
|-----------|--------------------|------------------------|-----------------|
| CPU | 8 cores | 16 cores (EPYC/Threadripper) | 32+ cores |
| RAM | 32 GB | 64–128 GB | 256 GB |
| Storage | 100 GB SSD | 500 GB NVMe | 1 TB NVMe |
| GPU | Not required | Optional (speeds up inference) | NVIDIA 24+ GB VRAM |

**Reference hardware tested:** AMD EPYC 7302P, 128 GB DDR4 ECC, 960 GB NVMe. Runs Seneca-Cybersecurity-LLM-x-QwQ-32B quantized at real-time analysis speeds with no GPU.

### Model Size Reference

| Model | RAM (quantized) | Quality | Notes |
|-------|-----------------|---------|-------|
| LLaMA 3.2 8B | ~6 GB | Good | Lightweight option |
| Phi-4 14B | ~10 GB | Good | Fast, low resource |
| Seneca-32B (QwQ) | ~20 GB | **Excellent** | **Default — fine-tuned for cybersecurity** |
| LLaMA 3.1 70B | ~45 GB | Excellent | High accuracy |
| LLaMA 3.1 405B | ~200 GB | Maximum | Research/high-end |

---

## Installation

### Quick Start — Plug & Play (Ubuntu 24.04)

Clone and run the installer on your server:

```bash
git clone https://github.com/argos-security/argos.git /opt/argos/app
cd /opt/argos/app
sudo bash installer/install.sh        # base system + realtime watcher
sudo bash install_tools.sh            # all security CLI tools
```

Start all services (auto-restart on reboot via systemd):

```bash
systemctl start argos-llama     # Seneca-32B LLM    :8080
systemctl start argos-server    # FastAPI API        :7070  (proxied → :80)
systemctl start argos-watcher   # Realtime watcher
systemctl start bloodhound-ce   # BloodHound CE      :8890
```

**Done.** Connect any device to `http://YOUR_SERVER_IP` — no extra config needed.

---

### Connect from Any Device

| Endpoint | URL | Description |
|---|---|---|
| **ARGOS API** | `http://YOUR_SERVER_IP/` | FastAPI — chat, events, devices |
| **ARGOS API (direct)** | `http://YOUR_SERVER_IP:7070/` | Direct, bypasses proxy |
| **Health check** | `http://YOUR_SERVER_IP/health` | `{"status":"ok"}` |
| **WebSocket** | `ws://YOUR_SERVER_IP/ws/{client_id}` | Real-time event stream |
| **BloodHound CE** | `http://YOUR_SERVER_IP:8890/` | AD attack path analysis |
| **Qdrant** | `http://YOUR_SERVER_IP:6333` | Vector DB |
| **SearXNG** | `http://YOUR_SERVER_IP:8888` | Private search |
| **LLM (Seneca)** | `http://YOUR_SERVER_IP:8080/v1` | OpenAI-compatible API |

> BloodHound CE default credentials: `admin` / `ArgosBloodhound2024!` — change on first login.

---

### Install All Security CLI Tools

```bash
# Installs: semgrep, bandit, trivy, yara, clamav, zeek, suricata,
# volatility3, ffuf, sqlmap, nikto, osv-scanner, impacket, garak
sudo bash install_tools.sh

# Skip Metasploit (~2 GB):
sudo bash install_tools.sh --skip-heavy
```

---

### Manual Setup (custom server)

```bash
# 1. LLM — llama.cpp with Seneca-32B
/opt/llama.cpp/build/bin/llama-server \\
  --model /opt/argos/models/argos-current.gguf \\
  --threads 28 --ctx-size 8192 --port 8080

# 2. API server
cd /opt/argos/app
pip install -r server/requirements-server.txt
python3 -m uvicorn server.server:app --host 0.0.0.0 --port 7070

# 3. BloodHound CE
cd /opt/bloodhound && docker compose up -d
```

---

### Environment Variables

```bash
cp .env.example /opt/argos/.env
nano /opt/argos/.env
```

Key variables:

```bash
LLAMA_SERVER_URL=http://localhost:8080
QDRANT_URL=http://localhost:6333
SEARXNG_URL=http://localhost:8888
BLOODHOUND_HOST=localhost
BLOODHOUND_PORT=8890

# Intel APIs (all optional, free tiers available)
SHODAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```
## Running the Agent

```bash
cd /opt/argos/agent

# CLI mode (interactive)
python3 main.py --mode cli

# Telegram bot mode
python3 main.py --mode telegram --token YOUR_BOT_TOKEN --allowed-ids 123456789

# Discord bot mode
python3 main.py --mode discord --token YOUR_DISCORD_TOKEN

# Webhook mode (HTTP API)
python3 main.py --mode webhook --port 9090 --auth-token YOUR_SECRET
```

### Telegram Setup

1. Create bot via @BotFather → get token
2. Get your chat ID: message @userinfobot
3. Run: `python3 main.py --mode telegram --token TOKEN --allowed-ids YOUR_CHAT_ID`

Once running, you can send any natural language command via Telegram and ARGOS will execute it — scan ports, look up CVEs, analyze logs, run pentests, generate reports.

---

## Configuration

### Environment Variables

```bash
# Add to /etc/environment
ARGOS_LLM_URL=http://localhost:8080/v1/chat/completions
ARGOS_LLM_KEY=your_api_key           # if llama.cpp requires auth

# Intelligence APIs (all optional, free tiers available)
SHODAN_API_KEY=your_key              # shodan.io/account — free
ABUSEIPDB_API_KEY=your_key          # abuseipdb.com/register — 1000 checks/day free
VIRUSTOTAL_API_KEY=your_key         # virustotal.com/gui/join-us — free
GREYNOISE_API_KEY=your_key          # greynoise.io — optional (community works without)
OTX_API_KEY=your_key                # otx.alienvault.com — free
URLSCAN_API_KEY=your_key            # urlscan.io — 100/day free
CENSYS_API_ID=your_id               # censys.io — 250/month free
CENSYS_API_SECRET=your_secret
HYBRID_ANALYSIS_API_KEY=your_key    # hybrid-analysis.com — free
IPINFO_TOKEN=your_token             # ipinfo.io — 50K/month free
IP2LOCATION_API_KEY=your_key        # ip2location.io — 30K/month free
HIBP_API_KEY=your_key               # haveibeenpwned.com (~$3.50/month)
EMAILREP_API_KEY=your_key           # emailrep.io — optional
PULSEDIVE_API_KEY=your_key          # pulsedive.com — optional
OPENCTI_URL=http://your-opencti:4000
OPENCTI_TOKEN=your-api-token
TPOT_HOST=your-tpot-ip              # T-Pot server IP

# Pentest tools
WPSCAN_API_TOKEN=your_token         # wpscan.com/register — free, full CVE data
SPIDERFOOT_URL=http://localhost:5001 # if running SpiderFoot as server
NEBULA_MODEL=llama3                  # Ollama model for Nebula AI
POWERPWN_AUTH_TOKEN=your_token      # Microsoft 365 auth token
PENTAGI_URL=http://localhost:8090
PENTAGI_TOKEN=your_token
PENTEST_COPILOT_URL=http://localhost:8888
```

### AbuseIPDB Setup (Free — 1000 checks/day)

1. Register at [abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Go to Account → API → create a key
3. Add it to the server:
   ```bash
   echo 'ABUSEIPDB_API_KEY=your_key_here' >> /etc/environment
   source /etc/environment
   ```

With the key active, ARGOS can:
- Check the abuse score (0-100) of every attacking IP
- See the attack history reported by 700,000+ organizations worldwide
- **Automatically report** attackers to the global database after every ban
- Include the score in the law enforcement dossier

### Autonomy Levels

| Level | Behavior |
|-------|----------|
| `full` | Acts immediately on all threats without asking. Highest protection, no human oversight. |
| `semi` | Acts automatically on high-confidence threats (>0.7). Escalates ambiguous cases to Telegram. **Default.** |
| `supervised` | Never acts alone. Logs all recommended actions and sends them for approval. |

---

## The AI Engine

### Seneca-Cybersecurity-LLM-x-QwQ-32B

ARGOS uses a custom fine-tuned model based on QwQ-32B, specifically trained for cybersecurity tasks:

- Trained by 8 specialized "professor" models, each an expert in a security domain
- Training data: offensive security, defensive analysis, threat intelligence, MITRE ATT&CK
- Runs via llama.cpp OpenAI-compatible API on port 8080
- No GPU required — runs on CPU-only servers
- Context window: 8192 tokens

The AI engine receives a structured description of each threat event and returns a JSON decision:

```json
{
  "severity_confirmed": true,
  "action": "deploy_honeypot",
  "reasoning": "Port scan pattern from known-bad ASN. Honeypot will collect attacker TTPs.",
  "confidence": 0.94,
  "escalate_to_human": false
}
```

Available actions: `block_ip`, `deploy_honeypot`, `isolate_process`, `close_port`, `alert_human`, `monitor`.

### Fallback Chain

```
Threat detected
      ↓
llama.cpp available?
  ↙         ↘
Yes           No
AI analysis   Rule-based fallback
      ↓
Confidence < 0.7 or escalate_to_human?
  ↙                               ↘
Telegram/Discord notification   Execute action autonomously
      ↓
Human decides
      ↓
Decision → training data
      ↓
Model fine-tuning (weekly via RunPod)
```

### Claude API Escalation (Optional)

For threats the local model cannot classify with confidence, ARGOS can call the Claude API:

- Only triggered for truly unprecedented events
- Costs minimal API credits (typically a few calls per month)
- Every Claude response is saved as fine-tuning data for the local model
- Over time, the local model learns to handle these cases independently

```bash
# Enable in config
CLAUDE_API_KEY=sk-ant-...
```

### Fine-Tuning Pipeline

The model is fine-tuned on accumulated incident data via RunPod:

1. 8 professor models generate training examples (each expert in a security domain)
2. Collect resolved incidents from the server database
3. Format as instruction-tuning pairs
4. Run LoRA fine-tuning on QwQ-32B base (low memory overhead)
5. Evaluate accuracy on held-out validation set
6. Atomic model replacement on production server (no downtime)

---

## Threat Detection

### Network Threats

| Threat | Detection Method | Default Action |
|--------|-----------------|----------------|
| Port scan | >10 unique ports probed in 60s from same IP | Deploy honeypot |
| Brute force | >5 failed auth attempts in 30s | Block IP |
| DDoS | Traffic volume spike + packet analysis | Rate limit + filter |
| C2 communication | Beacon pattern detection in outbound traffic | Block + alert |
| Data exfiltration | Unusual outbound volume to new external IPs | Alert + throttle |
| Repeat offender | IP matches previous incident history | Immediate block |

### Process Threats

| Threat | Detection Method | Default Action |
|--------|-----------------|----------------|
| Cryptominer | CPU >85% sustained, name/cmdline matching | Suspend + alert |
| Ransomware | Mass file modification pattern | Suspend + isolate |
| Rootkit | Suspicious system calls, hidden processes | Alert human |
| Privilege escalation | Unexpected privilege changes | Alert + log |
| Reverse shell | Suspicious outbound connection from system process | Block + alert |

### Behavioral Analysis

Beyond rule-based detection, the AI engine analyzes behavioral context:

- Login at unusual hours with valid credentials → monitor + restrict
- New device appears on internal network → quarantine until verified
- Process opens network connection it never has before → log + alert
- File access pattern matches known exfiltration behavior → alert

---

## Autonomous Response

### IP Blocking

ARGOS integrates natively with the OS firewall on each platform:

**Linux (iptables/fail2ban)**
```bash
iptables -A INPUT -s <IP> -j DROP
iptables -A OUTPUT -d <IP> -j DROP
```

**macOS (pf)**
```bash
pfctl -t argos_blocked -T add <IP>
```

**Windows (netsh)**
```
netsh advfirewall firewall add rule name=ARGOS_BLOCK_<IP> dir=in action=block remoteip=<IP>
```

### Process Control

Suspicious processes are suspended (not killed by default) so evidence is preserved. The process can be resumed, terminated, or submitted for deeper analysis.

### Network Isolation

In critical situations (confirmed ransomware, active data exfiltration), ARGOS can isolate a device from the network entirely while keeping it accessible from a management VLAN for investigation.

---

## Realtime Defense

### Automatic Threat Enrichment

When the realtime watcher bans an IP, it automatically runs a threat intelligence enrichment in a background thread:

1. **Geolocation + ASN** — country, city, ISP, ASN (ip-api.com, no key)
2. **WHOIS** — netname, org, abuse contact
3. **ThreatFox** — checks if IP is a known malware C2 or IOC (abuse.ch, no key)
4. **Profile saved** to `/opt/argos/logs/ip_profiles.jsonl`
5. **Enriched Telegram alert** (if configured) with country, org, threat flags

So every banned IP immediately gets a profile like:

```
PROFILE 116.99.172.210 | Vietnam (VN) / Huế | Viettel Group | AS24086
PROFILE 195.178.110.218 | Andorra (AD) | Techoff SRV Limited | AS48090 | VPS/hosting
```

### Ask ARGOS to Investigate

The `ip-investigator` plugin gives ARGOS the same investigation capabilities:

```
You: "chi ci ha attaccato stanotte?"
ARGOS → investigate_attackers(hours=12) + analyze_attack_patterns()
     → geo, ASN, WHOIS, ThreatFox per ogni IP
     → identifica campagne coordinate per ASN/subnet
     → categorizza username (crypto targeting, generic, service)
```

ARGOS has two active defense layers running simultaneously:

| | Realtime Watcher | Nightly Analysis |
|---|---|---|
| **File** | `realtime_watcher.py` | `nightly_analysis.py` |
| **When** | Always, 24/7 | Cron at 02:00 |
| **How** | `systemd` service (auto-start on boot) | crontab |
| **Ban trigger** | 5 hits in 120s, or 1 CRITICAL hit | ≥10 attacks or ≥3 from hosting/proxy |
| **Alert** | Instant Telegram notification | JSON report in `/opt/argos/reports/` |
| **Log** | `/opt/argos/logs/watcher.log` | `/opt/argos/logs/nightly.log` |

**CRITICAL patterns → immediate ban (1 hit):**
`SQL_INJECTION`, `CMD_INJECTION`, `REVERSE_SHELL`, `CREDENTIAL_DUMP`, `DOWNLOAD_EXEC`

**HIGH/MEDIUM patterns → ban after 5 hits in 120s:**
`BRUTE_FORCE`, `PATH_TRAVERSAL`, `XSS`

---

## Honeypot System

The ARGOS honeypot engine deploys context-aware decoys that mirror your real infrastructure.

### How It Works

When a port scan is detected on port X, ARGOS:
1. Opens a listener on port X
2. Presents a realistic service banner (SSH, MySQL, HTTP, FTP, etc. based on port)
3. Logs every byte sent and received from the attacker
4. Keeps the attacker engaged as long as possible
5. Saves forensic evidence to `/opt/argos/evidence/`
6. Automatically closes after 5 minutes or when attacker disconnects

### Contextual Decoys

| If you run | ARGOS deploys |
|------------|---------------|
| MySQL on port 3306 | Fake MySQL that accepts credentials and returns fake data |
| SSH on port 22 | Fake SSH that logs all auth attempts and commands |
| Web server on 80/443 | Fake admin panel with realistic login page |
| Redis | Fake Redis that accepts commands and logs them |

### Evidence Format

```
ARGOS Honeypot Evidence
Port: 22
Target attacker: 198.51.100.47
Started: 2025-03-19T03:42:11

[03:42:13] Connection from 198.51.100.47:54821
  Data: b'SSH-2.0-OpenSSH_7.4\r\n'
[03:42:14] Auth attempt: user=root password=password123
[03:42:15] Auth attempt: user=root password=admin
...
```

Evidence files are suitable for law enforcement submissions.

### T-Pot Integration

If you run a T-Pot honeypot, the `tpot.py` plugin connects to its Elasticsearch backend for advanced attacker analytics — attack statistics, harvested credentials, IP history.

---

## Built-in Tools

**37 built-in tools** always available without any plugins.

### Network Recon
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scan with service detection (-sV). Authorized targets only. |
| `masscan_scan` | Ultra-fast port discovery — scans thousands of ports/sec. |
| `ping_host` | ICMP reachability check |
| `dns_lookup` | DNS record query (A, MX, TXT, NS, CNAME, SOA) |
| `whois_lookup` | WHOIS for domain or IP |
| `reverse_dns` | Reverse DNS — IP to hostname |

### OSINT & Threat Intelligence
| Tool | Description |
|------|-------------|
| `cve_lookup` | NVD CVE database — description, CVSS score, severity, references |
| `ip_reputation` | IP geo + ASN + proxy/hosting/mobile detection (ip-api.com) |
| `shodan_host` | Shodan InternetDB — open ports, known CVEs, tags for an IP (free) |
| `shodan_search` | Shodan search query — find exposed hosts by service/port/org/vuln |
| `hash_lookup` | Malware hash check on MalwareBazaar (MD84/SHA1/SHA256) |
| `extract_iocs` | Extract IOCs from text: IPs, domains, URLs, hashes, CVE IDs |

### Vulnerability Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Scan URL/IP with 10,000+ Nuclei templates: CVEs, exposed admin panels, misconfigs |
| `whatweb_scan` | Fingerprint web technologies: CMS, server software, JS libraries, versions |
| `ssl_check` | SSL/TLS certificate check: expiry, issuer, protocol, cipher, self-signed |

### Advanced OSINT & Attribution
| Tool | Description |
|------|-------------|
| `theharvester_scan` | Harvest emails, subdomains, hosts from Google, Bing, LinkedIn, Shodan |
| `sherlock_search` | Find a username across 400+ social networks — map attacker identity |
| `ipwhois_lookup` | Full RDAP/WHOIS for an IP: org, network range, ASN, abuse contact email |
| `subdomain_enum` | Passive subdomain enumeration via crt.sh + hackertarget |
| `abuseipdb_check` | Check IP abuse score (0-100), attack categories, 700k+ org reports |
| `abuseipdb_report` | Report attacker IP to global AbuseIPDB database |
| `build_attacker_dossier` | Complete attacker profile: geo, ASN, Shodan, CVEs, abuse history, contacts |
| `generate_leo_report` | **Formal report for law enforcement** (Polizia Postale, CSIRT-IT, Europol, FBI IC3) with MITRE ATT&CK mapping, evidence SHA256 hash, ISP abuse contacts |

### Honeypot
| Tool | Description |
|------|-------------|
| `deploy_honeypot` | Deploy fake SSH, HTTP, FTP, MySQL services to capture attacker credentials |
| `honeypot_status` | Check honeypot status, total captures, unique attacker IPs |
| `read_honeypot_logs` | Read attacker activity: IPs, credentials tried, commands executed |
| `stop_honeypot` | Stop the honeypot |

### Auto-Hardening
| Tool | Description |
|------|-------------|
| `lynis_audit` | Security audit with hardening score (0-100), warnings, and suggestions |
| `harden_ssh` | Harden sshd_config: disable password auth, limit retries, set timeouts |
| `setup_ufw` | Configure UFW firewall: deny all incoming, allow only specified ports |
| `auto_harden` | **Full auto-hardening**: UFW + kernel sysctl + fail2ban + disable unused services |

### Log Analysis & Defense
| Tool | Description |
|------|-------------|
| `analyze_log` | Analyze raw log content for threats: brute force, SQLi, XSS, ransomware, C2 |
| `read_log_file` | Read and analyze a log file from server filesystem |
| `generate_report` | Generate structured JSON security report, saved to `/opt/argos/reports/` |
| `ban_ip` | Permanently ban an IP via fail2ban. Whitelist: 127.0.0.1, localhost, server IP |
| `unban_ip` | Remove an IP ban (false positive correction) |
| `list_banned_ips` | List all currently banned IPs |

---

## Plugin System

**76 hot-loadable plugins, 84 tools.** Drop a `.py` file in `agent/plugins/` and it's available immediately — no restart needed. Drop a `.py` file in `agent/plugins/` and it's available immediately — no restart needed. Drop a `.py` file in `agent/plugins/` and it's available immediately — no restart needed.

### Threat Intelligence (free APIs)

| Plugin | Tools | Key Required | Free Tier |
|--------|-------|-------------|-----------|
| `threat_intel_feeds.py` | `update_feeds`, `check_ip`, `check_ips_bulk`, `get_feed_stats`, `apply_blocklist_to_firewall`, `search_blocklist` | None | malicious-ip (84+ sources) + ShadowWhisperer honeypot + Ipsum + EmergingThreats + Spamhaus DROP |
| `ip_investigator.py` | `investigate_ip`, `investigate_attackers`, `analyze_attack_patterns`, `get_ip_profiles`, `enrich_banned_ips` | None | 100% free — ip-api, ThreatFox, URLHaus, WHOIS |
| `example_virustotal.py` | `vt_hash_scan`, `vt_url_scan`, `vt_ip_scan` | `VIRUSTOTAL_API_KEY` | virustotal.com/gui/join-us |
| `greynoise.py` | `greynoise_ip` | Optional `GREYNOISE_API_KEY` | Community API: no key needed |
| `alienvault_otx.py` | `otx_ip`, `otx_domain`, `otx_hash`, `otx_url` | `OTX_API_KEY` | Free at otx.alienvault.com |
| `threatfox_urlhaus.py` | `threatfox_ioc`, `threatfox_hash`, `urlhaus_lookup_url`, `urlhaus_lookup_host` | None | 100% free, no key |
| `opencti.py` | `opencti_search_ioc`, `opencti_get_threats` | `OPENCTI_URL` + `OPENCTI_TOKEN` | Self-hosted or Filigran cloud |

### URL & File Analysis

| Plugin | Tools | Key Required | Free Tier |
|--------|-------|-------------|-----------|
| `urlscan.py` | `urlscan_submit`, `urlscan_search` | `URLSCAN_API_KEY` | 100 scans/day |
| `hybrid_analysis.py` | `ha_hash_search`, `ha_url_submit`, `ha_get_report` | `HYBRID_ANALYSIS_API_KEY` | Free at hybrid-analysis.com |
| `ssl_labs.py` | `ssllabs_analyze` | None | 100% free, no key |

### IP & Email Intelligence

| Plugin | Tools | Key Required | Free Tier |
|--------|-------|-------------|-----------|
| `censys.py` | `censys_host`, `censys_search` | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 250 queries/month |
| `ipinfo.py` | `ipinfo_lookup`, `ipinfo_batch` | Optional `IPINFO_TOKEN` | 50K/month with token |
| `ip2location.py` | `ip2location_lookup` | Optional `IP2LOCATION_API_KEY` | 500/day anon, 30K/month with key |
| `emailrep.py` | `emailrep_check`, `pulsedive_lookup` | Optional keys | Free tier available |
| `hibp.py` | `hibp_password_check`, `hibp_email_check` | `HIBP_API_KEY` for email | Password check always free |

### IOC Extraction & OSINT Tools

| Plugin | Tools | Notes |
|--------|-------|-------|
| `datasurgeon.py` | `extract_iocs_from_text`, `extract_iocs_from_file`, `scan_dir_for_iocs`, `extract_credentials` | Pure Python IOC extractor: IPv4/IPv6, domain, URL, email, MD5/SHA1/SHA256/SHA512, CVE, JWT, API keys, AWS keys, private keys, credit cards. No deps required. |
| `ip_investigator.py` | `investigate_ip`, `investigate_attackers`, `analyze_attack_patterns`, `get_ip_profiles`, `enrich_banned_ips` | Deep IP enrichment: geo, WHOIS, ThreatFox, URLHaus, AbuseIPDB, VirusTotal. Reads auto-enriched ban profiles. |

### Fast Reconnaissance

| Plugin | Tools | Notes |
|--------|-------|-------|
| `fast_recon.py` | `fast_port_scan`, `deep_service_scan`, `masscan_sweep`, `sn0int_recon`, `full_recon_pipeline` | Full recon pipeline: RustScan → nmap -sV -sC → sn0int OSINT. Falls back to masscan/nmap automatically. |

### SIGMA / Log Analysis

| Plugin | Tools | Notes |
|--------|-------|-------|
| `zircolite_sigma.py` | `sigma_analyze_evtx`, `sigma_analyze_sysmon`, `sigma_analyze_linux`, `sigma_update_rules`, `sigma_full_analysis` | Zircolite SIGMA engine on Windows EVTX / Sysmon / Linux audit logs. MITRE ATT&CK mapping, auto-download latest rulesets from Zircolite repo. |

### DFIR Forensics

| Plugin | Tools | Notes |
|--------|-------|-------|
| `dfir_forensics.py` | `evtx_analyze`, `evtx_to_timeline`, `registry_forensics`, `prefetch_analyze`, `ir_collect_artifacts` | dfir-toolkit (Rust): EVTX parsing, registry hive analysis, prefetch execution history, bodyfile timeline. Linux IR artifact collection: cron, SUID, shell history, recently modified files. |

### Mobile Forensics

| Plugin | Tools | Notes |
|--------|-------|-------|
| `mobile_forensics.py` | `mvt_update_iocs`, `mvt_ios_scan_backup`, `mvt_android_scan_apk`, `mvt_check_iocs`, `mvt_generate_report` | MVT (Amnesty International): Pegasus, Predator, stalkerware IOC scanning on iOS backups and Android APKs. STIX2 IOC feed auto-updated. |

### Network Capture & Flow Analysis

| Plugin | Tools | Notes |
|--------|-------|-------|
| `network_capture.py` | `capture_start`, `capture_stop`, `analyze_pcap`, `flowmeter_analyze`, `capture_summary` | tcpdump/tshark capture with session management. PCAP analysis: top talkers, DNS queries, HTTP requests, cleartext credentials. FlowMeter ML traffic classification. |

### Favicon OSINT

| Plugin | Tools | Notes |
|--------|-------|-------|
| `favicon_osint.py` | `favicon_hash`, `favicon_search_shodan`, `favicon_search_zoomeye`, `favicon_search_fofa`, `favicon_full_hunt` | MurmurHash3 favicon fingerprinting + multi-platform search (Shodan/ZoomEye/Fofa). C2 infrastructure discovery, phishing clone detection. Hash computation works with zero API keys. |

### EXIF & File Metadata Forensics

| Plugin | Tools | Notes |
|--------|-------|-------|
| `exif_forensics.py` | `exif_extract`, `exif_gps_hunt`, `exif_author_hunt`, `exif_scan_dir`, `exif_steganography_hints` | ExifTool: GPS coordinates, author attribution, device fingerprinting, steganography hints. Works on 200+ file formats. |

### Document Analysis (Apache Tika)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `tika_extractor.py` | `tika_extract_text`, `tika_extract_metadata`, `tika_scan_dir`, `tika_detect_language`, `tika_malware_triage` | Apache Tika: extract text/metadata from 1000+ file types. Malware triage with risk scoring. Language detection for APT attribution. |

### Web Reconnaissance & Crawling

| Plugin | Tools | Notes |
|--------|-------|-------|
| `browser_recon.py` | `web_crawl`, `browser_screenshot`, `form_analyzer`, `js_recon`, `firecrawl_scrape` | Site mapper + admin panel finder + form CSRF analysis + JS API endpoint extraction + Firecrawl scraping (SDK or REST). Playwright fallback for JS-heavy sites. |

### Multi-Agent Pentest (CrewAI)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `crewai_pentest.py` | `crewai_recon_crew`, `crewai_vuln_crew`, `crewai_threat_hunt_crew`, `crewai_incident_response_crew` | CrewAI orchestration: 3-agent recon crew, vuln analysis crew, threat hunt crew, IR playbook generator. Uses local Seneca-32B by default. |

### Username OSINT

| Plugin | Tools | Notes |
|--------|-------|-------|
| `username_osint.py` | `userrecon_search`, `instagram_recon`, `extract_urls_from_page`, `sherlock_rs_search` | username across 200-400+ platforms (userrecon + sherlock-rs), Instagram public profile, URL extraction |

### Pentest Report Generation

| Plugin | Tools | Notes |
|--------|-------|-------|
| `pentest_report.py` | `generate_pentest_report` | HTML + Markdown + JSON output, CVSS scoring, MITRE ATT&CK, executive summary |

### AI Pentest Agents (authorized use only)

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `pentest_pipeline.py` | `run_pentest_pipeline`, `get_pentest_status`, `list_pentest_workspaces`, `get_pentest_report`, `run_external_scan` | `pyyaml`, optional: `playwright`, `schemathesis` | **Autonomous 5-phase white-box pipeline** (Shannon-inspired): code analysis → recon → 5 vuln specialists → 5 exploit agents → executive report. "No Exploit, No Report" quality gate. |
| `pentestgpt.py` | `pentestgpt_run` | `pip install pentestgpt` | Uses ARGOS local LLM or Claude |
| `pentagi.py` | `pentagi_start_flow`, `pentagi_get_flow`, `pentagi_list_flows` | `PENTAGI_URL` + `PENTAGI_TOKEN` | Self-hosted Docker |
| `pentest_copilot.py` | `pentest_copilot_start`, `pentest_copilot_status`, `pentest_copilot_consent` | `PENTEST_COPILOT_URL` + token | Real Kali + Burp Suite integration |
| `nebula.py` | `nebula_query`, `nebula_docker`, `nebula_list_capabilities` | `pip install nebula-ai` + Ollama or OpenAI | Natural language: "! scan 192.168.1.1 for open ports" |

### Offensive / Pentest CLI (authorized use only)

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `sn1per.py` | `sn1per_scan` | `sniper` CLI | `bash <(curl -sL install-sniper.sh)` |
| `netexec.py` | `netexec_smb`, `netexec_ssh`, `netexec_ldap`, `netexec_winrm` | `nxc` CLI | `pipx install NetExec` |
| `gobuster.py` | `gobuster_dir`, `gobuster_dns` | `gobuster` + SecLists | `apt install gobuster seclists` |
| `offensive_payloads.py` | `get_payloads`, `list_payload_categories` | None | Offline: `/opt/argos/payloads` (cloned by installer) |
| `reverse_shells.py` | `generate_reverse_shell`, `list_shell_types` | None | PHP obfuscated + 10 other types |

### Honeypot Platform

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `tpot.py` | `tpot_stats`, `tpot_credentials`, `tpot_search_ip` | `TPOT_HOST` env var | T-Pot Elasticsearch backend |

### DoS Resilience Testing (authorized pentest only)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `stress_test.py` | `http_load_test`, `tcp_flood_test`, `bandwidth_test`, `slowhttp_test`, `stress_report` | Authorized load testing: wrk/ab HTTP benchmark, hping3 TCP, iperf3 bandwidth, Slowloris resilience test. |

### AI Red Team & LLM Security

| Plugin | Tools | Notes |
|--------|-------|-------|
| `llm_redteam.py` | `llm_jailbreak_test`, `llm_prompt_injection_test`, `l1b3rt4s_test`, `list_llm_redteam_categories` | Tests any OpenAI-compatible endpoint. Auto-clones L1B3RT4S jailbreak collection. |

### Microsoft 365 / Power Platform

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `power_pwn.py` | `power_pwn_recon`, `power_pwn_dump_resources`, `power_pwn_copilot_hunter`, `power_pwn_llm_hound`, `power_pwn_tenant_mcp_recon`, `power_pwn_full_assessment` | `POWERPWN_AUTH_TOKEN` | `pip install power-pwn` |

### Advanced Pentest Platforms

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `pentest_swarm.py` | `pentest_swarm_start`, `pentest_swarm_status`, `pentest_swarm_findings`, `pentest_swarm_list_campaigns` | `PENTESTSWARM_ORCHESTRATOR_API_KEY` | 5 AI agents, 7 native Go tools (subfinder/httpx/nuclei/naabu/katana) |
| `emp3r0r.py` | `emp3r0r_build`, `emp3r0r_start_cc`, `emp3r0r_gen_agent`, `emp3r0r_list_modules` | Go >= 1.21 | Linux/Windows C2 with covert channels, Tor, SSHd implant |
| `overlord.py` | `overlord_list_modules`, `overlord_deploy`, `overlord_destroy`, `overlord_status` | Terraform + Ansible | Red team infra: C2, redirectors, phishing, attack boxes |

### Web & API Security

| Plugin | Tools | Notes |
|--------|-------|-------|
| `nettacker.py` | `nettacker_scan`, `nettacker_vuln_scan`, `nettacker_subdomain_enum`, `nettacker_list_modules` | `pip install owasp-nettacker`. 200+ scan modules, REST API. |
| `web_recon.py` | `rapidscan`, `vaile_recon`, `astra_api_scan`, `skipfish_scan`, `web_recon_full` | rapidscan multi-tool scan, Vaile web recon, Astra REST API OWASP Top 10, skipfish 10K+ checks |

### DLP Evasion Testing

| Plugin | Tools | Notes |
|--------|-------|-------|
| `cloakify.py` | `cloakify_encode`, `cloakify_decode`, `list_cloakify_ciphers` | Encodes data as emoji/LOTR/sports teams to test DLP controls. |

### Pentest Frameworks

| Plugin | Tools | Notes |
|--------|-------|-------|
| `pentest_frameworks.py` | `fsociety_run_tool`, `fsociety_list_tools`, `darkspiritz_run_module`, `darkspiritz_list_modules`, `kis_collect`, `kis_report` | fsociety all-in-one, DarkSpiritz Metasploit-style, KaliIntelligenceSuite OSINT |

### IoT Penetration Testing

| Plugin | Tools | Notes |
|--------|-------|-------|
| `iot_pentest.py` | `iot_scan_ports`, `iot_banner_grab`, `iot_default_creds_test`, `peniot_mqtt_test` | MQTT, CoAP, Modbus, BACnet, S7comm detection + default credential testing |

### MITRE ATT&CK Simulation

| Plugin | Tools | Notes |
|--------|-------|-------|
| `atomic_red_team.py` | `art_list_techniques`, `art_get_technique`, `art_execute_test`, `art_simulate_tactic` | Red Canary atomic tests mapped to MITRE ATT&CK. Parses YAML, executes bash/powershell/python. |

### OSINT Platforms

| Plugin | Tools | Notes |
|--------|-------|-------|
| `spiderfoot.py` | `spiderfoot_scan`, `spiderfoot_scan_results`, `spiderfoot_list_modules` | 400+ OSINT modules: IPs, domains, emails, usernames, phones. Shodan/VT/HaveIBeenPwned/Censys. |
| `username_osint.py` | `userrecon_search`, `instagram_recon`, `extract_urls_from_page` | Username recon across 200+ platforms, Instagram public profile OSINT |

### Hak5 Hardware Payloads

| Plugin | Tools | Notes |
|--------|-------|-------|
| `hak5_payloads.py` | `hak5_list_devices`, `hak5_list_payloads`, `hak5_get_payload`, `hak5_search_payloads` | Payload library for OMG Cable, BashBunny, KeyCroc, SharkJack, USB Rubber Ducky |

### WordPress Security

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `wordpress_scan.py` | `wpscan_vuln_scan`, `wpscan_user_enum`, `wpscan_password_attack` | `gem install wpscan` or Docker | `WPSCAN_API_TOKEN` for full CVE data |

### Social Engineering Testing (authorized red team only)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `social_engineering.py` | `maskphish_create`, `seeker_list_templates`, `seeker_start`, `stormbreaker_start` | maskphish URL obfuscation, seeker geolocation capture, Storm-Breaker webcam/mic testing. **SIGNED WRITTEN CONSENT REQUIRED.** |

### Payload Extension (LFI / SSTI / Encoders)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `hacktools.py` | `hacktools_lfi_payloads`, `hacktools_ssti_payloads`, `hacktools_encode`, `hacktools_headers_cheatsheet` | LFI/RFI payloads (PHP wrappers, traversal, /proc), SSTI for 8 engines (Jinja2/Twig/Freemarker/Mako/ERB), WAF bypass encoders, HTTP header cheatsheets |

### Repos Evaluated but Not Integrated

| Repo | Reason |
|------|--------|
| `wlmzz/Yuan3.0` | 40B MoE language model (HuggingFace) — not a security tool, no CLI |
| `M4cs/BabySploit` | Beginner tool — functionality covered by existing plugins |
| `Technowlogy-Pushpender/hackerpro` | All-in-one wrapper — every tool it calls is already integrated individually |
| `JGrotex/AutoPentestX` | Automated framework — superseded by pentest_swarm + pentest_copilot |
| `m84ll0k/pentesting-framework` | Limited scope — covered by existing pentest tools |
| `OpenSourcePentest/tools` | Documentation/links collection, no executable code |
| `cyberguideme/Tools` | Documentation/links only, no executable code |
| `A-poc/RedTeam-Tools` | MITRE ATT&CK reference list, no code |
| `enaqx/awesome-pentest` | Curated links list, no code |
| `paralax/awesome-honeypots` | Curated links list, no code |
| `rajkumardusad/IP-Tracer` | Unmaintained CLI wrapper over ip-api.com — already in `ip_reputation` |
| `ip2location-com/ip2location-nginx` | Nginx C module (not wrappable) — used REST API via `ip2location.py` |
| `syztem4our666/zsh-pentester` | Thin zsh wrappers — underlying tools already integrated |
| `anthropics/claude-code-security-review` | GitHub Actions action, not a subprocess |
| `pluginagentmarketplace/custom-plugin-cyber-security` | Claude Code IDE plugin, different runtime |
| `lucasjacks0n/EggShell` | macOS/iOS RAT — microphone recording, location tracking, USB injection — unauthorized surveillance risk |
| `Lomasterrrr/HackWebTool` | CloudFlare bypass + credential brute-force without authorization framework — repo closed by author |
| `mrprogrammer2938/Black-Tool` | All-in-one wrapper — every tool it calls is already integrated individually |
| `x11-repo/hack-tools-en` | Tool aggregator launcher — all underlying tools already integrated individually |
| `TianWen-Lab/TranSec` | Full Linux OS distribution for automotive security — not wrappable as a plugin |

---

## Subagent Orchestration

Run multiple ARGOS tasks in parallel with `spawn_subagents`:

```
spawn_subagents([
    {"task": "Port scan 10.0.0.1", "label": "portscan",
        "tools": ["nmap_scan", "masscan_scan"]},
    {"task": "Full OSINT on 10.0.0.1", "label": "osint",
        "tools": ["shodan_host", "greynoise_ip", "otx_ip", "abuseipdb_check", "ipinfo_lookup"]},
    {"task": "Check TLS of site.com", "label": "tls",
        "tools": ["ssllabs_analyze", "ssl_check"]},
    {"task": "Scan for vulns on site.com", "label": "vulns",
        "tools": ["nuclei_scan", "whatweb_scan", "gobuster_dir"]},
])
```

All 4 run simultaneously. Results aggregated when all finish.

---

## Complete Pentest Workflow

ARGOS supports two complementary pentest modes.

### Mode 1 — Autonomous White-Box Pipeline (Web Applications)

The `pentest_pipeline` plugin runs a structured 5-phase autonomous pentest against web applications with access to their source code. Inspired by the Shannon framework (Keygraph, AGPL-3.0).

> *"Lancia un pentest su https://staging.myapp.com con codice sorgente in /opt/repos/myapp"*

```
Phase 1 — Pre-Recon
  ├── Source code analysis (white-box: auth flows, injection sinks, attack surface)
  └── External scans (nmap, subfinder, whatweb)
       ↓ code_analysis_deliverable.md

Phase 2 — Recon (Attack Surface Mapping)
  ├── Live browser exploration (authenticated)
  ├── API endpoint inventory with auth requirements
  ├── Role/privilege architecture mapping
  └── IDOR & privilege escalation candidates
       ↓ recon_deliverable.md

Phase 3 — Vulnerability Analysis (5 parallel specialists)
  ├── Injection analyst     → SQLi, CMDi, LFI, SSTI, Path Traversal
  ├── XSS analyst           → Reflected, Stored, DOM-based + CSP analysis
  ├── Auth analyst          → Broken auth, JWT, session management, MFA bypass
  ├── SSRF analyst          → All server-side request sinks + cloud metadata
  └── Authorization analyst → IDOR, vertical escalation, workflow bypass
       ↓ exploitation_queue.json (only verified, externally_exploitable vulns)

Phase 4 — Exploitation (5 parallel agents, conditional)
  ONLY if exploitation_queue is non-empty ("No Exploit, No Report" policy)
  ├── Injection exploitation → data exfiltration with OWASP workflow
  ├── XSS exploitation       → session cookie theft, account takeover PoC
  ├── Auth exploitation      → credential attacks, JWT tampering, session fixation
  ├── SSRF exploitation      → cloud metadata (AWS/GCP/Azure), internal service access
  └── Authz exploitation     → IDOR data access, admin endpoint bypass
       ↓ *_exploitation_evidence.md (reproducible PoCs only)

Phase 5 — Report
  └── Executive security report — verified findings only, clean PoCs, severity ratings
```

**Key features:**
- Resume interrupted sessions from any phase
- YAML target config for auth flows, scope rules, multi-role accounts
- Findings automatically saved to Qdrant for RAG + training feedback

```
# Via natural language (Telegram, Discord, CLI):
"Lancia il pentest pipeline su https://app.target.com con repo /opt/repos/app"
"Mostra lo stato del workspace app_target_20260402"
"Report finale del pentest app_target_20260402"

# Direct tool call:
run_pentest_pipeline(target_url="https://app.target.com", source_code_path="/opt/repos/app")
run_external_scan(target="192.168.1.100")
```

---

### Mode 2 — Network/Infrastructure Pentest

ARGOS can conduct a complete pentest autonomously and generate a professional report. Just ask:

> *"Do a full pentest of 10.0.0.1 and generate the report"*

The model will autonomously orchestrate these steps using subagents:

```
Step 1 — Recon (parallel)
  ├── nmap_scan           → open ports, services, banners
  ├── masscan_scan        → fast full-port discovery
  ├── shodan_host         → known CVEs, Shodan tags
  ├── whatweb_scan        → web tech detection (CMS, framework, versions)
  └── subdomain_enum      → passive subdomains (crt.sh + hackertarget)

Step 2 — Threat Intel (parallel)
  ├── greynoise_ip        → noise vs targeted threat
  ├── abuseipdb_check     → attack history from 700k+ organizations
  ├── ipinfo_lookup       → ASN, geoloc, VPN/proxy detection
  └── otx_ip              → AlienVault OTX pulse data

Step 3 — Vulnerability Assessment (parallel)
  ├── nuclei_scan         → 10,000+ templates (CVE, admin panels, misconfigs)
  ├── ssl_check           → TLS/SSL certificate analysis
  ├── ssllabs_analyze     → grade A-F + Heartbleed/POODLE check
  └── gobuster_dir        → hidden directories and files

Step 4 — Deep Analysis
  ├── theharvester_scan   → emails, subdomains, hosts from OSINT sources
  ├── urlscan_submit      → sandbox URL analysis
  └── sn1per_scan         → full automated recon (if installed)

Step 5 — Report
  └── generate_pentest_report → HTML + Markdown + JSON with:
        ✓ Executive Summary (non-technical, for management)
        ✓ Findings with CVSS score (Critical/High/Medium/Low/Info)
        ✓ Proof of Concept / Evidence with SHA256 hash
        ✓ Specific remediation steps
        ✓ MITRE ATT&CK mapping
        ✓ CVE/CWE references
        ✓ Professional colored HTML report ready for client delivery
```

Reports saved to: `/opt/argos/reports/`

### Example prompts

```
"Do a full pentest of example.com.
Check: open ports, web vulnerabilities, subdomains, TLS issues.
At the end generate a professional HTML report with all findings."
```

```
"Analyze the security of 192.168.1.0/24.
Identify active hosts, exposed services, known CVEs.
Generate a client report with executive summary and remediation steps."
```

---

## Dashboard

The ARGOS web dashboard is a React application served by the central server.

**Running:** `cd dashboard && npm run build` (or `npm run dev` for development)

### Views

**Overview** — System health, active threats, recent events, blocked IPs counter, devices online.

**Threat Feed** — Real-time stream of all events across all devices. Filter by severity, type, device, time range.

**Devices** — All connected agents. Status, last seen, threats per device, quick actions.

**Intelligence** — Blocked IP list, threat statistics, attacker geolocation map, top threat types.

**Honeypots** — Active honeypots, interaction logs, evidence files ready for download.

**AI** — Model status, confidence trends, training history, manual fine-tune trigger.

**Settings** — Autonomy level, notification preferences, community intel, API keys.

WebSocket event stream: real-time updates pushed from `server/api/` via `dashboard/src/ws.ts`.

---

## Mobile App

> Coming in a future release.

The planned ARGOS mobile app (iOS and Android) will provide:

- Live dashboard of all protected devices
- Push notifications for every significant threat event
- One-tap approve/block for pending AI decisions
- Geographic visualization of attack sources
- Emergency actions — isolate device, block IP, from anywhere

---

## Community Intelligence

Community intelligence is **opt-in only**. Nothing is shared without explicit consent.

When enabled, ARGOS contributes anonymized threat indicators to the shared network:

- IP addresses confirmed malicious
- Attack patterns and TTPs
- Honeypot interaction signatures

What is **never** shared:
- Your IP address or device identifiers
- Internal network topology
- Log content or evidence files
- Any personally identifiable information

The community database benefits all users: when an IP attacks one node and gets flagged, every other node knows about it before it arrives.

---


### MCP Integration + Hook Middleware (Claw Code)

Ispirato all'architettura di [Claw Code](https://github.com/sigjin/claw-code):

| Plugin | Tools | Funzione |
|--------|-------|----------|
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Connessione a qualsiasi server MCP (GitHub, PostgreSQL, Slack, filesystem). Tool auto-discovery come  |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Pre/Post hook middleware: audit log automatico, rate limiter, dangerous tool gate, hook custom runtime |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 6 | Token tracking per sessione, session compaction, permission modes (readonly/workspace_write/danger_full_access), parity audit, cost estimation |

**Permission Modes:**
- !=0
'#'=0
'$'=1226
'*'=(  )
-=569Xl
'?'=127
@=(  )
ARGC=0
HISTCMD=0
LINENO=1
PPID=87332
TTYIDLE=-1
ZSH_EVAL_CONTEXT=cmdarg:eval:cmdsubst
ZSH_SUBSHELL=1
status=127
zsh_eval_context=( cmdarg eval cmdsubst ) — solo OSINT/query passive
-  — operazioni file + pentest, no hardening
-  — accesso completo

**MCP Servers configurabili** in : filesystem, GitHub, PostgreSQL, Brave Search, Slack, HTTP custom.


### SAST, Malware, Forensics, AI Security & Cloud (v2.0)

10 nuovi plugin aggiunti:

| Plugin | Tools | Categoria |
|--------|-------|-----------|
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 3 | SAST — Semgrep 30+ linguaggi + Bandit Python |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Container/IaC — Docker, packages, SBOM, Terraform |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Malware — YARA rules + ClamAV scanning |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 6 | Memory Forensics — pslist, malfind, hashdump, netscan |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 4 | Network IDS — Zeek, Suricata, IOC extraction |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Exploit Framework — msfrpc integration |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | SQL Injection — scan, dump, OS shell |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | HTTP Fuzzing — dirs, vhosts, params, wordlists |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | AI Security — LLM vuln scanner, red team, benchmark |
|  | C2 framework (archived March 2026) — already have emp3r0r; overlapping functionality |
|  | Windows process killer for PID termination — too niche for defensive platform |
|  | Shellcode packer/AV evasion — malware delivery tool, outside defensive scope |
|  | MCP protocol debugger (Node.js) — too niche; not a security tool |
|  | Documentation/links collection — no wrappable code |
|  | GUI-only forensics app (Python Tkinter) — cannot be headless |
|  | Resource list / documentation only |
|  | Italian digital forensics documentation only |
|  | PortSwigger lab solutions (Rust code) — not a runnable tool |
|  | Superseded by dfir_forensics.py (more comprehensive) |
|  | Thin wrappers — underlying tools already integrated individually |
|  | 5 | Cloud — ScoutSuite, Prowler, IAM analyzer |

## Development Roadmap

### Phase 1 — Core
- [x] Cross-platform agent (Linux, macOS, Windows)
- [x] Network monitoring and threat detection
- [x] Process monitoring
- [x] AI engine with llama.cpp (Seneca-Cybersecurity-LLM-x-QwQ-32B)
- [x] Rule-based fallback
- [x] IP blocking via native OS firewall + fail2ban
- [x] Honeypot TCP engine
- [x] Process suspension
- [x] SQLite threat database
- [x] CLI interface
- [x] Telegram + Discord + Webhook channels
- [x] Realtime watcher (systemd, 24/7)
- [x] Nightly analysis (cron, 02:00)
- [x] Tamper-evident audit log (SHA256 chain)
- [x] Plugin system (84 plugins, 332 tools, hot-reload)

### Phase 2 — Server & Intelligence
- [x] FastAPI central server (`server/server.py`)
- [x] Multi-device coordination (`server/api/devices.py`)
- [ ] Threat correlation across devices
- [x] Public threat feed integration — AbuseIPDB, VirusTotal, Shodan (`server/intelligence/feeds.py`)
- [x] Attacker attribution reports (`server/intelligence/attribution.py`)
- [x] Docker deployment (`server/Dockerfile` + `server/docker-compose.yml`)
- [ ] TLS everywhere

### Phase 3 — AI & Learning
- [x] Fine-tuning pipeline (LoRA) — Seneca-32B on RunPod (`server/training/train_gpu.py`)
- [x] Cybersecurity training dataset — 8 professor models, custom alignment (`server/training/`)
- [x] Shannon pentest methodology training data — 5-phase pipeline examples (`training/datasets/foundational/shannon_pentest_training.jsonl`)
- [ ] Continuous learning from incidents (automated, no manual trigger)
- [x] Claude API escalation (`server/ai_engine/escalation.py`)
- [x] Pentest findings → Qdrant RAG memory (automatic after each pipeline run)
- [ ] Behavioral baseline modeling per device

### Phase 4 — Interfaces
- [x] React web dashboard (`dashboard/src/`)
- [ ] React Native mobile app (iOS + Android)
- [ ] Push notifications (Firebase)
- [x] Real-time WebSocket event stream (`dashboard/src/ws.ts`)

### Phase 5 — Advanced Defense
- [ ] Contextual honeypot generator (per-service decoys)
- [ ] Dynamic port management
- [ ] Network segment isolation
- [ ] Credential rotation triggers
- [ ] Ransomware-specific response chain
- [ ] DDoS mitigation module

### Phase 6 — Community & Scale
- [ ] Opt-in community threat sharing
- [ ] One-click installers (Linux .deb/.rpm, macOS .pkg, Windows .exe)
- [ ] Auto-update system
- [ ] Documentation site
- [x] Plugin system for custom detectors (84 plugins, 332 tools)

---

## Project Structure

```
argos/
│
├── README.md
├── LICENSE
├── requirements.txt            # Agent Python dependencies
├── argos_agent.py              # Legacy entry point
├── setup_model.py              # llama.cpp model setup helper
├── simulate.py                 # Threat simulation for testing
│
├── agent/                      # Agentic AI core
│   ├── main.py                 # Entry point (CLI / Telegram / Discord / Webhook)
│   ├── agent.py                # Core agentic loop (tool-calling LLM)
│   ├── session.py              # Conversation history + compaction
│   ├── orchestrator.py         # Parallel subagent execution (ThreadPoolExecutor)
│   ├── plugin_loader.py        # Dynamic plugin discovery + hot-reload
│   ├── audit.py                # Tamper-evident audit log (SHA256 chain)
│   ├── channels/
│   │   ├── telegram.py         # Telegram bot
│   │   ├── discord.py          # Discord bot (WebSocket + HTTP fallback)
│   │   └── webhook.py          # HTTP webhook server with rate limiting
│   ├── tools/
│   │   ├── network.py          # nmap, masscan, ping, DNS, WHOIS
│   │   ├── osint.py            # CVE lookup, IP rep, Shodan, hash check, IOC extraction
│   │   ├── osint_advanced.py   # theHarvester, Sherlock, ipwhois, subdomain enum
│   │   ├── analysis.py         # log analysis, threat detection, report generation, ban_ip
│   │   ├── vuln.py             # nuclei, whatweb, SSL check
│   │   ├── attribution.py      # AbuseIPDB, attacker dossier, law enforcement report
│   │   ├── hardening.py        # Lynis, SSH hardening, UFW, auto-harden
│   │   └── honeypot.py         # deploy/manage honeypots, read attacker captures
│   ├── plugins/                # 84 hot-loadable plugins (see Plugin System above)
│   │   ├── pentest_pipeline.py # Autonomous 84-phase white-box pentest pipeline (Shannon-inspired)
│   │   ├── example_virustotal.py
│   │   ├── greynoise.py
│   │   └── ... (43 total)
│   └── README.md               # Detailed agent + plugin documentation
│
├── server/                     # Central FastAPI server
│   ├── server.py               # FastAPI entry point
│   ├── db.py                   # Database models
│   ├── dashboard.py            # Dashboard data aggregation
│   ├── requirements-server.txt
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── api/
│   │   ├── events.py           # Event ingestion from agents
│   │   ├── devices.py          # Device management + multi-device coordination
│   │   ├── dashboard.py        # Dashboard data endpoints
│   │   ├── auth.py             # Token management
│   │   ├── ai_chat.py          # AI chat endpoint
│   │   └── intelligence.py     # Threat intelligence aggregation
│   ├── ai_engine/
│   │   ├── engine.py           # llama.cpp / OpenAI-compatible integration
│   │   ├── seneca_engine.py    # Seneca-specific engine
│   │   ├── coordinator.py      # Multi-agent coordination
│   │   ├── prompts.py          # System prompts and templates
│   │   ├── fallback.py         # Rule-based fallback logic
│   │   ├── escalation.py       # Claude API escalation
│   │   ├── dream.py            # Dream mode: proactive threat hunting
│   │   └── tools.py            # AI tool definitions
│   ├── training/
│   │   ├── train_gpu.py        # LoRA fine-tuning on RunPod
│   │   ├── train_argos.py      # ARGOS-specific training pipeline
│   │   ├── generate_professors.py  # 8 professor model generators
│   │   ├── generate_training_data.py
│   │   ├── build_alignment_dataset.py
│   │   ├── pipeline.py         # Training orchestration
│   │   └── runpod_setup.sh     # RunPod GPU environment setup
│   └── intelligence/
│       ├── feeds.py            # AbuseIPDB, VirusTotal, Shodan feeds
│       └── attribution.py      # IP attribution and WHOIS
│
├── dashboard/                  # React web dashboard
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── ws.ts               # WebSocket real-time event stream
│   │   ├── api.ts              # REST API client
│   │   ├── types.ts            # TypeScript type definitions
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Dashboard views
│   │   ├── hooks/              # React hooks (useWebSocket, etc.)
│   │   └── utils/              # Helpers and formatters
│   └── package.json
│
├── installer/
│   └── install.sh              # Plug & play installer (Ubuntu/Debian)
│
├── prompts/
│   └── pentest/                # 13 prompt templates for pentest pipeline agents
│       ├── 01_pre_recon.txt    # Phase 1: code analysis + external scans
│       ├── 02_recon.txt        # Phase 2: attack surface mapping
│       ├── 03_vuln_*.txt       # Phase 3: 5 vulnerability analysis specialists
│       ├── 04_exploit_*.txt    # Phase 4: 5 exploitation specialists
│       └── 05_report.txt       # Phase 5: executive security report
│
├── configs/
│   └── pentest/
│       └── example_target.yaml # Target config template (auth, rules, scope)
│
└── docs/
    ├── architecture.md
    ├── api-reference.md
    ├── training-guide.md
    └── deployment-guide.md
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Agent | Python 3.10+ | Cross-platform monitoring, agentic loop, tool execution |
| Network monitoring | psutil, Scapy | Connection tracking, packet analysis |
| Local database | SQLite | Threat history, blocked IPs, session data |
| AI engine | llama.cpp (OpenAI-compatible) | Local inference, no GPU required |
| AI model | Seneca-Cybersecurity-LLM-x-QwQ-32B | Custom fine-tuned cybersecurity model |
| AI fallback | Python rules engine | Offline operation without AI |
| AI escalation | Claude API (optional) | Unprecedented threat analysis |
| Remote access | Telegram + Discord + Webhook | Human-in-the-loop channels |
| Central server | FastAPI + Uvicorn | REST API, WebSocket, device coordination |
| Server database | PostgreSQL | Centralized threat database |
| Real-time cache | Redis | Event streaming, session management |
| Web dashboard | React + Recharts + Vite | Real-time monitoring interface |
| WebSocket | `ws.ts` + FastAPI WebSocket | Live event stream from server to dashboard |
| Containerization | Docker + Docker Compose | Server deployment |
| Fine-tuning | LoRA (PEFT) on RunPod | Efficient model adaptation on GPU cloud |
| Training data | 8 professor models | Automated cybersecurity training data generation |
| Plugin system | Python hot-reload | 84 plugins, 332 tools, drop-in extensibility |

---

## Contributing

ARGOS is community-built. All contributions are welcome.

### How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear, documented code
4. Add or update tests as appropriate
5. Submit a pull request with a clear description

### Writing a Plugin

Create a `.py` file in `agent/plugins/` with this structure:

```python
MANIFEST = {
    "id":          "my_plugin",
    "name":        "My Plugin",
    "description": "What it does",
    "version":     "84.0.0",
    "author":      "Your Name",
    "requires":    [],  # pip packages auto-installed by installer
}

def my_tool(param: str) -> dict:
    """Tool description shown to the AI model."""
    # your code
    return {"result": ..., "source": "My Plugin"}

TOOLS = {
    "my_tool": {
        "fn": my_tool,
        "description": "Description for the AI model",
        "parameters": {
            "type": "object",
            "properties": {
                "param": {"type": "string", "description": "..."},
            },
            "required": ["param"]
        }
    }
}
```

Drop it in `agent/plugins/` — no restart needed.

### Areas We Need Help

- New threat detectors (attack patterns, protocol parsers)
- Platform-specific improvements (Windows and macOS)
- Mobile app development (React Native)
- Dashboard components (React)
- Training data curation for the AI model
- Documentation and translations
- Performance optimization for low-resource devices

### Reporting Vulnerabilities

Please do not open public issues for security vulnerabilities in ARGOS itself. Email security@argos-security.io with details. We will respond within 84 hours.

---

## License

ARGOS is released under the MIT License. See [LICENSE](LICENSE) for the full text.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of this software. The only requirement is attribution.

---

## Manifesto

The gap between who can afford real cybersecurity and who cannot is not a technical problem. It is a choice. The tools exist. The knowledge exists. What has been missing is the will to make them available to everyone.

ARGOS is that will, made concrete.

A small business owner should not have to choose between payroll and protecting their customer data. A journalist investigating corruption should not be exposed because they cannot afford enterprise EDR. A nonprofit running on donations should not be an easy target because enterprise security is priced out of reach.

Security is infrastructure. Like clean water or electricity, the baseline level of protection should not depend on how much money you have.

ARGOS will always be free. It will always be open. And it will always get better — because every person who uses it, improves it, or simply believes in it is part of making that true.

---

*Built with the conviction that everyone deserves to be protected.*

*ARGOS — Open Source AI Security Platform*
