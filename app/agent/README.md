# ARGOS Agent

Autonomous cybersecurity agent powered by Seneca-32B (llama.cpp), inspired by OpenClaw's agentic architecture.

## Architecture

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
        └── plugins/               ← hot-loadable plugin modules (42 plugins, 128 tools)
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
              ├── stress_test.py         ← DoS resilience testing: MHDDoS (57 methods) + Impulse + DDoS-Ripper
              ├── power_pwn.py           ← Microsoft 365 / Power Platform pentesting (power-pwn)
              ├── cloakify.py            ← DLP evasion testing: Cloakify data exfil obfuscation
              ├── llm_redteam.py         ← LLM adversarial testing: jailbreaks, prompt injection, L1B3RT4S
              ├── pentest_swarm.py       ← Pentest-Swarm-AI: 5-agent swarm (subfinder/httpx/nuclei/naabu/katana)
              ├── emp3r0r.py             ← emp3r0r C2 framework: Linux/Windows implants, covert channels
              ├── nettacker.py           ← OWASP Nettacker: 200+ scan modules, REST API
              ├── web_recon.py           ← Web recon: rapidscan + Vaile + Astra REST API security
              ├── overlord.py            ← Red team infra automation: C2/redirectors/phishing via Terraform
              ├── pentest_frameworks.py  ← fsociety + DarkSpiritz exploit framework + KaliIntelligenceSuite
              ├── iot_pentest.py         ← IoT pentest: MQTT/CoAP/Modbus/BACnet + default creds testing
              ├── atomic_red_team.py     ← MITRE ATT&CK atomic test execution (Red Canary)
              ├── spiderfoot.py          ← SpiderFoot OSINT: 400+ modules, Shodan/VT/HaveIBeenPwned
              ├── hak5_payloads.py       ← Hak5 device payloads: OMG Cable, BashBunny, KeyCroc, SharkJack
              ├── username_osint.py      ← Username recon across 200+ platforms + Instagram OSINT
              ├── wordpress_scan.py      ← WPScan: WordPress vuln scanner (plugins/themes/CVEs/users)
              ├── social_engineering.py  ← seeker + Storm-Breaker + maskphish (authorized red team)
              ├── nebula.py              ← Nebula AI pentesting assistant (Ollama/OpenAI, natural language)
              └── hacktools.py           ← LFI/RFI payloads, SSTI (8 engines), encoders, headers cheatsheet
```

## What it does

1. User sends message (CLI or Telegram)
2. Agent calls Seneca-32B via llama.cpp OpenAI API (port 8080)
3. Model decides which tools to call
4. Agent executes tools (nmap, CVE lookup, log analysis, etc.)
5. Results fed back to model
6. Loop until model produces final answer

## Running

```bash
# CLI mode
cd /opt/argos/agent
python3 main.py --mode cli

# Telegram mode
python3 main.py --mode telegram --token YOUR_BOT_TOKEN --allowed-ids 123456789
```

## Tools Available (169 total — 37 built-in + 128 plugins + 4 orchestrator)

### Network Recon
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scan with service detection (-sV). Authorized targets only. |
| `masscan_scan` | Ultra-fast port discovery — scans thousands of ports/sec. Authorized targets only. |
| `ping_host` | ICMP reachability check |
| `dns_lookup` | DNS record query (A, MX, TXT, NS, CNAME, SOA) |
| `whois_lookup` | WHOIS for domain or IP |
| `reverse_dns` | Reverse DNS — IP to hostname |

### OSINT & Threat Intelligence
| Tool | Description |
|------|-------------|
| `cve_lookup` | NVD CVE database — description, CVSS score, severity, references |
| `ip_reputation` | IP geo + ASN + proxy/hosting/mobile detection (ip-api.com) |
| `shodan_host` | Shodan InternetDB — open ports, known CVEs, tags for an IP (free, no key) |
| `shodan_search` | Shodan search query — find exposed hosts by service/port/org/vuln (requires `SHODAN_API_KEY`) |
| `hash_lookup` | Malware hash check on MalwareBazaar (MD5/SHA1/SHA256) |
| `extract_iocs` | Extract IOCs from text: IPs, domains, URLs, hashes, CVE IDs |

### Vulnerability Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Scan URL/IP with 10,000+ Nuclei templates: CVEs, exposed admin panels, default credentials, misconfigs |
| `whatweb_scan` | Fingerprint web technologies: CMS, server software, JS libraries, versions |
| `ssl_check` | SSL/TLS certificate check: expiry, issuer, protocol version, cipher, self-signed detection |

### Advanced OSINT & Attribution
| Tool | Description |
|------|-------------|
| `theharvester_scan` | Harvest emails, subdomains, hosts for a domain from Google, Bing, LinkedIn, DNSDumpster, Shodan |
| `sherlock_search` | Find a username/handle across 400+ social networks — map attacker's online identity |
| `ipwhois_lookup` | Full RDAP/WHOIS for an IP: owner org, network range, ASN, **abuse contact email** |
| `subdomain_enum` | Passive subdomain enumeration via crt.sh (Certificate Transparency) and hackertarget |
| `abuseipdb_check` | Check IP abuse score (0-100), attack categories, reports from 700k+ organizations |
| `abuseipdb_report` | Report attacker IP to global AbuseIPDB database |
| `build_attacker_dossier` | Complete attacker profile: geo, ASN, Shodan, CVEs, abuse history, contacts |
| `generate_leo_report` | **Formal report for law enforcement** (Polizia Postale, CSIRT-IT, Europol, FBI IC3) with MITRE ATT&CK mapping, evidence SHA256 hash, ISP abuse contacts |

### Honeypot
| Tool | Description |
|------|-------------|
| `deploy_honeypot` | Deploy fake SSH, HTTP, FTP, MySQL services to capture attacker credentials and commands |
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
| `analyze_log` | Analyze raw log content for threats: brute force, SQLi, XSS, ransomware, C2, path traversal |
| `read_log_file` | Read and analyze a log file from server filesystem |
| `generate_report` | Generate structured JSON security report, saved to /opt/argos/reports/ |
| `ban_ip` | Permanently ban an IP via fail2ban. Whitelist: 127.0.0.1, localhost, server IP |
| `unban_ip` | Remove an IP ban (false positive correction) |
| `list_banned_ips` | List all currently banned IPs |

## Realtime vs Nightly

ARGOS ha due livelli di difesa attiva:

| | Realtime Watcher | Nightly Analysis |
|---|---|---|
| **File** | `realtime_watcher.py` | `nightly_analysis.py` |
| **Quando gira** | Sempre, H24 | Cron alle 02:00 |
| **Come** | `systemd` service (auto-start al boot) | crontab |
| **Reazione** | Banna entro secondi | Banna la notte successiva |
| **Trigger ban** | 5 hit in 120s, oppure 1 hit CRITICAL | ≥10 attacchi o ≥3 da hosting/proxy |
| **Alert** | Telegram istantaneo | Report JSON in `/opt/argos/reports/` |
| **Log** | `/opt/argos/logs/watcher.log` | `/opt/argos/logs/nightly.log` |

Pattern CRITICAL → ban immediato (1 solo hit):
`SQL_INJECTION`, `CMD_INJECTION`, `REVERSE_SHELL`, `CREDENTIAL_DUMP`, `DOWNLOAD_EXEC`

Pattern HIGH/MEDIUM → ban dopo 5 hit in 120 secondi:
`BRUTE_FORCE`, `PATH_TRAVERSAL`, `XSS`

## Installation (plug & play)

```bash
# On any Ubuntu/Debian server:
sudo bash /opt/argos/installer/install.sh
```

Installs: nmap, masscan, whatweb, nuclei, fail2ban, Python deps, ARGOS directories, nightly cron.

Optional env vars (add to `/etc/environment`):
```
ARGOS_LLM_URL=http://localhost:8080/v1/chat/completions
ARGOS_LLM_KEY=your_api_key
SHODAN_API_KEY=your_shodan_key       # free at shodan.io/account
ABUSEIPDB_API_KEY=your_key           # free at abuseipdb.com/register — 1000 checks/day
```

### AbuseIPDB setup (free)

1. Registrati su [abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Vai su Account → API → crea una key
3. Aggiungila al server:
   ```bash
   echo 'ABUSEIPDB_API_KEY=your_key_here' >> /etc/environment
   source /etc/environment
   ```

Con la key attiva ARGOS può:
- Controllare lo score di abuso di ogni IP attaccante (0-100)
- Vedere lo storico degli attacchi segnalati da 700.000+ organizzazioni nel mondo
- **Segnalare automaticamente** gli attaccanti al database globale dopo ogni ban
- Includere il punteggio nel dossier per le forze dell'ordine

## Plugins (42 plugins, 128 tools — hot-loadable, no restart needed)

Plugins live in `agent/plugins/` and are auto-loaded at startup. Drop a `.py` file in and it's available.

### Threat Intelligence (free APIs)

| Plugin | Tools | Key Required | Free Tier |
|--------|-------|-------------|-----------|
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

### Pentest Report Generation

| Plugin | Tools | Notes |
|--------|-------|-------|
| `pentest_report.py` | `generate_pentest_report` | HTML + Markdown + JSON output, CVSS scoring, MITRE ATT&CK, executive summary |

### AI Pentest Agents (authorized use only)

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `pentestgpt.py` | `pentestgpt_run` | `pip install pentestgpt` | Uses ARGOS local LLM or Claude |
| `pentagi.py` | `pentagi_start_flow`, `pentagi_get_flow`, `pentagi_list_flows` | `PENTAGI_URL` + `PENTAGI_TOKEN` | Self-hosted Docker |
| `pentest_copilot.py` | `pentest_copilot_start`, `pentest_copilot_status`, `pentest_copilot_consent` | `PENTEST_COPILOT_URL` + token | Real Kali + Burp Suite integration |

### Offensive / Pentest CLI (authorized use only)

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `sn1per.py` | `sn1per_scan` | `sniper` CLI | `bash <(curl -sL install-sniper.sh)` |
| `netexec.py` | `netexec_smb`, `netexec_ssh`, `netexec_ldap`, `netexec_winrm` | `nxc` CLI | `pipx install NetExec` |
| `gobuster.py` | `gobuster_dir`, `gobuster_dns` | `gobuster` + SecLists | `apt install gobuster seclists` |
| `offensive_payloads.py` | `get_payloads`, `list_payload_categories` | None (fetches from GitHub) | Offline: `/opt/argos/payloads` (cloned by installer) |
| `reverse_shells.py` | `generate_reverse_shell`, `list_shell_types` | None | PHP obfuscated variant + 10 other types |

### Honeypot Platform

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `tpot.py` | `tpot_stats`, `tpot_credentials`, `tpot_search_ip` | `TPOT_HOST` env var | T-Pot self-hosted |

### DoS Resilience Testing (authorized pentest only)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `stress_test.py` | `mhddos_test`, `impulse_test`, `dripper_test`, `kraken_test`, `stress_test_full` | Auto-installs MHDDoS (57 methods), Impulse, DDoS-Ripper, Kraken to `/opt/argos/stress/`. MAX 200 threads, 300s. |

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
| `pentest_swarm.py` | `pentest_swarm_start`, `pentest_swarm_status`, `pentest_swarm_findings`, `pentest_swarm_list_campaigns` | `PENTESTSWARM_ORCHESTRATOR_API_KEY` | CLI: `pentestswarm scan target` — 5 AI agents, 7 native Go tools |
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
| `cloakify.py` | `cloakify_encode`, `cloakify_decode`, `list_cloakify_ciphers` | Encodes data as emoji/LOTR/sports teams to test DLP controls. Auto-clones TryCatchHCF/Cloakify. |

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
| `atomic_red_team.py` | `art_list_techniques`, `art_get_technique`, `art_execute_test`, `art_simulate_tactic` | Red Canary atomic tests mapped to MITRE ATT&CK. Parses YAML technique files, executes bash/powershell/python executors. |

### OSINT Platforms

| Plugin | Tools | Notes |
|--------|-------|-------|
| `spiderfoot.py` | `spiderfoot_scan`, `spiderfoot_scan_results`, `spiderfoot_list_modules` | 400+ OSINT modules: IPs, domains, emails, usernames, phones. Shodan/VT/HaveIBeenPwned/Censys. CLI or REST API (`SPIDERFOOT_URL`). |
| `username_osint.py` | `userrecon_search`, `instagram_recon`, `extract_urls_from_page` | Username recon across 200+ platforms (userrecon/Sherlock), Instagram public profile OSINT, URL extraction from pages. |

### Hak5 Hardware Payloads

| Plugin | Tools | Notes |
|--------|-------|-------|
| `hak5_payloads.py` | `hak5_list_devices`, `hak5_list_payloads`, `hak5_get_payload`, `hak5_search_payloads` | Payload library for OMG Cable, BashBunny, KeyCroc, SharkJack, USB Rubber Ducky. Auto-clones wlmzz/omg-payloads etc. |

### WordPress Security

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `wordpress_scan.py` | `wpscan_vuln_scan`, `wpscan_user_enum`, `wpscan_password_attack` | `gem install wpscan` or Docker | `WPSCAN_API_TOKEN` for full CVE data. Vulnerable plugins/themes, user enum, brute-force. |

### Social Engineering Testing (authorized red team only)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `social_engineering.py` | `maskphish_create`, `seeker_list_templates`, `seeker_start`, `stormbreaker_start` | maskphish URL obfuscation, seeker geolocation capture, Storm-Breaker webcam/mic access testing. **SIGNED WRITTEN CONSENT REQUIRED.** |

### Payload Extension (LFI / SSTI / Encoders)

| Plugin | Tools | Notes |
|--------|-------|-------|
| `hacktools.py` | `hacktools_lfi_payloads`, `hacktools_ssti_payloads`, `hacktools_encode`, `hacktools_headers_cheatsheet` | LFI/RFI payloads (PHP wrappers, traversal, /proc), SSTI for 8 engines (Jinja2/Twig/Freemarker/Mako/ERB/etc.), WAF bypass encoders, HTTP header cheatsheets. From LasCC/HackTools. |

### AI Pentesting Assistant

| Plugin | Tools | Requires | Notes |
|--------|-------|---------|-------|
| `nebula.py` | `nebula_query`, `nebula_docker`, `nebula_list_capabilities` | `pip install nebula-ai` + Ollama or OpenAI | Natural language security tasks: "! scan 192.168.1.1 for open ports". Set `NEBULA_MODEL` for local Ollama. |

### Add all API keys at once:

```bash
cat >> /etc/environment << 'EOF'
# ARGOS Plugin API Keys — add the ones you have
VIRUSTOTAL_API_KEY=your_key      # virustotal.com/gui/join-us (free)
GREYNOISE_API_KEY=your_key       # greynoise.io (optional, community works without)
OTX_API_KEY=your_key             # otx.alienvault.com (free)
URLSCAN_API_KEY=your_key         # urlscan.io/user/signup (100/day free)
CENSYS_API_ID=your_id            # censys.io/register (250/month free)
CENSYS_API_SECRET=your_secret
HYBRID_ANALYSIS_API_KEY=your_key # hybrid-analysis.com (free)
IPINFO_TOKEN=your_token          # ipinfo.io/signup (50K/month free)
IP2LOCATION_API_KEY=your_key     # ip2location.io/sign-up (30K/month free)
HIBP_API_KEY=your_key            # haveibeenpwned.com/API/Key (~$3.50/month)
EMAILREP_API_KEY=your_key        # emailrep.io (optional)
PULSEDIVE_API_KEY=your_key       # pulsedive.com (optional)
OPENCTI_URL=http://your-opencti:4000
OPENCTI_TOKEN=your-api-token
TPOT_HOST=your-tpot-ip           # T-Pot server IP
WPSCAN_API_TOKEN=your_token      # wpscan.com/register (free) — full CVE data
SPIDERFOOT_URL=http://localhost:5001  # if running SpiderFoot as server (optional)
PENTEST_SWARM_URL=http://localhost:8888  # Pentest-Swarm API (optional)
POWERPWN_AUTH_TOKEN=your_token   # Microsoft 365 auth token
EOF
source /etc/environment
```

### Subagent Orchestration

Run multiple ARGOS tasks in parallel:

```
spawn_subagents([
    {"task": "Port scan 10.0.0.1", "label": "portscan", "tools": ["nmap_scan", "masscan_scan"]},
    {"task": "Full OSINT on 10.0.0.1", "label": "osint",
        "tools": ["shodan_host", "greynoise_ip", "otx_ip", "abuseipdb_check", "ipinfo_lookup"]},
    {"task": "Check TLS of site.com", "label": "tls",
        "tools": ["ssllabs_analyze", "ssl_check"]},
    {"task": "Scan for vulns on site.com", "label": "vulns",
        "tools": ["nuclei_scan", "whatweb_scan", "gobuster_dir"]},
])
```

All 4 run simultaneously. Results aggregated when all finish.

### Repos not integrated (and why):

| Repo | Reason |
|------|--------|
| `wlmzz/Yuan3.0` | 40B MoE language model (HuggingFace) — not a security tool, no CLI |
| `M4cs/BabySploit` | Beginner tool — functionality covered by existing plugins (nmap, nuclei, gobuster) |
| `Technowlogy-Pushpender/hackerpro` | All-in-one wrapper — every tool it calls is already integrated individually |
| `JGrotex/AutoPentestX` | Automated framework — superseded by pentest_swarm + pentest_copilot |
| `m4ll0k/pentesting-framework` | Limited scope — covered by existing pentest tools |
| `OpenSourcePentest/tools` | Documentation/links collection, no executable code |
| `cyberguideme/Tools` | Documentation/links only, no executable code |
| `A-poc/RedTeam-Tools` | Documentation/MITRE ATT&CK reference list, no code |
| `enaqx/awesome-pentest` | Curated links list, no code |
| `paralax/awesome-honeypots` | Curated links list, no code |
| `rajkumardusad/IP-Tracer` | Unmaintained CLI wrapper over ip-api.com — already in `ip_reputation` tool |
| `ip2location-com/ip2location-nginx` | Nginx C module (not wrappable) — used REST API instead via `ip2location.py` |
| `syztem4our666/zsh-pentester` | Thin zsh wrappers — underlying tools (nmap, gobuster) already integrated |
| `anthropics/claude-code-security-review` | GitHub Actions action, not a subprocess |
| `pluginagentmarketplace/custom-plugin-cyber-security` | Claude Code IDE plugin, different runtime |
| `lucasjacks0n/EggShell` | macOS/iOS RAT/surveillance (microphone recording, location tracking, USB injection) — unauthorized surveillance risk |
| `Lomasterrrr/HackWebTool` | CloudFlare bypass + credential brute-force without authorization framework — repo closed by author |
| `mrprogrammer2938/Black-Tool` | All-in-one wrapper (Nmap, WPScan, etc.) — every tool it calls is already integrated individually |
| `x11-repo/hack-tools-en` | Tool aggregator launcher — all underlying tools already integrated individually |
| `TianWen-Lab/TranSec` | Full Linux OS distribution for automotive security — not wrappable as a plugin |

## Complete Penetration Test Workflow

ARGOS può condurre un pentest completo in autonomia e generare un report professionale.
Chiedi semplicemente: *"Fai un pentest completo di 10.0.0.1 e genera il report"*

Il modello orchestrerà autonomamente questi step usando i subagent:

```
Step 1 — Recon (parallelo)
  ├── nmap_scan           → porte aperte, servizi, banner
  ├── masscan_scan        → scoperta rapida full-port
  ├── shodan_host         → CVE note, tag Shodan
  ├── whatweb_scan        → tecnologie web (CMS, framework, versioni)
  └── subdomain_enum      → sottodomini passivi (crt.sh + hackertarget)

Step 2 — Threat Intel (parallelo)
  ├── greynoise_ip        → noise vs targeted threat
  ├── abuseipdb_check     → storia attacchi segnalati
  ├── ipinfo_lookup       → ASN, geoloc, VPN/proxy
  └── otx_ip              → pulse AlienVault OTX

Step 3 — Vulnerability Assessment (parallelo)
  ├── nuclei_scan         → 10.000+ template (CVE, panel admin, misconfig)
  ├── ssl_check           → TLS/SSL analisi
  ├── ssllabs_analyze     → grade A-F + Heartbleed/POODLE
  └── gobuster_dir        → directory e file nascosti

Step 4 — Deep Analysis
  ├── theharvester_scan   → email, sottodomini, host da OSINT
  ├── urlscan_submit      → analisi sandbox URL
  └── sn1per_scan         → recon automatizzato completo (se installato)

Step 5 — Report
  └── generate_pentest_report → HTML + Markdown + JSON con:
        ✓ Executive Summary (non-tecnico, per management)
        ✓ Findings con CVSS score (Critical/High/Medium/Low/Info)
        ✓ Proof of Concept / Evidence con SHA256 hash
        ✓ Steps di remediation specifici
        ✓ Mapping MITRE ATT&CK
        ✓ Riferimenti CVE/CWE
        ✓ Report HTML colorato pronto da consegnare al cliente
```

Report salvati in: `/opt/argos/reports/`

### Prompt di esempio per pentest completo

```
"Fai un pentest completo di example.com.
Cerca: porte aperte, vulnerabilità web, sottodomini, problemi TLS.
Alla fine genera un report professionale HTML con tutti i findings."
```

```
"Analizza la sicurezza di 192.168.1.0/24.
Identifica host attivi, servizi esposti, CVE note.
Genera report per il cliente con executive summary e remediation steps."
```

## Telegram Setup

1. Create bot via @BotFather → get token
2. Get your chat ID: message @userinfobot
3. Run: `python3 main.py --mode telegram --token TOKEN --allowed-ids YOUR_CHAT_ID`
