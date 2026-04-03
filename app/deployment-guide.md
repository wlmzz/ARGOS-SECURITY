# Deployment Guide

This guide covers all three ARGOS deployment modes in detail. Read the relevant section for your setup.

---

## Table of Contents

- [Before You Start](#before-you-start)
- [Mode 1: Standalone](#mode-1-standalone)
- [Mode 2: Self-Hosted](#mode-2-self-hosted)
- [Mode 3: Cloud](#mode-3-cloud)
- [Installing the Agent](#installing-the-agent)
- [TLS Certificates](#tls-certificates)
- [Firewall Configuration](#firewall-configuration)
- [Environment Variables](#environment-variables)
- [Running as a System Service](#running-as-a-system-service)
- [Updating ARGOS](#updating-argos)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)

---

## Before You Start

### Choosing Your Mode

**Standalone** — best for:
- Individual devices (laptop, personal server)
- Maximum privacy (nothing leaves the machine)
- Air-gapped environments
- Testing and evaluation

**Self-Hosted** — best for:
- Businesses and home labs with multiple devices
- Centralized monitoring and control
- Shared threat intelligence within your network
- Full control over all data

**Cloud** — best for:
- Devices with limited compute (old hardware, embedded systems)
- Quick setup without server management
- Access to community threat intelligence
- Pay only infrastructure costs

### Prerequisites

All modes:
- Python 3.10 or higher
- 512 MB free RAM on the agent device
- Network connectivity to the target system

Self-hosted additionally:
- A server with at least 64 GB RAM (for Phi-4 14B)
- Docker and Docker Compose, or manual Python/Node.js environment
- A domain name (for TLS — strongly recommended)

---

## Mode 1: Standalone

Everything runs on the device being protected. No external connections.

### Step 1: Install

```bash
# Clone
git clone https://github.com/argos-security/argos.git
cd argos

# Install Python dependencies
pip3 install -r requirements.txt

# Install Ollama (AI engine)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the AI model
ollama pull phi4:14b
# This downloads ~8 GB. Use llama3.2:8b for smaller devices (~5 GB).
```

### Step 2: First Run

```bash
# Start ARGOS in standalone mode, semi-autonomous, with debug output
sudo python3 argos_agent.py --mode=standalone --autonomy=semi --debug
```

You will see the ARGOS banner and confirmation that monitoring has started.

The first run creates `~/.argos/config.json` with your settings.

### Step 3: Run as Service (Linux)

```bash
# Copy service file
sudo cp installer/argos.service /etc/systemd/system/

# Edit the service file if needed
sudo nano /etc/systemd/system/argos.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable argos
sudo systemctl start argos

# Check status
sudo systemctl status argos
sudo journalctl -u argos -f
```

### Step 4: Configure

Edit `~/.argos/config.json` to adjust settings:

```json
{
  "mode": "standalone",
  "ai_model": "phi4:14b",
  "ollama_url": "http://localhost:11434",
  "scan_interval": 5,
  "autonomy_level": "semi",
  "honeypot_enabled": true,
  "log_level": "INFO"
}
```

Restart after changes: `sudo systemctl restart argos`

### Hardware Recommendations for Standalone

| Device Class | RAM | Recommended Model | Notes |
|-------------|-----|-------------------|-------|
| Server | 128+ GB | phi4:14b | Best quality |
| Desktop | 32–64 GB | phi4:14b quantized | Good quality |
| Laptop | 16–32 GB | llama3.2:8b | Acceptable |
| Old hardware | 8–16 GB | llama3.2:3b | Basic detection |
| Raspberry Pi | 4–8 GB | No local AI | Rule-based only |

---

## Mode 2: Self-Hosted

You run the ARGOS server. All devices connect to it.

### Architecture

```
[Agent 1: Web Server]   ─┐
[Agent 2: Workstation]  ──┼─> [ARGOS Server] <─> [Ollama AI]
[Agent 3: NAS]          ─┘         │
                                   ├─> [PostgreSQL]
                                   ├─> [Redis]
                                   └─> [Dashboard / Mobile App]
```

### Step 1: Prepare the Server

**Minimum server requirements:** 16 cores, 64 GB RAM, 500 GB SSD, Ubuntu 22.04+

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo apt install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

### Step 2: Clone and Configure

```bash
# Clone
git clone https://github.com/argos-security/argos.git
cd argos

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

Minimum `.env` to edit:

```env
# Database password — change this
POSTGRES_PASSWORD=choose_a_strong_password_here

# Your server's public domain or IP
ARGOS_SERVER_URL=https://argos.yourdomain.com

# Optional: Claude API for escalation
CLAUDE_API_KEY=sk-ant-...
```

### Step 3: TLS Certificates

ARGOS must run with TLS to protect agent-to-server communication.

**Option A — Let's Encrypt (recommended for public domains):**

```bash
# Install certbot
sudo apt install -y certbot

# Get certificate
sudo certbot certonly --standalone -d argos.yourdomain.com

# Copy to certs directory
mkdir -p certs
sudo cp /etc/letsencrypt/live/argos.yourdomain.com/fullchain.pem certs/cert.pem
sudo cp /etc/letsencrypt/live/argos.yourdomain.com/privkey.pem   certs/key.pem
sudo chown $USER:$USER certs/*.pem
chmod 600 certs/key.pem
```

**Option B — Self-signed (for internal networks):**

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/C=IT/O=ARGOS/CN=argos.internal" \
  -addext "subjectAltName=IP:YOUR_SERVER_IP,DNS:argos.internal"
```

Agents connecting to a self-signed server need:
```json
{ "verify_tls": false }
```
in their config (or use the `--no-verify-tls` flag).

### Step 4: Start the Stack

```bash
# Pull images and start everything
docker compose up -d

# Watch startup (first time pulls Phi-4 — takes 10–20 minutes)
docker compose logs -f ollama-init
docker compose logs -f server

# Verify all services are healthy
docker compose ps
```

Expected output:
```
NAME              STATUS
argos-postgres    running (healthy)
argos-redis       running
argos-ollama      running (healthy)
argos-server      running (healthy)
argos-dashboard   running
argos-nginx       running
```

Dashboard is accessible at: `https://argos.yourdomain.com` (or your IP on port 3000)
API is accessible at: `https://argos.yourdomain.com:8443`

### Step 5: Register Agent Devices

On the server, register each device that will connect:

```bash
curl -X POST https://argos.yourdomain.com:8443/api/devices/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web-server-01",
    "platform": "linux",
    "autonomy": "semi"
  }'
```

Response:
```json
{
  "device_id": "a1b2c3d4e5f6...",
  "token": "eyJhbGci..."
}
```

Save both — the token cannot be retrieved again.

### Step 6: Install Agent on Each Device

On each device to protect:

```bash
# Clone agent
git clone https://github.com/argos-security/argos.git
cd argos
pip3 install -r requirements.txt

# Start connected to your server
sudo python3 argos_agent.py \
  --mode=self-hosted \
  --server=https://argos.yourdomain.com:8443 \
  --token=YOUR_TOKEN_HERE \
  --autonomy=semi
```

The device will appear in your dashboard within seconds.

---

## Mode 3: Cloud

Connect to the community ARGOS server. Minimal local hardware required.

### Step 1: Register

Visit `https://argos-security.io/register` and create a free account.

Choose your billing method (infrastructure cost only — no markup):
- Pay-per-use: charged per GB of data processed
- Monthly flat: fixed rate per connected device

### Step 2: Register Your Devices

From the web dashboard, click "Add Device" for each machine you want to protect. You'll receive a device ID and token.

### Step 3: Install Agent

```bash
git clone https://github.com/argos-security/argos.git
cd argos
pip3 install -r requirements.txt

sudo python3 argos_agent.py \
  --mode=cloud \
  --server=https://cloud.argos-security.io \
  --token=YOUR_TOKEN_HERE
```

That's it. The agent is lightweight in cloud mode — it collects data locally and sends it to the server for analysis.

---

## Installing the Agent

### Linux (systemd)

```bash
# As root or with sudo
cp installer/argos.service /etc/systemd/system/

# Edit paths if you installed argos in a non-standard location
nano /etc/systemd/system/argos.service

systemctl daemon-reload
systemctl enable --now argos

# Verify
systemctl status argos
```

`installer/argos.service`:
```ini
[Unit]
Description=ARGOS Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/argos
ExecStart=/usr/bin/python3 /opt/argos/argos_agent.py --mode=standalone --autonomy=semi
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### macOS (LaunchDaemon)

```bash
sudo cp installer/io.argos.agent.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/io.argos.agent.plist
sudo launchctl start io.argos.agent
```

### Windows (Service)

Run PowerShell as Administrator:

```powershell
# Install NSSM (Non-Sucking Service Manager)
choco install nssm

# Install ARGOS as a Windows service
nssm install ARGOS "C:\Python310\python.exe" "C:\argos\argos_agent.py --mode=standalone --autonomy=semi"
nssm set ARGOS AppDirectory "C:\argos"
nssm set ARGOS DisplayName "ARGOS Security Agent"
nssm set ARGOS Description "Open Source AI Security Platform"
nssm set ARGOS Start SERVICE_AUTO_START

# Start the service
nssm start ARGOS

# Verify
Get-Service ARGOS
```

---

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./argos.db` | Database connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `AI_MODEL` | `phi4:14b` | Ollama model name |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8443` | Server port |
| `SSL_KEY` | *(none)* | Path to TLS private key |
| `SSL_CERT` | *(none)* | Path to TLS certificate |
| `CLAUDE_API_KEY` | *(none)* | Claude API key for escalation |
| `TRAINING_DIR` | `./training_data` | Training data directory |
| `MIN_TRAINING_EXAMPLES` | `50` | Minimum examples before training |
| `DEV` | `false` | Enable dev mode (auto-reload) |

### Agent

Configured via `~/.argos/config.json` or CLI flags. See [Configuration](../README.md#configuration).

---

## Firewall Configuration

### Server Inbound Rules

```bash
# ARGOS API (agents + dashboard backend)
ufw allow 8443/tcp

# Dashboard (if not using nginx reverse proxy)
ufw allow 3000/tcp

# Nginx reverse proxy (if using)
ufw allow 80/tcp
ufw allow 443/tcp

# SSH (for management — restrict to your IP)
ufw allow from YOUR_ADMIN_IP to any port 22

# Enable
ufw enable
```

### Agent Outbound Rules

Agents need outbound access to:
- Your ARGOS server (port 8443 or 443)
- `api.abuseipdb.com` (optional, for IP enrichment)
- `ip-api.com` (optional, for geolocation)
- `api.anthropic.com` (optional, for Claude API escalation)

No inbound ports are required for agents in self-hosted or cloud mode.

In standalone mode, if honeypots are enabled, the agent listens on targeted ports locally.

---

## Updating ARGOS

### Agent Update

```bash
cd argos/
git pull origin main
pip3 install -r requirements.txt
sudo systemctl restart argos
```

### Server Update (Docker)

```bash
cd argos/
git pull origin main
docker compose pull
docker compose up -d
docker compose logs -f server
```

Database migrations run automatically on startup.

---

## Backup and Restore

### Backup (Self-Hosted)

```bash
#!/bin/bash
# backup-argos.sh — run daily via cron

BACKUP_DIR="/backup/argos/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Database
docker compose exec postgres pg_dump -U argos argos > "$BACKUP_DIR/argos.sql"

# Evidence files
cp -r ~/.argos/evidence/ "$BACKUP_DIR/evidence/"

# Configuration
cp -r ~/.argos/config.json "$BACKUP_DIR/"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup complete: $BACKUP_DIR.tar.gz"
```

Add to crontab: `0 2 * * * /opt/argos/backup-argos.sh`

### Restore

```bash
# Extract backup
tar -xzf backup-20260319.tar.gz

# Restore database
docker compose exec -T postgres psql -U argos argos < backup-20260319/argos.sql

# Restore evidence
cp -r backup-20260319/evidence/ ~/.argos/evidence/

# Restart
docker compose restart server
```

---

## Troubleshooting

### Agent Won't Start

**Permission denied on network monitoring:**
```
[WARNING] Network monitoring requires elevated privileges
```
Solution: Run with `sudo` or grant `CAP_NET_ADMIN` capability:
```bash
sudo setcap cap_net_admin,cap_net_raw+ep /usr/bin/python3
```

**Ollama not found:**
```
[WARNING] Ollama not available — rule-based fallback active
```
Solution: Install Ollama and pull the model:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull phi4:14b
```

**Port already in use:**
```
OSError: [Errno 98] Address already in use
```
Solution: A honeypot is trying to bind a port already in use. Disable honeypots or change the conflicting service's port.

### Server Won't Start

**Database connection failed:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
Solution: Ensure PostgreSQL is running:
```bash
docker compose up -d postgres
docker compose logs postgres
```

**Ollama not reachable:**
```
[WARNING] Ollama not reachable — rule-based fallback active
```
Solution: Check Ollama container:
```bash
docker compose logs ollama
docker compose exec ollama ollama list
```

**Port 8443 in use:**
```
ERROR: address already in use
```
Solution: Change the port in `docker-compose.yml` or stop the conflicting process.

### Dashboard Not Loading

- Verify the server is running: `curl https://your-server:8443/health`
- Check CORS — the server must allow requests from the dashboard origin
- Check browser console for errors
- Verify `VITE_API_URL` in the dashboard environment matches the server URL

### Agents Not Appearing in Dashboard

- Verify the agent is running: `systemctl status argos`
- Check the server URL and token in agent config
- Verify firewall allows outbound from agent to server port 8443
- Check agent logs: `journalctl -u argos -f`
- Check server logs: `docker compose logs server`

### High False Positive Rate

The AI model may flag legitimate traffic as threats in the first days of operation because it has no baseline for your network.

Short-term: Switch to `supervised` autonomy mode and review each alert manually.

Long-term: The baseline learning system (in development) will automatically learn what is normal for your environment.

Immediate relief: Whitelist known-good IPs:
```json
{
  "whitelisted_ips": ["10.0.1.0/24", "192.168.1.0/24"]
}
```

---

*ARGOS Deployment Guide — v0.1.0*
