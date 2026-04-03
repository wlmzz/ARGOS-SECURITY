#!/bin/bash
# ARGOS Installer — full plug & play setup
# Usage: sudo bash install.sh
# Tested on Ubuntu 22.04 / 24.04 / Debian 12

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC}  $1"; }
step() { echo -e "\n${BLUE}[>>]${NC} $1"; }

echo "╔══════════════════════════════════════════════╗"
echo "║       ARGOS — Autonomous Security Agent      ║"
echo "║         Full Installer  v2.0  (plug&play)    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    err "Please run as root: sudo bash install.sh"
    exit 1
fi

# ─── 1. APT packages ──────────────────────────────────────────────────────────
step "Step 1/9 — APT packages"
apt-get update -qq
APT_PKGS="
    nmap masscan whatweb whois dnsutils traceroute
    fail2ban lynis ufw
    python3 python3-pip python3-venv pipx
    curl wget unzip git golang
    gobuster
    seclists
    nikto
    sqlmap
    dirb
    netcat-openbsd
    jq net-tools iputils-ping
    build-essential libssl-dev libffi-dev
"
for pkg in $APT_PKGS; do
    pkg=$(echo $pkg | tr -d ' ')
    [ -z "$pkg" ] && continue
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        ok "$pkg already installed"
    else
        apt-get install -y -qq "$pkg" 2>/dev/null && ok "$pkg installed" || warn "$pkg not available — skipping"
    fi
done

# ─── 2. Nuclei ────────────────────────────────────────────────────────────────
step "Step 2/9 — Nuclei (vulnerability scanner)"
if command -v nuclei &>/dev/null; then
    ok "Nuclei already installed: $(nuclei -version 2>&1 | head -1)"
else
    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 2>/dev/null)
    NUCLEI_VER=${NUCLEI_VER:-v3.7.1}
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" -o /tmp/nuclei.zip
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei
    chmod +x /usr/local/bin/nuclei
    rm -f /tmp/nuclei.zip
    ok "Nuclei ${NUCLEI_VER} installed"
fi
# Update templates in background
nuclei -update-templates -silent & 2>/dev/null
ok "Nuclei templates update started (background)"

# ─── 3. NetExec (nxc) ─────────────────────────────────────────────────────────
step "Step 3/9 — NetExec (network pentesting framework)"
if command -v nxc &>/dev/null; then
    ok "NetExec already installed: $(nxc --version 2>&1 | head -1)"
else
    if command -v pipx &>/dev/null; then
        pipx install "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null && ok "NetExec installed via pipx" \
            || pip3 install --break-system-packages "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null && ok "NetExec installed via pip3" \
            || warn "NetExec install failed — install manually: pipx install git+https://github.com/Pennyw0rth/NetExec"
    else
        pip3 install --break-system-packages "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null && ok "NetExec installed" \
            || warn "NetExec install failed — install manually"
    fi
fi

# ─── 4. Python tools ──────────────────────────────────────────────────────────
step "Step 4/9 — Python security tools"

_pip_install() {
    local pkg="$1"
    if pip3 install -q "$pkg" 2>/dev/null; then
        ok "$pkg installed"
    elif pip3 install -q --break-system-packages "$pkg" 2>/dev/null; then
        ok "$pkg installed (--break-system-packages)"
    else
        warn "$pkg install failed"
    fi
}

_pip_install theHarvester
_pip_install sherlock-project
_pip_install requests
_pip_install ipwhois
_pip_install geoip2fast
_pip_install honeypots
_pip_install pentestgpt

ok "Python tools installed"

# ─── 5. Sn1per ────────────────────────────────────────────────────────────────
step "Step 5/9 — Sn1per (attack surface management)"
if command -v sniper &>/dev/null; then
    ok "Sn1per already installed"
else
    warn "Sn1per not installed — install manually for full pentesting:"
    warn "  bash <(curl -sL https://raw.githubusercontent.com/1N3/Sn1per/master/install.sh)"
fi

# ─── 6. Offensive payloads clone ─────────────────────────────────────────────
step "Step 6/9 — Offensive payloads wordlist (offline cache)"
PAYLOADS_DIR="/opt/argos/payloads"
if [ -d "$PAYLOADS_DIR/.git" ]; then
    ok "Offensive-Payloads already cloned — pulling updates"
    git -C "$PAYLOADS_DIR" pull -q 2>/dev/null || warn "Could not pull updates"
else
    git clone -q https://github.com/InfoSecWarrior/Offensive-Payloads "$PAYLOADS_DIR" 2>/dev/null \
        && ok "Offensive-Payloads cloned to $PAYLOADS_DIR" \
        || warn "Could not clone Offensive-Payloads — payloads will be fetched on demand"
fi

# ─── 7. ARGOS directories ─────────────────────────────────────────────────────
step "Step 7/9 — ARGOS directory structure"
mkdir -p /opt/argos/{agent,logs,reports,sessions,payloads}
mkdir -p /opt/argos/agent/{tools,channels,plugins}
mkdir -p /opt/argos/loot/{shells,scans,nmap,sn1per}
chmod 700 /opt/argos/loot
ok "Directories created"

# Set ARGOS_PAYLOADS_DIR env var so plugin finds offline copy
if ! grep -q "ARGOS_PAYLOADS_DIR" /etc/environment 2>/dev/null; then
    echo 'ARGOS_PAYLOADS_DIR=/opt/argos/payloads' >> /etc/environment
    ok "ARGOS_PAYLOADS_DIR set in /etc/environment"
fi

# ─── 8. Cron + systemd ────────────────────────────────────────────────────────
step "Step 8/9 — Cron (nightly) + systemd (realtime)"

# Nightly analysis cron
CRON_JOB="0 2 * * * cd /opt/argos/agent && python3 nightly_analysis.py >> /opt/argos/logs/nightly.log 2>&1"
if crontab -l 2>/dev/null | grep -q "nightly_analysis"; then
    ok "Nightly cron already configured"
else
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    ok "Nightly analysis cron set (runs at 02:00)"
fi

# Realtime watcher systemd service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_SRC="$SCRIPT_DIR/argos-watcher.service"
SERVICE_DST="/etc/systemd/system/argos-watcher.service"
if [ -f "$SERVICE_SRC" ]; then
    cp "$SERVICE_SRC" "$SERVICE_DST"
    systemctl daemon-reload
    systemctl enable argos-watcher
    systemctl restart argos-watcher
    sleep 2
    if systemctl is-active --quiet argos-watcher; then
        ok "argos-watcher service running (realtime threat detection H24)"
    else
        warn "argos-watcher installed but not running — check: journalctl -u argos-watcher -n 20"
    fi
else
    warn "argos-watcher.service not found in $SCRIPT_DIR — skipping"
fi

# ─── 9. Environment variables ─────────────────────────────────────────────────
step "Step 9/9 — Optional API keys setup"

ENV_FILE="/etc/environment"
add_env_comment() {
    local key="$1" comment="$2"
    if ! grep -q "^$key=" "$ENV_FILE" 2>/dev/null && ! grep -q "^#.*$key" "$ENV_FILE" 2>/dev/null; then
        echo "# $comment" >> "$ENV_FILE"
        echo "#${key}=your_key_here" >> "$ENV_FILE"
    fi
}

add_env_comment "ARGOS_LLM_URL"           "ARGOS LLM endpoint (e.g. http://localhost:8080/v1/chat/completions)"
add_env_comment "SHODAN_API_KEY"           "Shodan API key — shodan.io/account (free: 1 query credit)"
add_env_comment "ABUSEIPDB_API_KEY"        "AbuseIPDB API key — abuseipdb.com/register (free: 1000 checks/day)"
add_env_comment "VIRUSTOTAL_API_KEY"       "VirusTotal — virustotal.com/gui/join-us (free: 4 req/min)"
add_env_comment "OTX_API_KEY"             "AlienVault OTX — otx.alienvault.com (free)"
add_env_comment "URLSCAN_API_KEY"          "URLScan.io — urlscan.io/user/signup (free: 100/day)"
add_env_comment "CENSYS_API_ID"            "Censys API ID — censys.io/register (free: 250/month)"
add_env_comment "CENSYS_API_SECRET"        "Censys API Secret (same registration)"
add_env_comment "HYBRID_ANALYSIS_API_KEY"  "Hybrid Analysis — hybrid-analysis.com (free)"
add_env_comment "IPINFO_TOKEN"             "IPInfo token — ipinfo.io/signup (free: 50K/month)"
add_env_comment "IP2LOCATION_API_KEY"      "IP2Location — ip2location.io/sign-up (free: 30K/month)"
add_env_comment "HIBP_API_KEY"             "Have I Been Pwned — haveibeenpwned.com/API/Key (~3.50/month)"
add_env_comment "OPENCTI_URL"              "OpenCTI URL (e.g. http://your-opencti:4000)"
add_env_comment "OPENCTI_TOKEN"            "OpenCTI Bearer token (Settings → Profile → API Access)"
add_env_comment "TPOT_HOST"                "T-Pot server IP (github.com/telekom-security/tpotce)"
add_env_comment "PENTAGI_URL"              "PentAGI URL (e.g. https://your-pentagi:8443)"
add_env_comment "PENTAGI_TOKEN"            "PentAGI Bearer token (Settings → API Tokens)"
add_env_comment "PENTEST_COPILOT_URL"      "Pentest Copilot URL (e.g. http://localhost:8080)"
add_env_comment "PENTEST_COPILOT_TOKEN"    "Pentest Copilot session token"
add_env_comment "GREYNOISE_API_KEY"        "GreyNoise — greynoise.io (community works without key)"
add_env_comment "EMAILREP_API_KEY"         "EmailRep — emailrep.io (free: 10/day without key)"
add_env_comment "PULSEDIVE_API_KEY"        "Pulsedive — pulsedive.com (free tier)"

ok "API key placeholders added to $ENV_FILE (uncomment and fill in)"

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║           Installation Complete!             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Tools installed:"
command -v nmap      &>/dev/null && echo "  ✓ nmap"        || echo "  ✗ nmap"
command -v masscan   &>/dev/null && echo "  ✓ masscan"     || echo "  ✗ masscan"
command -v nuclei    &>/dev/null && echo "  ✓ nuclei"      || echo "  ✗ nuclei"
command -v gobuster  &>/dev/null && echo "  ✓ gobuster"    || echo "  ✗ gobuster"
command -v whatweb   &>/dev/null && echo "  ✓ whatweb"     || echo "  ✗ whatweb"
command -v nikto     &>/dev/null && echo "  ✓ nikto"       || echo "  ✗ nikto"
command -v sqlmap    &>/dev/null && echo "  ✓ sqlmap"      || echo "  ✗ sqlmap"
command -v nxc       &>/dev/null && echo "  ✓ nxc (NetExec)" || echo "  ✗ nxc (NetExec) — install manually"
command -v sniper    &>/dev/null && echo "  ✓ sniper (Sn1per)" || echo "  ✗ sniper — install manually (see README)"
command -v fail2ban-client &>/dev/null && echo "  ✓ fail2ban" || echo "  ✗ fail2ban"
[ -d "$PAYLOADS_DIR" ] && echo "  ✓ Offensive-Payloads ($PAYLOADS_DIR)" || echo "  ✗ Offensive-Payloads (will fetch on demand)"
echo ""
echo "  Services:"
systemctl is-active --quiet argos-watcher 2>/dev/null && echo "  ✓ argos-watcher (realtime)" || echo "  ✗ argos-watcher not running"
crontab -l 2>/dev/null | grep -q nightly && echo "  ✓ nightly cron (02:00)" || echo "  ✗ nightly cron not set"
echo ""
echo "  Run ARGOS:"
echo "    cd /opt/argos/agent && python3 main.py --mode cli"
echo ""
echo "  Configure API keys:"
echo "    nano /etc/environment    # uncomment and fill in your keys"
echo "    source /etc/environment"
echo ""
echo "  Full docs: /opt/argos/agent/README.md"
echo ""
