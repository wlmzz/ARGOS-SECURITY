#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ARGOS Tool Installer — installa tutti i tool CLI usati dai plugin
# Ubuntu 24.04 · Testato su IONOS AMD EPYC 125GB RAM
# Uso: bash install_tools.sh [--skip-heavy]
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
SKIP_HEAVY=${1:-""}
LOG="/opt/argos/logs/install_tools.log"
mkdir -p /opt/argos/logs /opt/argos/yara_rules/custom /opt/argos/wordlists

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
ok()  { echo "  ✓ $*" | tee -a "$LOG"; }
skip(){ echo "  · $* già installato" | tee -a "$LOG"; }
fail(){ echo "  ✗ $* FALLITO — continuo" | tee -a "$LOG"; }

log "=== ARGOS Tool Installer ==="
log "Sistema: $(lsb_release -ds 2>/dev/null || echo 'Linux')"

# ── 0. Aggiorna apt ──────────────────────────────────────────────────────────
log "[0/10] Aggiornamento apt..."
apt-get update -qq 2>>"$LOG" && ok "apt aggiornato"

# ── 1. SAST ──────────────────────────────────────────────────────────────────
log "[1/10] SAST — Semgrep, Bandit, Trivy..."

if ! command -v semgrep &>/dev/null; then
    pip3 install semgrep --break-system-packages -q && ok "semgrep installato" || fail "semgrep"
else skip "semgrep"; fi

if ! command -v bandit &>/dev/null; then
    pip3 install bandit --break-system-packages -q && ok "bandit installato" || fail "bandit"
else skip "bandit"; fi

if ! command -v trivy &>/dev/null; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>>"$LOG" \
        && ok "trivy installato" || fail "trivy"
else skip "trivy"; fi

# ── 2. Malware Detection ─────────────────────────────────────────────────────
log "[2/10] Malware — YARA, ClamAV..."

if ! command -v yara &>/dev/null; then
    apt-get install -y -qq yara 2>>"$LOG" && ok "yara installato" || fail "yara"
else skip "yara"; fi

if ! command -v clamscan &>/dev/null; then
    apt-get install -y -qq clamav clamav-daemon 2>>"$LOG" \
        && freshclam 2>>"$LOG" \
        && ok "clamav installato + definizioni aggiornate" || fail "clamav"
else skip "clamav"; fi

# ── 3. Network IDS ───────────────────────────────────────────────────────────
log "[3/10] Network IDS — Zeek, Suricata..."

if ! command -v zeek &>/dev/null && ! command -v zcat &>/dev/null; then
    # Zeek da repository ufficiale
    apt-get install -y -qq gnupg 2>>"$LOG"
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
        > /etc/apt/sources.list.d/zeek.list 2>>"$LOG" || true
    curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg 2>>"$LOG" || true
    apt-get update -qq 2>>"$LOG"
    apt-get install -y -qq zeek 2>>"$LOG" && ok "zeek installato" || {
        # Fallback: zeek da apt standard
        apt-get install -y -qq zeek 2>>"$LOG" && ok "zeek installato (apt)" || fail "zeek"
    }
    # Aggiungi zeek al PATH
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/environment
    export PATH=$PATH:/opt/zeek/bin
else skip "zeek"; fi

if ! command -v suricata &>/dev/null; then
    apt-get install -y -qq suricata 2>>"$LOG" \
        && suricata-update 2>>"$LOG" \
        && ok "suricata installato + regole aggiornate" || fail "suricata"
else skip "suricata"; fi

# ── 4. Memory Forensics ──────────────────────────────────────────────────────
log "[4/10] Forensics — Volatility 3..."

if ! command -v vol &>/dev/null && ! python3 -c "import volatility3" &>/dev/null 2>&1; then
    pip3 install volatility3 --break-system-packages -q 2>>"$LOG" && ok "volatility3 installato" || fail "volatility3"
    # Crea wrapper
    cat > /usr/local/bin/vol << 'VOLEOF'
#!/bin/bash
python3 -m volatility3 "$@"
VOLEOF
    chmod +x /usr/local/bin/vol
else skip "volatility3"; fi

# ── 5. HTTP Fuzzing ──────────────────────────────────────────────────────────
log "[5/10] Fuzzing — FFUF, wordlists..."

if ! command -v ffuf &>/dev/null; then
    # Da release GitHub
    FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v2.1.0")
    curl -sL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin ffuf 2>>"$LOG" \
        && chmod +x /usr/local/bin/ffuf \
        && ok "ffuf ${FFUF_VER} installato" || {
        # Fallback: go install
        command -v go &>/dev/null && go install github.com/ffuf/ffuf/v2@latest 2>>"$LOG" \
            && ok "ffuf installato via go" || fail "ffuf"
    }
else skip "ffuf"; fi

# Wordlists
if [ ! -d /usr/share/wordlists/dirb ]; then
    apt-get install -y -qq dirb 2>>"$LOG" && ok "wordlists dirb installate" || fail "dirb wordlists"
else skip "wordlists dirb"; fi

if [ ! -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
    apt-get install -y -qq seclists 2>>"$LOG" && ok "SecLists installate" || {
        # Fallback: clone da GitHub
        git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/argos/wordlists/SecLists 2>>"$LOG" \
            && ok "SecLists clonate in /opt/argos/wordlists/SecLists" || fail "SecLists"
    }
else skip "SecLists"; fi

# ── 6. SQL Injection ─────────────────────────────────────────────────────────
log "[6/10] SQLmap..."

if ! command -v sqlmap &>/dev/null; then
    apt-get install -y -qq sqlmap 2>>"$LOG" && ok "sqlmap installato" || {
        pip3 install sqlmap --break-system-packages -q 2>>"$LOG" && ok "sqlmap installato via pip" || fail "sqlmap"
    }
else skip "sqlmap"; fi

# ── 7. Metasploit ────────────────────────────────────────────────────────────
log "[7/10] Metasploit Framework..."

if ! command -v msfconsole &>/dev/null; then
    if [ "$SKIP_HEAVY" != "--skip-heavy" ]; then
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
            > /tmp/msfinstall 2>>"$LOG" \
            && chmod +x /tmp/msfinstall \
            && /tmp/msfinstall 2>>"$LOG" \
            && ok "Metasploit installato" || fail "Metasploit (usa --skip-heavy per saltare)"
    else
        log "  · Metasploit saltato (--skip-heavy)"
    fi
else skip "Metasploit"; fi

# ── 8. AI Security ───────────────────────────────────────────────────────────
log "[8/10] AI Security — Garak..."

if ! command -v garak &>/dev/null && ! python3 -c "import garak" &>/dev/null 2>&1; then
    pip3 install garak --break-system-packages -q 2>>"$LOG" && ok "garak installato" || fail "garak"
else skip "garak"; fi

# ── 9. Nikto ─────────────────────────────────────────────────────────────────
log "[9/10] Web scanner — Nikto, OSV-Scanner..."

if ! command -v nikto &>/dev/null; then
    apt-get install -y -qq nikto 2>>"$LOG" && ok "nikto installato" || fail "nikto"
else skip "nikto"; fi

if ! command -v osv-scanner &>/dev/null; then
    OSV_VER=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v1.7.4")
    curl -sL "https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_linux_amd64" \
        -o /usr/local/bin/osv-scanner 2>>"$LOG" \
        && chmod +x /usr/local/bin/osv-scanner \
        && ok "osv-scanner ${OSV_VER} installato" || fail "osv-scanner"
else skip "osv-scanner"; fi

# ── 10. Impacket ─────────────────────────────────────────────────────────────
log "[10/10] Windows tools — Impacket..."

if ! command -v impacket-secretsdump &>/dev/null; then
    pip3 install impacket --break-system-packages -q 2>>"$LOG" && ok "impacket installato" || fail "impacket"
else skip "impacket"; fi

# ── YARA rules base ──────────────────────────────────────────────────────────
log "Setup YARA rules base..."
if [ ! -f /opt/argos/yara_rules/base_rules.yar ]; then
    cat > /opt/argos/yara_rules/base_rules.yar << 'YARAEOF'
rule SuspiciousStrings {
    meta:
        description = "Strings commonly found in malware"
        author = "ARGOS"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "wget http" nocase
        $s4 = "curl http" nocase
        $s5 = "/bin/sh -i" nocase
        $s6 = "base64 -d" nocase
    condition:
        2 of them
}
rule WebShell {
    meta:
        description = "Common PHP/ASP web shell patterns"
    strings:
        $php1 = "eval(base64_decode" nocase
        $php2 = "system($_" nocase
        $php3 = "exec($_GET" nocase
        $asp1 = "Response.Write(Shell" nocase
    condition:
        any of them
}
YARAEOF
    ok "YARA base rules create"
fi

# ── Riepilogo ─────────────────────────────────────────────────────────────────
log ""
log "=== INSTALLAZIONE COMPLETATA ==="
log "Tool installati:"
for tool in semgrep bandit trivy yara clamscan zeek suricata vol ffuf sqlmap nikto osv-scanner impacket-secretsdump garak msfconsole; do
    if command -v "$tool" &>/dev/null 2>&1 || python3 -c "import ${tool//[-.]/_}" &>/dev/null 2>&1; then
        log "  ✓ $tool"
    else
        log "  ✗ $tool (non trovato)"
    fi
done
log ""
log "Log completo: $LOG"
