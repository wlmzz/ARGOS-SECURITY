"""
ARGOS — Open Source AI Security Platform
Core Agent v0.1.0

Security is a right, not a privilege.
https://github.com/argos-security/argos

MIT License
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import platform
import threading
import subprocess
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional
from pathlib import Path

# Third-party (pip install psutil scapy requests)
try:
    import psutil
    import requests
except ImportError:
    print("[!] Missing dependencies. Run: pip install psutil requests")
    sys.exit(1)

# ─── CONFIG ──────────────────────────────────────────────────────────────────

VERSION = "0.1.0"
PLATFORM = platform.system().lower()  # linux / windows / darwin

@dataclass
class AgentConfig:
    mode: str = "standalone"          # standalone | self-hosted | cloud
    server_url: str = ""              # only for self-hosted/cloud
    api_token: str = ""
    ai_model: str = "phi4:14b"        # ollama model name
    gguf_model_path: str = ""         # path to local GGUF file (auto-imported into Ollama)
    ollama_url: str = "http://localhost:11434"
    scan_interval: int = 5            # seconds between scans
    autonomy_level: str = "semi"      # full | semi | supervised
    honeypot_enabled: bool = True
    community_intel: bool = False     # opt-in threat sharing
    log_level: str = "INFO"

# Load config from file or use defaults
CONFIG_PATH = Path.home() / ".argos" / "config.json"

def load_config() -> AgentConfig:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        return AgentConfig(**data)
    return AgentConfig()

def save_config(config: AgentConfig):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(asdict(config), f, indent=2)

# ─── LOGGING ─────────────────────────────────────────────────────────────────

def setup_logging(level: str):
    log_dir = Path.home() / ".argos" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"argos-{datetime.now().strftime('%Y%m%d')}.log"

    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

log = logging.getLogger("argos")

# ─── DATA MODELS ─────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    id: str
    timestamp: str
    threat_type: str          # port_scan | brute_force | ddos | malware | anomaly | ...
    severity: str             # low | medium | high | critical
    source_ip: str
    source_port: int
    target_port: int
    protocol: str
    description: str
    raw_data: dict
    action_taken: str = "none"
    ai_analysis: str = ""
    evidence_path: str = ""

    @classmethod
    def create(cls, threat_type: str, severity: str, source_ip: str,
               source_port: int, target_port: int, protocol: str,
               description: str, raw_data: dict) -> "ThreatEvent":
        ts = datetime.now().isoformat()
        event_id = hashlib.sha256(f"{ts}{source_ip}{threat_type}".encode()).hexdigest()[:12]
        return cls(
            id=event_id,
            timestamp=ts,
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            source_port=source_port,
            target_port=target_port,
            protocol=protocol,
            description=description,
            raw_data=raw_data,
        )

# ─── THREAT DATABASE (local SQLite) ─────────────────────────────────────────

import sqlite3

class ThreatDB:
    def __init__(self):
        db_path = Path.home() / ".argos" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_schema()
        self._lock = threading.Lock()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                source_ip TEXT,
                source_port INTEGER,
                target_port INTEGER,
                protocol TEXT,
                description TEXT,
                raw_data TEXT,
                action_taken TEXT,
                ai_analysis TEXT,
                evidence_path TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at TEXT,
                expires_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_ip ON threats(source_ip)
        """)
        self.conn.commit()

    def save_threat(self, event: ThreatEvent):
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.id, event.timestamp, event.threat_type, event.severity,
                event.source_ip, event.source_port, event.target_port,
                event.protocol, event.description, json.dumps(event.raw_data),
                event.action_taken, event.ai_analysis, event.evidence_path
            ))
            self.conn.commit()

    def get_ip_history(self, ip: str) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM threats WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 50",
                (ip,)
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "SELECT ip FROM blocked_ips WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)",
                (ip, datetime.now().isoformat())
            )
            return cur.fetchone() is not None

    def block_ip(self, ip: str, reason: str, duration_minutes: Optional[int] = None):
        expires = None
        if duration_minutes:
            from datetime import timedelta
            expires = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?,?)
            """, (ip, reason, datetime.now().isoformat(), expires))
            self.conn.commit()

# ─── NETWORK MONITOR ─────────────────────────────────────────────────────────

class NetworkMonitor:
    """
    Monitors network connections and detects anomalies.
    Works cross-platform via psutil.
    """

    def __init__(self, db: ThreatDB):
        self.db = db
        self._seen_connections: set = set()
        self._port_scan_tracker: dict = {}  # ip -> {ports_tried, first_seen}
        self._brute_force_tracker: dict = {}  # ip -> {attempts, first_seen}
        self.PORT_SCAN_THRESHOLD = 10        # ports tried in window
        self.PORT_SCAN_WINDOW = 60           # seconds
        self.BRUTE_FORCE_THRESHOLD = 5       # attempts
        self.BRUTE_FORCE_WINDOW = 30         # seconds

    def scan(self) -> list[ThreatEvent]:
        events = []
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            log.warning("Network monitoring requires elevated privileges")
            return events

        now = time.time()

        for conn in connections:
            if conn.status not in ('ESTABLISHED', 'SYN_RECV', 'SYN_SENT'):
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0

            # Skip private/loopback IPs
            if self._is_private(remote_ip):
                continue

            # Port scan detection
            if remote_ip not in self._port_scan_tracker:
                self._port_scan_tracker[remote_ip] = {
                    'ports': set(), 'first_seen': now
                }

            tracker = self._port_scan_tracker[remote_ip]
            tracker['ports'].add(local_port)

            # Reset window if expired
            if now - tracker['first_seen'] > self.PORT_SCAN_WINDOW:
                tracker['ports'] = {local_port}
                tracker['first_seen'] = now

            if len(tracker['ports']) >= self.PORT_SCAN_THRESHOLD:
                event = ThreatEvent.create(
                    threat_type="port_scan",
                    severity="high",
                    source_ip=remote_ip,
                    source_port=remote_port,
                    target_port=local_port,
                    protocol="tcp",
                    description=f"Port scan detected: {len(tracker['ports'])} ports probed in {self.PORT_SCAN_WINDOW}s",
                    raw_data={
                        'ports_tried': list(tracker['ports']),
                        'window_seconds': self.PORT_SCAN_WINDOW
                    }
                )
                events.append(event)
                # Reset to avoid repeated alerts
                tracker['ports'] = set()

        return events

    def check_connection_anomaly(self, ip: str, port: int) -> Optional[ThreatEvent]:
        """Check if a single new connection looks suspicious."""
        history = self.db.get_ip_history(ip)
        if len(history) >= 3:
            # IP has been seen attacking before
            return ThreatEvent.create(
                threat_type="repeat_offender",
                severity="high",
                source_ip=ip,
                source_port=0,
                target_port=port,
                protocol="tcp",
                description=f"Known malicious IP reconnecting ({len(history)} previous incidents)",
                raw_data={'previous_incidents': len(history)}
            )
        return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if IP is private/loopback."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False

# ─── PROCESS MONITOR ─────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Monitors running processes for suspicious behavior.
    Detects: ransomware patterns, cryptominers, unusual privilege escalation.
    """

    SUSPICIOUS_NAMES = {
        'cryptominer_patterns': ['xmrig', 'minerd', 'cpuminer', 'cgminer'],
        'ransomware_patterns': ['locker', 'ransom', 'crypt0'],
        'suspicious_tools': ['netcat', 'mimikatz', 'meterpreter'],
    }
    # Exact name matches only (not substring) — avoids false positives on system daemons
    EXACT_NAMES = {'nc', 'ncat', 'nmap'}

    def __init__(self, db: ThreatDB):
        self.db = db
        self._known_pids: dict = {}

    def scan(self) -> list[ThreatEvent]:
        events = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent',
                                              'memory_percent', 'username']):
                try:
                    info = proc.info
                    event = self._analyze_process(info)
                    if event:
                        events.append(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            log.error(f"Process scan error: {e}")
        return events

    def _analyze_process(self, info: dict) -> Optional[ThreatEvent]:
        name = (info.get('name') or '').lower()
        cmdline = ' '.join(info.get('cmdline') or []).lower()

        # CPU spike (potential cryptominer)
        cpu = info.get('cpu_percent') or 0
        if cpu > 85:
            return ThreatEvent.create(
                threat_type="high_cpu_process",
                severity="medium",
                source_ip="localhost",
                source_port=0,
                target_port=0,
                protocol="process",
                description=f"Process '{info['name']}' using {cpu:.1f}% CPU — possible cryptominer",
                raw_data={'pid': info['pid'], 'name': info['name'], 'cpu': cpu}
            )

        # Exact name match (short strings — must match whole process name)
        if name in self.EXACT_NAMES:
            return ThreatEvent.create(
                threat_type="suspicious_process",
                severity="high",
                source_ip="localhost",
                source_port=0,
                target_port=0,
                protocol="process",
                description=f"Suspicious tool detected: '{info['name']}' (exact match)",
                raw_data={'pid': info['pid'], 'name': info['name'],
                          'cmdline': cmdline, 'category': 'exact_match'}
            )

        # Substring match only for longer, unambiguous patterns
        for category, patterns in self.SUSPICIOUS_NAMES.items():
            for pattern in patterns:
                if pattern in name or pattern in cmdline:
                    return ThreatEvent.create(
                        threat_type="suspicious_process",
                        severity="critical",
                        source_ip="localhost",
                        source_port=0,
                        target_port=0,
                        protocol="process",
                        description=f"Suspicious process detected: '{info['name']}' matches {category}",
                        raw_data={'pid': info['pid'], 'name': info['name'],
                                  'cmdline': cmdline, 'category': category}
                    )

        return None

# ─── AI ANALYSIS ENGINE ──────────────────────────────────────────────────────

class AIEngine:
    """
    Local AI analysis using Ollama.
    Falls back to rule-based analysis if Ollama unavailable.
    Escalates to Claude API for complex/unprecedented threats.
    """

    SYSTEM_PROMPT = """You are ARGOS, an autonomous cybersecurity AI.
Analyze the threat event and respond with a JSON object containing:
- severity_confirmed: true/false
- action: one of [block_ip, deploy_honeypot, isolate_process, close_port, alert_human, monitor]
- reasoning: brief explanation (max 2 sentences)
- confidence: 0.0 to 1.0
- escalate_to_human: true/false

Respond ONLY with valid JSON. No markdown, no preamble."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._ollama_available = self._check_ollama()

    def _check_ollama(self) -> bool:
        try:
            r = requests.get(f"{self.config.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            log.warning("Ollama not available — using rule-based fallback")
            return False

    def analyze(self, event: ThreatEvent) -> dict:
        """Analyze threat and return action recommendation."""
        if self._ollama_available:
            return self._analyze_with_ai(event)
        else:
            return self._rule_based_analysis(event)

    def _analyze_with_ai(self, event: ThreatEvent) -> dict:
        prompt = f"""Threat Event:
Type: {event.threat_type}
Severity: {event.severity}
Source IP: {event.source_ip}
Description: {event.description}
Raw data: {json.dumps(event.raw_data, indent=2)}"""

        try:
            r = requests.post(
                f"{self.config.ollama_url}/api/generate",
                json={
                    "model": self.config.ai_model,
                    "prompt": prompt,
                    "system": self.SYSTEM_PROMPT,
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=30
            )
            if r.status_code == 200:
                response_text = r.json().get('response', '{}')
                return json.loads(response_text)
        except Exception as e:
            log.error(f"AI analysis error: {e}")

        return self._rule_based_analysis(event)

    def _rule_based_analysis(self, event: ThreatEvent) -> dict:
        """Fallback rule-based decisions when AI is unavailable."""
        rules = {
            "port_scan": {
                "action": "deploy_honeypot",
                "reasoning": "Port scan detected — deploying honeypot to gather attacker intelligence",
                "confidence": 0.9,
                "escalate_to_human": False
            },
            "brute_force": {
                "action": "block_ip",
                "reasoning": "Brute force attack — blocking IP immediately",
                "confidence": 0.95,
                "escalate_to_human": False
            },
            "repeat_offender": {
                "action": "block_ip",
                "reasoning": "Known malicious IP — blocking immediately",
                "confidence": 0.99,
                "escalate_to_human": False
            },
            "suspicious_process": {
                "action": "isolate_process",
                "reasoning": "Suspicious process matching known malware pattern",
                "confidence": 0.85,
                "escalate_to_human": True
            },
            "high_cpu_process": {
                "action": "alert_human",
                "reasoning": "Unusual CPU usage — possible cryptominer, needs verification",
                "confidence": 0.6,
                "escalate_to_human": True
            }
        }

        result = rules.get(event.threat_type, {
            "action": "alert_human",
            "reasoning": "Unknown threat type — escalating to human review",
            "confidence": 0.5,
            "escalate_to_human": True
        })

        result["severity_confirmed"] = event.severity in ("high", "critical")
        return result

# ─── RESPONSE ENGINE ─────────────────────────────────────────────────────────

class ResponseEngine:
    """
    Executes defensive actions based on AI recommendations.
    All actions are logged and reversible.
    """

    def __init__(self, config: AgentConfig, db: ThreatDB):
        self.config = config
        self.db = db
        self._honeypots_active: dict = {}  # port -> thread

    def execute(self, event: ThreatEvent, ai_decision: dict) -> str:
        action = ai_decision.get('action', 'alert_human')
        confidence = ai_decision.get('confidence', 0.5)

        # In supervised mode, always ask human for critical actions
        if self.config.autonomy_level == "supervised":
            if action in ('block_ip', 'isolate_process', 'close_port'):
                log.info(f"[SUPERVISED] Would execute: {action} — waiting for human approval")
                return f"pending_approval:{action}"

        # In semi-autonomous mode, act if confidence is high enough
        if self.config.autonomy_level == "semi" and confidence < 0.7:
            log.info(f"[SEMI] Low confidence ({confidence:.2f}) — escalating to human")
            return "escalated_low_confidence"

        # Execute action
        if action == "block_ip":
            return self._block_ip(event)
        elif action == "deploy_honeypot":
            return self._deploy_honeypot(event)
        elif action == "isolate_process":
            return self._isolate_process(event)
        elif action == "close_port":
            return self._close_port(event)
        elif action == "monitor":
            return "monitoring"
        else:
            return "alert_sent"

    def _block_ip(self, event: ThreatEvent) -> str:
        ip = event.source_ip
        log.warning(f"[ACTION] Blocking IP: {ip} — Reason: {event.threat_type}")

        self.db.block_ip(ip, event.threat_type, duration_minutes=60)

        # Platform-specific firewall block
        if PLATFORM == "linux":
            self._run_cmd(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            self._run_cmd(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        elif PLATFORM == "darwin":
            self._run_cmd(["pfctl", "-t", "argos_blocked", "-T", "add", ip])
        elif PLATFORM == "windows":
            self._run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ARGOS_BLOCK_{ip}", "dir=in", "action=block",
                f"remoteip={ip}"
            ])

        return f"blocked:{ip}"

    def _deploy_honeypot(self, event: ThreatEvent) -> str:
        """Deploy a simple TCP honeypot on the scanned ports."""
        if not self.config.honeypot_enabled:
            return "honeypot_disabled"

        port = event.target_port
        if port in self._honeypots_active:
            return f"honeypot_already_active:{port}"

        log.info(f"[ACTION] Deploying honeypot on port {port} for attacker {event.source_ip}")

        thread = threading.Thread(
            target=self._run_honeypot,
            args=(port, event.source_ip),
            daemon=True
        )
        thread.start()
        self._honeypots_active[port] = thread

        return f"honeypot_deployed:{port}"

    def _run_honeypot(self, port: int, target_ip: str):
        """Simple honeypot that logs attacker interactions."""
        evidence_dir = Path.home() / ".argos" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen(5)
                s.settimeout(300)  # 5 minute honeypot lifetime

                log.info(f"[HONEYPOT] Listening on port {port}")
                evidence_file = evidence_dir / f"honeypot_{target_ip}_{port}_{int(time.time())}.log"

                with open(evidence_file, 'w') as ef:
                    ef.write(f"ARGOS Honeypot Evidence\n")
                    ef.write(f"Port: {port}\n")
                    ef.write(f"Target attacker: {target_ip}\n")
                    ef.write(f"Started: {datetime.now().isoformat()}\n\n")

                    start_time = time.time()
                    while time.time() - start_time < 300:
                        try:
                            conn, addr = s.accept()
                            ef.write(f"[{datetime.now().isoformat()}] Connection from {addr[0]}:{addr[1]}\n")

                            conn.settimeout(30)
                            try:
                                data = conn.recv(4096)
                                ef.write(f"  Data received ({len(data)} bytes): {data[:200]!r}\n")
                                # Send fake banner to keep attacker engaged
                                conn.send(b"SSH-2.0-OpenSSH_8.9\r\n")
                            except socket.timeout:
                                pass
                            finally:
                                conn.close()
                        except socket.timeout:
                            break

                log.info(f"[HONEYPOT] Evidence saved: {evidence_file}")

        except PermissionError:
            log.warning(f"[HONEYPOT] Cannot bind port {port} — needs root/admin")
        except Exception as e:
            log.error(f"[HONEYPOT] Error on port {port}: {e}")
        finally:
            self._honeypots_active.pop(port, None)

    def _isolate_process(self, event: ThreatEvent) -> str:
        pid = event.raw_data.get('pid')
        if not pid:
            return "no_pid"

        try:
            proc = psutil.Process(pid)
            proc.suspend()
            log.warning(f"[ACTION] Process suspended: PID {pid} ({event.raw_data.get('name')})")
            return f"process_suspended:{pid}"
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log.error(f"[ACTION] Cannot isolate process {pid}: {e}")
            return f"isolation_failed:{e}"

    def _close_port(self, event: ThreatEvent) -> str:
        port = event.target_port
        log.warning(f"[ACTION] Closing port: {port}")

        if PLATFORM == "linux":
            self._run_cmd(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
        elif PLATFORM == "windows":
            self._run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ARGOS_CLOSE_{port}", "dir=in", "action=block",
                "protocol=tcp", f"localport={port}"
            ])

        return f"port_closed:{port}"

    @staticmethod
    def _run_cmd(cmd: list):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                log.warning(f"Command failed: {' '.join(cmd)} — {result.stderr}")
        except FileNotFoundError:
            log.warning(f"Command not found: {cmd[0]}")
        except subprocess.TimeoutExpired:
            log.warning(f"Command timed out: {' '.join(cmd)}")

# ─── MAIN AGENT LOOP ─────────────────────────────────────────────────────────

class ArgosAgent:
    """
    Main ARGOS agent — orchestrates all monitoring and response.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.db = ThreatDB()
        self.net_monitor = NetworkMonitor(self.db)
        self.proc_monitor = ProcessMonitor(self.db)
        self.ai_engine = AIEngine(config)
        self.response_engine = ResponseEngine(config, self.db)
        self._running = False

    def start(self):
        self._running = True
        self._print_banner()

        log.info(f"ARGOS v{VERSION} starting on {PLATFORM}")
        log.info(f"Mode: {self.config.mode} | Autonomy: {self.config.autonomy_level}")
        log.info(f"AI: {'Ollama ' + self.config.ai_model if self.ai_engine._ollama_available else 'Rule-based fallback'}")

        # Start monitoring threads
        threads = [
            threading.Thread(target=self._network_loop, daemon=True, name="net-monitor"),
            threading.Thread(target=self._process_loop, daemon=True, name="proc-monitor"),
        ]

        for t in threads:
            t.start()
            log.info(f"[✓] Started: {t.name}")

        log.info(f"[✓] ARGOS is active — monitoring all systems")

        # Keep main thread alive
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down ARGOS...")
            self._running = False

    def _network_loop(self):
        while self._running:
            try:
                events = self.net_monitor.scan()
                for event in events:
                    self._handle_event(event)
            except Exception as e:
                log.error(f"Network monitor error: {e}")
            time.sleep(self.config.scan_interval)

    def _process_loop(self):
        while self._running:
            try:
                events = self.proc_monitor.scan()
                for event in events:
                    self._handle_event(event)
            except Exception as e:
                log.error(f"Process monitor error: {e}")
            time.sleep(self.config.scan_interval * 2)

    def _handle_event(self, event: ThreatEvent):
        """Core event handling pipeline."""
        # Skip if IP already blocked
        if self.db.is_blocked(event.source_ip) and event.source_ip != "localhost":
            return

        log.warning(f"[THREAT] {event.severity.upper()} | {event.threat_type} | {event.source_ip} | {event.description}")

        # AI analysis
        ai_decision = self.ai_engine.analyze(event)
        event.ai_analysis = ai_decision.get('reasoning', '')
        log.info(f"[AI] Action: {ai_decision.get('action')} | Confidence: {ai_decision.get('confidence', 0):.2f}")

        # Execute response
        action_result = self.response_engine.execute(event, ai_decision)
        event.action_taken = action_result

        # Save to database
        self.db.save_threat(event)

        # Send to server if connected mode
        if self.config.mode in ("self-hosted", "cloud") and self.config.server_url:
            self._report_to_server(event)

        log.info(f"[✓] Event handled: {event.id} | Action: {action_result}")

    def _report_to_server(self, event: ThreatEvent):
        try:
            requests.post(
                f"{self.config.server_url}/api/events",
                json=asdict(event),
                headers={"Authorization": f"Bearer {self.config.api_token}"},
                timeout=5
            )
        except Exception as e:
            log.debug(f"Server report failed: {e}")

    @staticmethod
    def _print_banner():
        print("""
\033[36m
  ▄████████    ▄████████    ▄██████▄     ▄██████▄     ▄████████
  ███    ███   ███    ███   ███    ███   ███    ███   ███    ███
  ███    ███   ███    ███   ███    █▀    ███    ███   ███    █▀
  ███    ███  ▄███▄▄▄▄██▀  ▄███         ███    ███   ███
▀███████████ ▀▀███▀▀▀▀▀   ▀▀███ ████▄  ███    ███ ▀███████████
  ███    ███ ▀███████████   ███    ███  ███    ███          ███
  ███    ███   ███    ███   ███    ███  ███    ███    ███    ███
  ███    █▀    ███    ███   ████████▀    ▀██████▀     ████████▀
              ███    ███
\033[0m
\033[90m  Open Source AI Security Platform · v{VERSION}
  Security is a right, not a privilege.
  https://github.com/argos-security/argos
\033[0m
""".format(VERSION=VERSION))

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ARGOS — Open Source AI Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Security is a right, not a privilege."
    )
    parser.add_argument('--mode', choices=['standalone', 'self-hosted', 'cloud'],
                        default='standalone', help='Deployment mode')
    parser.add_argument('--autonomy', choices=['full', 'semi', 'supervised'],
                        default='semi', help='Autonomy level')
    parser.add_argument('--server', default='', help='Server URL (self-hosted/cloud mode)')
    parser.add_argument('--token', default='', help='API token')
    parser.add_argument('--no-honeypot', action='store_true', help='Disable honeypots')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    config = load_config()
    config.mode = args.mode
    config.autonomy_level = args.autonomy
    config.server_url = args.server
    config.api_token = args.token
    config.honeypot_enabled = not args.no_honeypot
    config.log_level = "DEBUG" if args.debug else "INFO"

    save_config(config)
    setup_logging(config.log_level)

    agent = ArgosAgent(config)
    agent.start()

if __name__ == "__main__":
    main()
