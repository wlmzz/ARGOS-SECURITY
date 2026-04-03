import logging
from typing import Optional

import psutil

from agent.models import ThreatEvent
from agent.db import ThreatDB

log = logging.getLogger("argos.process")

# Ports commonly used by cryptocurrency mining pools
MINING_POOL_PORTS = {3333, 4444, 7777, 14444, 45700, 14433, 9999}

CPU_SPIKE_THRESHOLD = 85  # percent


class ProcessMonitor:
    """
    Monitors running processes for suspicious behavior.
    Detects: ransomware patterns, cryptominers (by name, cmdline, and
    mining pool connections), unusual tools.
    """

    SUSPICIOUS_NAMES = {
        "cryptominer_patterns": ["xmrig", "minerd", "cpuminer", "cgminer", "ethminer",
                                 "phoenixminer", "nbminer"],
        "ransomware_patterns":  ["encrypt", "locker", "ransom", "crypt0"],
        "suspicious_tools":     ["nc", "ncat", "netcat", "mimikatz", "meterpreter"],
    }

    def __init__(self, db: ThreatDB):
        self.db = db
        self._known_pids: dict = {}

    def scan(self) -> list[ThreatEvent]:
        events = []
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cmdline", "cpu_percent",
                 "memory_percent", "username", "connections"]
            ):
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
        name = (info.get("name") or "").lower()
        cmdline = " ".join(info.get("cmdline") or []).lower()
        cpu = info.get("cpu_percent", 0)
        connections = info.get("connections") or []

        # ── Suspicious name / cmdline match ──────────────────────────────────
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
                        description=(
                            f"Suspicious process detected: '{info['name']}' "
                            f"matches {category}"
                        ),
                        raw_data={
                            "pid": info["pid"],
                            "name": info["name"],
                            "cmdline": cmdline[:300],
                            "category": category,
                        }
                    )

        # ── Mining pool connection + high CPU ─────────────────────────────────
        # Improved over original: checks actual outbound ports against known
        # mining pool ports and correlates with CPU usage.
        if cpu > CPU_SPIKE_THRESHOLD and connections:
            for conn in connections:
                if (hasattr(conn, "raddr") and conn.raddr
                        and conn.raddr.port in MINING_POOL_PORTS):
                    return ThreatEvent.create(
                        threat_type="cryptominer",
                        severity="high",
                        source_ip="localhost",
                        source_port=0,
                        target_port=conn.raddr.port,
                        protocol="tcp",
                        description=(
                            f"Process '{info['name']}' connected to mining pool port "
                            f"{conn.raddr.port} at {cpu:.0f}% CPU"
                        ),
                        raw_data={
                            "pid": info["pid"],
                            "name": info["name"],
                            "cmdline": cmdline[:300],
                            "cpu_percent": cpu,
                            "mining_port": conn.raddr.port,
                        }
                    )

        # ── CPU spike (generic — possible cryptominer, needs verification) ────
        if cpu > CPU_SPIKE_THRESHOLD:
            return ThreatEvent.create(
                threat_type="high_cpu_process",
                severity="medium",
                source_ip="localhost",
                source_port=0,
                target_port=0,
                protocol="process",
                description=(
                    f"Process '{info['name']}' using {cpu:.1f}% CPU — possible cryptominer"
                ),
                raw_data={
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu": cpu,
                }
            )

        return None
