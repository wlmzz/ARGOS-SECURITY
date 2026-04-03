import platform
import time
import logging

import psutil

from agent.models import ThreatEvent
from agent.db import ThreatDB

PLATFORM = platform.system().lower()
log = logging.getLogger("argos.network")


class NetworkMonitor:
    """
    Monitors network connections and detects anomalies.
    Works cross-platform via psutil.
    Detects: port scans, brute force connection patterns, repeat offenders.
    """

    PORT_SCAN_THRESHOLD = 10   # unique ports probed within window
    PORT_SCAN_WINDOW = 60      # seconds
    BRUTE_FORCE_THRESHOLD = 5  # repeated connection attempts
    BRUTE_FORCE_WINDOW = 30    # seconds

    def __init__(self, db: ThreatDB):
        self.db = db
        self._seen_connections: set = set()
        self._port_scan_tracker: dict = {}   # ip -> {ports: set, first_seen: float}
        self._brute_force_tracker: dict = {} # ip -> {count: int, first_seen: float}

    def scan(self) -> list[ThreatEvent]:
        events = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.warning("Network monitoring requires elevated privileges")
            return events

        now = time.time()

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "SYN_RECV", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0

            # Skip private/loopback IPs
            if self._is_private(remote_ip):
                continue

            # ── Port scan detection ──────────────────────────────────────────
            if remote_ip not in self._port_scan_tracker:
                self._port_scan_tracker[remote_ip] = {
                    "ports": set(), "first_seen": now
                }

            ps_tracker = self._port_scan_tracker[remote_ip]

            # Reset window if expired
            if now - ps_tracker["first_seen"] > self.PORT_SCAN_WINDOW:
                ps_tracker["ports"] = set()
                ps_tracker["first_seen"] = now

            ps_tracker["ports"].add(local_port)

            if len(ps_tracker["ports"]) >= self.PORT_SCAN_THRESHOLD:
                n = len(ps_tracker["ports"])
                ps_tracker["ports"] = set()  # reset to avoid repeated alerts
                events.append(ThreatEvent.create(
                    threat_type="port_scan",
                    severity="high",
                    source_ip=remote_ip,
                    source_port=remote_port,
                    target_port=local_port,
                    protocol="tcp",
                    description=f"Port scan detected: {n} unique ports probed in {self.PORT_SCAN_WINDOW}s",
                    raw_data={
                        "ports_tried": list(ps_tracker["ports"]),
                        "window_seconds": self.PORT_SCAN_WINDOW,
                    }
                ))

            # ── Brute force connection detection ─────────────────────────────
            # Detects rapid repeated connections from the same IP, which the
            # original monolith tracked but never turned into ThreatEvents.
            if remote_ip not in self._brute_force_tracker:
                self._brute_force_tracker[remote_ip] = {"count": 0, "first_seen": now}

            bf_tracker = self._brute_force_tracker[remote_ip]

            if now - bf_tracker["first_seen"] > self.BRUTE_FORCE_WINDOW:
                bf_tracker["count"] = 1
                bf_tracker["first_seen"] = now
            else:
                bf_tracker["count"] += 1

            if bf_tracker["count"] >= self.BRUTE_FORCE_THRESHOLD:
                count = bf_tracker["count"]
                bf_tracker["count"] = 0  # reset
                events.append(ThreatEvent.create(
                    threat_type="brute_force",
                    severity="high",
                    source_ip=remote_ip,
                    source_port=remote_port,
                    target_port=local_port,
                    protocol="tcp",
                    description=(
                        f"Brute force detected: {count} connections from {remote_ip} "
                        f"in {self.BRUTE_FORCE_WINDOW}s"
                    ),
                    raw_data={
                        "attempts": count,
                        "window_seconds": self.BRUTE_FORCE_WINDOW,
                        "target_port": local_port,
                    }
                ))

        return events

    def check_connection_anomaly(self, ip: str, port: int) -> ThreatEvent | None:
        """Check if a single new connection looks suspicious based on IP history."""
        history = self.db.get_ip_history(ip)
        if len(history) >= 3:
            return ThreatEvent.create(
                threat_type="repeat_offender",
                severity="high",
                source_ip=ip,
                source_port=0,
                target_port=port,
                protocol="tcp",
                description=f"Known malicious IP reconnecting ({len(history)} previous incidents)",
                raw_data={"previous_incidents": len(history)}
            )
        return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Return True if the IP is private, loopback, or link-local."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False
