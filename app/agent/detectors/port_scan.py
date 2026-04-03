import time

from agent.models import ThreatEvent


class PortScanDetector:
    """Stateful detector for port scan activity from a single source IP."""

    def __init__(self, threshold: int = 10, window: int = 60):
        self.threshold = threshold
        self.window = window
        self._tracker: dict = {}  # ip -> {ports: set, first_seen: float}

    def update(self, ip: str, port: int) -> ThreatEvent | None:
        """
        Record a connection attempt from `ip` to `port`.
        Returns a ThreatEvent if the scan threshold is reached, else None.
        """
        now = time.time()
        if ip not in self._tracker:
            self._tracker[ip] = {"ports": set(), "first_seen": now}
        t = self._tracker[ip]

        # Reset window if expired
        if now - t["first_seen"] > self.window:
            t["ports"] = set()
            t["first_seen"] = now

        t["ports"].add(port)

        if len(t["ports"]) >= self.threshold:
            n = len(t["ports"])
            ports_snapshot = list(t["ports"])
            t["ports"] = set()  # reset to avoid repeated alerts
            return ThreatEvent.create(
                threat_type="port_scan",
                severity="high",
                source_ip=ip,
                source_port=0,
                target_port=port,
                protocol="tcp",
                description=f"Port scan: {n} unique ports probed in {self.window}s",
                raw_data={"ports_tried": ports_snapshot, "window_seconds": self.window}
            )
        return None
