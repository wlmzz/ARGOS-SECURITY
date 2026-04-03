import time

from agent.models import ThreatEvent


class BruteForceDetector:
    """Stateful detector for brute force login attempts against a service."""

    def __init__(self, threshold: int = 5, window: int = 30):
        self.threshold = threshold
        self.window = window
        self._tracker: dict = {}  # "{ip}:{service}" -> {count: int, first_seen: float}

    def update(self, ip: str, service: str = "ssh", port: int = 22) -> ThreatEvent | None:
        """
        Record a failed authentication attempt from `ip` against `service`.
        Returns a ThreatEvent when the threshold is reached within the window.
        """
        now = time.time()
        key = f"{ip}:{service}"
        if key not in self._tracker:
            self._tracker[key] = {"count": 0, "first_seen": now}
        t = self._tracker[key]

        if now - t["first_seen"] > self.window:
            t["count"] = 1
            t["first_seen"] = now
        else:
            t["count"] += 1

        if t["count"] >= self.threshold:
            count = t["count"]
            t["count"] = 0  # reset after firing
            return ThreatEvent.create(
                threat_type="brute_force",
                severity="high",
                source_ip=ip,
                source_port=0,
                target_port=port,
                protocol="tcp",
                description=f"Brute force on {service}: {count} attempts in {self.window}s",
                raw_data={"attempts": count, "service": service, "window": self.window}
            )
        return None
