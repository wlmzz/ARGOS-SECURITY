import time

from agent.models import ThreatEvent

EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MB within the detection window
SUSPICIOUS_PORTS = {1194, 1723, 4444, 4445, 8443, 31337}


class ExfiltrationDetector:
    """
    Detects possible data exfiltration by tracking outbound data volume
    to individual remote IPs within a rolling time window.
    """

    def __init__(self):
        self._upload_tracker: dict = {}  # ip -> {bytes: int, first_seen: float}
        self.window = 60  # seconds

    def update(self, remote_ip: str, bytes_sent: int) -> ThreatEvent | None:
        """
        Record bytes sent to `remote_ip`.
        Returns a ThreatEvent if the threshold is exceeded within the window.
        """
        now = time.time()
        if remote_ip not in self._upload_tracker:
            self._upload_tracker[remote_ip] = {"bytes": 0, "first_seen": now}
        t = self._upload_tracker[remote_ip]

        if now - t["first_seen"] > self.window:
            t["bytes"] = bytes_sent
            t["first_seen"] = now
        else:
            t["bytes"] += bytes_sent

        if t["bytes"] >= EXFIL_BYTES_THRESHOLD:
            mb = t["bytes"] / 1024 / 1024
            total_bytes = t["bytes"]
            t["bytes"] = 0  # reset after alert
            return ThreatEvent.create(
                threat_type="exfiltration",
                severity="high",
                source_ip="localhost",
                source_port=0,
                target_port=0,
                protocol="tcp",
                description=(
                    f"Possible exfiltration: {mb:.1f} MB sent to "
                    f"{remote_ip} in {self.window}s"
                ),
                raw_data={
                    "remote_ip": remote_ip,
                    "bytes_sent": total_bytes,
                    "mb": round(mb, 2),
                }
            )
        return None
