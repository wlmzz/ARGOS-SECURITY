import time
from collections import defaultdict

from agent.models import ThreatEvent


class DDoSDetector:
    """Detects Distributed Denial-of-Service patterns, specifically SYN flood attacks."""

    PACKET_RATE_THRESHOLD = 1000  # connections per minute
    SYN_FLOOD_THRESHOLD = 50      # half-open (SYN_RECV) connections

    def __init__(self):
        self._conn_counter: dict = defaultdict(list)  # port -> [timestamps]

    def update(self, connections: list) -> ThreatEvent | None:
        """
        Analyse the current snapshot of active connections.
        Returns a ThreatEvent if a SYN flood pattern is detected.
        """
        now = time.time()

        # Count SYN_RECV (half-open) connections — signature of a SYN flood
        syn_recv = [c for c in connections if getattr(c, "status", "") == "SYN_RECV"]

        if len(syn_recv) >= self.SYN_FLOOD_THRESHOLD:
            target_ports = list({c.laddr.port for c in syn_recv if c.laddr})
            return ThreatEvent.create(
                threat_type="ddos",
                severity="critical",
                source_ip="multiple",
                source_port=0,
                target_port=target_ports[0] if target_ports else 0,
                protocol="tcp",
                description=f"Possible SYN flood: {len(syn_recv)} half-open connections",
                raw_data={
                    "syn_recv_count": len(syn_recv),
                    "target_ports": target_ports,
                }
            )
        return None
