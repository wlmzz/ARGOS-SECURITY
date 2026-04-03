import hashlib
from dataclasses import dataclass, field
from datetime import datetime


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
    ai_confidence: float = 0.0

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
