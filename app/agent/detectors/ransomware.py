import time
from pathlib import Path

from agent.models import ThreatEvent

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".crypted", ".locky", ".cerber", ".zepto", ".odin",
}

MASS_MODIFY_THRESHOLD = 20  # files modified within the detection window


class RansomwareDetector:
    """
    Detects ransomware activity by monitoring file change patterns:
    - files with known ransomware extensions
    - mass file modification bursts
    """

    def __init__(self):
        self._recent_changes: list = []  # list of (timestamp: float, path: str)
        self.window = 60  # seconds

    def report_file_change(self, path: str) -> ThreatEvent | None:
        """
        Call this whenever a file is created or modified.
        Returns a ThreatEvent if ransomware behaviour is suspected.
        """
        now = time.time()
        self._recent_changes.append((now, path))

        # Prune entries outside the detection window
        self._recent_changes = [
            (t, p) for t, p in self._recent_changes if now - t < self.window
        ]

        ext = Path(path).suffix.lower()
        is_suspicious_ext = ext in RANSOMWARE_EXTENSIONS
        is_mass = len(self._recent_changes) >= MASS_MODIFY_THRESHOLD

        if is_suspicious_ext or is_mass:
            if is_suspicious_ext:
                reason = f"suspicious extension '{ext}'"
            else:
                reason = (
                    f"mass file modification "
                    f"({len(self._recent_changes)} files in {self.window}s)"
                )
            return ThreatEvent.create(
                threat_type="ransomware",
                severity="critical",
                source_ip="localhost",
                source_port=0,
                target_port=0,
                protocol="filesystem",
                description=f"Possible ransomware: {reason}",
                raw_data={
                    "path": path,
                    "extension": ext,
                    "recent_changes": len(self._recent_changes),
                }
            )
        return None
