import hashlib
import platform
import logging
from pathlib import Path

from agent.models import ThreatEvent
from agent.db import ThreatDB

PLATFORM = platform.system().lower()
log = logging.getLogger("argos.filesystem")

WATCH_PATHS = {
    "linux":   ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/usr/bin", "/usr/sbin"],
    "darwin":  ["/etc/passwd", "/Library/LaunchDaemons", "/Library/LaunchAgents"],
    "windows": [],  # watchdog on Windows requires special path handling
}


class FilesystemMonitor:
    """Monitors critical system files for unauthorized modifications (File Integrity Monitoring)."""

    def __init__(self, db: ThreatDB):
        self.db = db
        self._baseline: dict[str, str] = {}  # path -> sha256 hex digest
        self._built = False

    def build_baseline(self):
        """Compute SHA-256 baseline hashes for all watched paths."""
        paths = WATCH_PATHS.get(PLATFORM, [])
        for path_str in paths:
            p = Path(path_str)
            if p.is_file():
                try:
                    self._baseline[str(p)] = self._hash_file(p)
                except (PermissionError, OSError):
                    pass
            elif p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        try:
                            self._baseline[str(f)] = self._hash_file(f)
                        except (PermissionError, OSError):
                            pass
        self._built = True
        log.info(f"[FIM] Baseline built: {len(self._baseline)} files")

    def scan(self) -> list[ThreatEvent]:
        """Compare current file state against baseline and return events for any changes."""
        if not self._built:
            self.build_baseline()
            return []  # First run only builds the baseline; no alerts yet

        events = []
        for path_str, old_hash in list(self._baseline.items()):
            p = Path(path_str)
            if not p.exists():
                events.append(ThreatEvent.create(
                    threat_type="file_deleted",
                    severity="high",
                    source_ip="localhost",
                    source_port=0,
                    target_port=0,
                    protocol="filesystem",
                    description=f"Critical file deleted: {path_str}",
                    raw_data={"path": path_str, "previous_hash": old_hash}
                ))
                del self._baseline[path_str]
            else:
                try:
                    new_hash = self._hash_file(p)
                    if new_hash != old_hash:
                        events.append(ThreatEvent.create(
                            threat_type="file_modified",
                            severity="high",
                            source_ip="localhost",
                            source_port=0,
                            target_port=0,
                            protocol="filesystem",
                            description=f"Critical file modified: {path_str}",
                            raw_data={
                                "path": path_str,
                                "old_hash": old_hash,
                                "new_hash": new_hash,
                            }
                        ))
                        self._baseline[path_str] = new_hash
                except (PermissionError, OSError):
                    pass
        return events

    @staticmethod
    def _hash_file(path: Path) -> str:
        """Compute SHA-256 digest of a file in 64 KB chunks."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
