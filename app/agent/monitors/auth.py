import platform
import subprocess
import re
import time
from pathlib import Path

from agent.models import ThreatEvent

PLATFORM = platform.system().lower()


class AuthMonitor:
    """Parses system authentication logs to detect brute force attacks."""

    THRESHOLD = 5   # failed attempts within window to trigger an alert
    WINDOW = 30     # seconds

    def __init__(self):
        self._attempt_tracker: dict = {}  # ip -> {count: int, first_seen: float}

    def scan(self) -> list[ThreatEvent]:
        if PLATFORM == "linux":
            return self._parse_linux_auth()
        elif PLATFORM == "darwin":
            return self._parse_macos_auth()
        # Windows: requires win32evtlog — not yet implemented
        return []

    def _parse_linux_auth(self) -> list[ThreatEvent]:
        """Parse /var/log/auth.log (or /var/log/secure on RHEL/CentOS) for failed SSH attempts."""
        events = []
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            auth_log = Path("/var/log/secure")  # RHEL/CentOS
        if not auth_log.exists():
            return events

        # Matches: "Failed password for [user] from [ip]"
        PATTERN = re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)")

        try:
            # Read only the last 1000 lines for performance
            result = subprocess.run(
                ["tail", "-n", "1000", str(auth_log)],
                capture_output=True, text=True, timeout=5
            )
            now = time.time()
            for line in result.stdout.splitlines():
                m = PATTERN.search(line)
                if m:
                    ip = m.group(1)
                    if ip not in self._attempt_tracker:
                        self._attempt_tracker[ip] = {"count": 0, "first_seen": now}
                    tracker = self._attempt_tracker[ip]

                    if now - tracker["first_seen"] > self.WINDOW:
                        tracker["count"] = 1
                        tracker["first_seen"] = now
                    else:
                        tracker["count"] += 1

                    if tracker["count"] >= self.THRESHOLD:
                        events.append(ThreatEvent.create(
                            threat_type="brute_force",
                            severity="high",
                            source_ip=ip,
                            source_port=0,
                            target_port=22,
                            protocol="tcp",
                            description=(
                                f"SSH brute force: {tracker['count']} failed attempts "
                                f"in {self.WINDOW}s"
                            ),
                            raw_data={
                                "attempts": tracker["count"],
                                "window": self.WINDOW,
                                "service": "ssh",
                            }
                        ))
                        tracker["count"] = 0  # reset counter after alert
        except Exception:
            pass
        return events

    def _parse_macos_auth(self) -> list[ThreatEvent]:
        """Use the macOS `log` command to detect authentication failures."""
        events = []
        try:
            result = subprocess.run(
                [
                    "log", "show", "--last", "5m",
                    "--predicate", "eventMessage contains 'authentication failed'",
                    "--style", "compact",
                ],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()
            if len(lines) > self.THRESHOLD:
                events.append(ThreatEvent.create(
                    threat_type="brute_force",
                    severity="medium",
                    source_ip="unknown",
                    source_port=0,
                    target_port=0,
                    protocol="system",
                    description=(
                        f"Multiple authentication failures detected "
                        f"({len(lines)} in 5 min)"
                    ),
                    raw_data={"failures": len(lines), "source": "macos_log"}
                ))
        except Exception:
            pass
        return events
