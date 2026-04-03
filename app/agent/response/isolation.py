import platform
import subprocess
import logging

PLATFORM = platform.system().lower()
log = logging.getLogger("argos.isolation")


class NetworkIsolation:
    """Full network isolation for a compromised device."""

    def __init__(self):
        self._isolated = False
        self._saved_rules: list = []

    def isolate(self, allow_local: bool = True) -> bool:
        """
        Block all network traffic except optionally LAN/localhost.
        Returns True if isolation was applied successfully.
        """
        log.critical("[Isolation] ISOLATING DEVICE FROM NETWORK")
        if PLATFORM == "linux":
            return self._isolate_linux(allow_local)
        elif PLATFORM == "darwin":
            return self._isolate_macos(allow_local)
        elif PLATFORM == "windows":
            return self._isolate_windows()
        return False

    def restore(self) -> bool:
        """
        Restore normal network connectivity.
        Returns True if rules were successfully removed.
        """
        log.info("[Isolation] Restoring network connectivity")
        if PLATFORM == "linux":
            return self._restore_linux()
        elif PLATFORM == "darwin":
            return self._restore_macos()
        elif PLATFORM == "windows":
            return self._restore_windows()
        return False

    # ── Linux ────────────────────────────────────────────────────────────────

    def _isolate_linux(self, allow_local: bool) -> bool:
        cmds = [
            ["iptables", "-P", "INPUT",   "DROP"],
            ["iptables", "-P", "OUTPUT",  "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
            # Always allow loopback
            ["iptables", "-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ]
        if allow_local:
            cmds += [
                ["iptables", "-A", "INPUT", "-s", "192.168.0.0/16", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-s", "10.0.0.0/8",     "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT",
                 "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ]
        success = all(
            subprocess.run(cmd, capture_output=True).returncode == 0
            for cmd in cmds
        )
        self._isolated = success
        return success

    def _restore_linux(self) -> bool:
        cmds = [
            ["iptables", "-P", "INPUT",   "ACCEPT"],
            ["iptables", "-P", "OUTPUT",  "ACCEPT"],
            ["iptables", "-P", "FORWARD", "ACCEPT"],
            ["iptables", "-F"],
        ]
        success = all(
            subprocess.run(cmd, capture_output=True).returncode == 0
            for cmd in cmds
        )
        if success:
            self._isolated = False
        return success

    # ── macOS ────────────────────────────────────────────────────────────────

    def _isolate_macos(self, allow_local: bool) -> bool:
        # Full pf-based isolation requires writing a custom anchor file and
        # reloading pf, which is highly system-specific.  Flag as not supported
        # rather than silently failing.
        log.warning("[Isolation] macOS isolation requires manual pf configuration")
        return False

    def _restore_macos(self) -> bool:
        return False

    # ── Windows ──────────────────────────────────────────────────────────────

    def _isolate_windows(self) -> bool:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,blockoutbound",
            ],
            capture_output=True,
        )
        self._isolated = result.returncode == 0
        return self._isolated

    def _restore_windows(self) -> bool:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,allowoutbound",
            ],
            capture_output=True,
        )
        if result.returncode == 0:
            self._isolated = False
            return True
        return False
