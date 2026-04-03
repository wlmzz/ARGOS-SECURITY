import platform
import subprocess
import logging

PLATFORM = platform.system().lower()
log = logging.getLogger("argos.firewall")


class CrossPlatformFirewall:
    """Cross-platform firewall management for ARGOS."""

    def block_ip(self, ip: str) -> bool:
        """Block all inbound and outbound traffic for `ip`."""
        log.warning(f"[Firewall] Blocking IP: {ip}")
        if PLATFORM == "linux":
            return (
                self._run(["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"])
                and self._run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
            )
        elif PLATFORM == "darwin":
            return self._run(["pfctl", "-t", "argos_blocked", "-T", "add", ip])
        elif PLATFORM == "windows":
            return self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ARGOS_BLOCK_{ip}", "dir=in", "action=block",
                f"remoteip={ip}",
            ])
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove a previously added block rule for `ip`."""
        log.info(f"[Firewall] Unblocking IP: {ip}")
        if PLATFORM == "linux":
            return (
                self._run(["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"])
                and self._run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
            )
        elif PLATFORM == "darwin":
            return self._run(["pfctl", "-t", "argos_blocked", "-T", "delete", ip])
        elif PLATFORM == "windows":
            return self._run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=ARGOS_BLOCK_{ip}",
            ])
        return False

    def block_port(self, port: int, proto: str = "tcp") -> bool:
        """Drop all inbound traffic on `port`/`proto`."""
        log.warning(f"[Firewall] Blocking port: {port}/{proto}")
        if PLATFORM == "linux":
            return self._run([
                "iptables", "-A", "INPUT", "-p", proto,
                "--dport", str(port), "-j", "DROP",
            ])
        elif PLATFORM == "windows":
            return self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ARGOS_CLOSE_{port}", "dir=in", "action=block",
                f"protocol={proto}", f"localport={port}",
            ])
        return False

    def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        """Remove a previously added port block rule."""
        log.info(f"[Firewall] Unblocking port: {port}/{proto}")
        if PLATFORM == "linux":
            return self._run([
                "iptables", "-D", "INPUT", "-p", proto,
                "--dport", str(port), "-j", "DROP",
            ])
        elif PLATFORM == "windows":
            return self._run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=ARGOS_CLOSE_{port}",
            ])
        return False

    @staticmethod
    def _run(cmd: list) -> bool:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                log.warning(
                    f"Firewall command failed: {' '.join(cmd)} "
                    f"— {result.stderr.strip()}"
                )
                return False
            return True
        except FileNotFoundError:
            log.warning(f"Firewall command not found: {cmd[0]}")
            return False
        except subprocess.TimeoutExpired:
            log.warning(f"Firewall command timed out: {' '.join(cmd)}")
            return False
