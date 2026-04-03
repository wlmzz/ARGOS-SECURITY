from agent.models import ThreatEvent

MINER_NAMES = {
    "xmrig", "minerd", "cpuminer", "cgminer",
    "ethminer", "phoenixminer", "nbminer",
}

MINING_PORTS = {3333, 4444, 7777, 14444, 45700, 14433, 9999}

CPU_THRESHOLD = 85  # percent


class CryptominerDetector:
    """
    Detects cryptocurrency mining activity by inspecting process metadata
    and outbound connections to known mining pool ports.
    """

    def update(
        self,
        proc_info: dict,
        connections: list | None = None,
    ) -> ThreatEvent | None:
        """
        Analyse a process snapshot.

        Args:
            proc_info: dict with keys pid, name, cmdline, cpu_percent.
            connections: optional list of psutil connection objects for the process.

        Returns a ThreatEvent if mining activity is detected, else None.
        """
        name = (proc_info.get("name") or "").lower()
        cmdline = " ".join(proc_info.get("cmdline") or []).lower()
        cpu = proc_info.get("cpu_percent", 0)

        # ── Name / cmdline match ─────────────────────────────────────────────
        for miner in MINER_NAMES:
            if miner in name or miner in cmdline:
                return ThreatEvent.create(
                    threat_type="cryptominer",
                    severity="high",
                    source_ip="localhost",
                    source_port=0,
                    target_port=0,
                    protocol="process",
                    description=f"Cryptominer process detected: '{proc_info.get('name')}'",
                    raw_data={
                        "pid": proc_info.get("pid"),
                        "name": proc_info.get("name"),
                        "cmdline": cmdline[:200],
                    }
                )

        # ── Mining pool port + high CPU ───────────────────────────────────────
        if connections and cpu > CPU_THRESHOLD:
            for conn in connections:
                if (hasattr(conn, "raddr") and conn.raddr
                        and conn.raddr.port in MINING_PORTS):
                    return ThreatEvent.create(
                        threat_type="cryptominer",
                        severity="high",
                        source_ip="localhost",
                        source_port=0,
                        target_port=conn.raddr.port,
                        protocol="tcp",
                        description=(
                            f"Process '{proc_info.get('name')}' connected to mining "
                            f"pool port {conn.raddr.port} at {cpu:.0f}% CPU"
                        ),
                        raw_data={
                            "pid": proc_info.get("pid"),
                            "port": conn.raddr.port,
                            "cpu": cpu,
                        }
                    )
        return None
