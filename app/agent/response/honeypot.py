import socket
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("argos.honeypot")

# Realistic service banners keyed by port number.
# These are sent immediately after a client connects to keep the attacker
# engaged long enough to record their payloads.
SERVICE_BANNERS: dict[int, bytes] = {
    21:    b"220 FTP server ready (vsftpd 3.0.5)\r\n",
    22:    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23:    b"\xff\xfd\x01\xff\xfd\x1f\xff\xfd!\xff\xfd\"\xff\xfb\x01",  # Telnet IAC sequence
    25:    b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
    80:    (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.57 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>Apache2 Ubuntu Default Page</title></head>"
        b"<body><h1>Apache2 Ubuntu Default Page</h1></body></html>"
    ),
    110:   b"+OK POP3 server ready\r\n",
    143:   b"* OK IMAP4rev1 server ready\r\n",
    443:   (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>Welcome</title></head><body>Welcome</body></html>"
    ),
    3306:  b"\x0a5.7.44-log\x00\x01\x00\x00\x00\x7e\x26\x35\x31\x40\x7c\x03\x00\xff\xf7\x08\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    5432:  b"\x00\x00\x00\x08\x04\xd2\x16/",   # PostgreSQL startup message
    6379:  b"+PONG\r\n",                         # Redis PING response
    8080:  (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Tomcat/9.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<h1>Tomcat Default Page</h1>"
    ),
    8443:  b"HTTP/1.1 403 Forbidden\r\nServer: nginx/1.24.0\r\n\r\n",
    27017: b"\x4f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00",  # MongoDB
}

HONEYPOT_LIFETIME = 300  # seconds each honeypot listener stays active


class HoneypotEngine:
    """
    Deploys per-port TCP honeypot listeners that log attacker interactions
    and capture payloads as evidence.
    """

    def __init__(self):
        self._active: dict[int, threading.Thread] = {}  # port -> thread
        self._evidence_dir = Path.home() / ".argos" / "evidence"
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    def deploy(self, port: int, attacker_ip: str) -> bool:
        """
        Start a honeypot listener on `port` targeting `attacker_ip`.
        Returns False if a listener is already active on that port.
        """
        if port in self._active:
            log.info(f"[Honeypot] Already active on port {port}")
            return False
        t = threading.Thread(
            target=self._run,
            args=(port, attacker_ip),
            daemon=True,
            name=f"honeypot-{port}",
        )
        t.start()
        self._active[port] = t
        log.info(f"[Honeypot] Deployed on port {port} for {attacker_ip}")
        return True

    def stop(self, port: int):
        """Remove tracking entry for `port` (the daemon thread will exit naturally)."""
        self._active.pop(port, None)

    def list_active(self) -> list[int]:
        """Return a list of ports with active honeypot listeners."""
        return list(self._active.keys())

    def _run(self, port: int, target_ip: str):
        banner = SERVICE_BANNERS.get(port, b"Welcome\r\n")
        evidence_file = (
            self._evidence_dir
            / f"honeypot_{target_ip}_{port}_{int(time.time())}.log"
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(5)
                srv.settimeout(HONEYPOT_LIFETIME)

                with open(evidence_file, "w") as ef:
                    ef.write("ARGOS Honeypot Evidence\n")
                    ef.write(f"Port: {port}\n")
                    ef.write(f"Target attacker: {target_ip}\n")
                    ef.write(f"Started: {datetime.now().isoformat()}\n\n")

                    deadline = time.time() + HONEYPOT_LIFETIME
                    while time.time() < deadline:
                        try:
                            conn, addr = srv.accept()
                            ef.write(
                                f"[{datetime.now().isoformat()}] "
                                f"Connection from {addr[0]}:{addr[1]}\n"
                            )
                            conn.settimeout(30)
                            try:
                                conn.send(banner)
                                data = conn.recv(4096)
                                if data:
                                    ef.write(
                                        f"  Data ({len(data)} bytes): "
                                        f"{data[:300]!r}\n"
                                    )
                                ef.flush()
                            except socket.timeout:
                                pass
                            finally:
                                conn.close()
                        except socket.timeout:
                            break

                log.info(f"[Honeypot] Evidence saved: {evidence_file}")

        except PermissionError:
            log.warning(f"[Honeypot] Cannot bind port {port} — needs root/admin")
        except Exception as e:
            log.error(f"[Honeypot] Error on port {port}: {e}")
        finally:
            self._active.pop(port, None)
