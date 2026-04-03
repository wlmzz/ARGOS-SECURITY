"""
ARGOS Plugin: IoT Honeypot
Honeypot telnet/SSH per catturare malware IoT, botnet e credential stuffing.
Ispirato a telnet-iot-honeypot (Phype) — riscritto completamente Python 3
con analisi automatica dei payload catturati e integrazione ARGOS.

Emula dispositivi IoT vulnerabili (router, cam, DVR) per attirare attaccanti
e raccogliere intelligence su botnet attive.
"""
from __future__ import annotations
import asyncio, json, os, re, hashlib, time, logging, socket, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST = {
    "id":          "iot-honeypot",
    "name":        "IoT Honeypot",
    "description": (
        "Honeypot telnet/SSH emula dispositivi IoT vulnerabili (router, cam, DVR) "
        "per catturare credential stuffing, download malware e comandi botnet. "
        "Analisi automatica payload, classificazione botnet, integrazione watcher."
    ),
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_HONEYPOT_DIR   = Path("/opt/argos/honeypot")
_CAPTURES_FILE  = Path("/opt/argos/honeypot/captures.jsonl")
_PAYLOADS_DIR   = Path("/opt/argos/honeypot/payloads")
_LOG_FILE       = Path("/opt/argos/logs/honeypot.log")

log = logging.getLogger("argos.iot_honeypot")

# Credenziali che gli attaccanti tipicamente provano
_FAKE_BANNER = "BusyBox v1.25.1 (2018-06-11) built-in shell (ash)\n\n"
_LOGIN_PROMPT = "\nBusyBox login: "
_PASS_PROMPT  = "Password: "
_SHELL_PROMPT = "# "

# Comandi attaccanti cercano di eseguire
_KNOWN_COMMANDS = {
    "wget":     "download",
    "curl":     "download",
    "tftp":     "download",
    "busybox":  "shell",
    "chmod":    "exec_prep",
    "sh":       "shell",
    "cat /proc/cpuinfo": "recon",
    "uname":    "recon",
    "id":       "recon",
    "ps":       "recon",
    "kill":     "kill_proc",
    "rm -rf":   "destructive",
    "/bin/":    "shell",
    "echo":     "canary",
}

_KNOWN_BOTNETS = {
    "mirai":    ["wget", "tftp", "busybox", "enable", "system", "sh"],
    "qbot":     ["curl", "chmod +x", "/tmp/", ">/dev/null"],
    "gafgyt":   ["busybox", "PING", "HOLD", "UDP", "TCP"],
    "mozi":     ["wget", "nohup", "chmod 777", ">/dev/null"],
    "hajime":   ["atk", "dl", "sn", "debug"],
}

# Stato globale dei server honeypot attivi
_active_servers: dict[str, Any] = {}
_captures_lock = threading.Lock()


def _save_capture(capture: dict) -> None:
    _CAPTURES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _captures_lock:
        with open(_CAPTURES_FILE, "a") as f:
            f.write(json.dumps(capture) + "\n")


def _classify_botnet(commands: list[str]) -> str:
    """Identifica la famiglia botnet dai comandi usati."""
    cmd_text = " ".join(commands).lower()
    scores: dict[str, int] = {}
    for botnet, indicators in _KNOWN_BOTNETS.items():
        score = sum(1 for ind in indicators if ind.lower() in cmd_text)
        if score > 0:
            scores[botnet] = score
    if scores:
        return max(scores, key=scores.__getitem__)
    return "unknown"


def _extract_urls(text: str) -> list[str]:
    """Estrae URL da comandi (target download malware)."""
    return re.findall(r"https?://\S+|ftp://\S+", text)


def _hash_payload(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _TelnetHoneypot:
    """Server telnet che emula un dispositivo IoT vulnerabile."""

    def __init__(self, port: int = 2323, max_connections: int = 50):
        self.port            = port
        self.max_connections = max_connections
        self._server         = None
        self._running        = False

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip   = peer[0] if peer else "unknown"
        session: dict = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "source_ip":   ip,
            "source_port": peer[1] if peer else 0,
            "type":        "telnet",
            "credentials": [],
            "commands":    [],
            "urls":        [],
            "botnet":      "unknown",
            "raw_session": "",
        }
        raw_buf = []

        try:
            # Invia banner IoT falso
            writer.write(_FAKE_BANNER.encode())
            writer.write(_LOGIN_PROMPT.encode())
            await writer.drain()

            # Fase login
            for attempt in range(5):
                try:
                    username = (await asyncio.wait_for(reader.read(64), timeout=10)).decode(errors="replace").strip()
                    raw_buf.append(f"LOGIN: {username}")
                    writer.write(_PASS_PROMPT.encode())
                    await writer.drain()
                    password = (await asyncio.wait_for(reader.read(64), timeout=10)).decode(errors="replace").strip()
                    raw_buf.append(f"PASS: {password}")

                    session["credentials"].append({"username": username, "password": password})

                    # Simula autenticazione fallita le prime volte, poi accetta
                    if attempt >= 1:
                        writer.write(b"\n" + _SHELL_PROMPT.encode())
                        await writer.drain()
                        break
                    else:
                        writer.write(b"\nLogin incorrect\n" + _LOGIN_PROMPT.encode())
                        await writer.drain()
                except asyncio.TimeoutError:
                    break

            # Fase comandi — cattura tutto quello che l'attaccante invia
            deadline = time.time() + 120  # max 2 minuti per sessione
            while time.time() < deadline:
                try:
                    line = (await asyncio.wait_for(reader.readline(), timeout=15)).decode(errors="replace").strip()
                    if not line:
                        continue
                    raw_buf.append(f"CMD: {line}")
                    session["commands"].append(line)

                    # Estrai URL da comandi download
                    urls = _extract_urls(line)
                    session["urls"].extend(urls)

                    # Risposta realistica
                    if line.startswith("uname"):
                        writer.write(b"Linux " + socket.gethostname().encode()[:20] + b" 3.10.14 #1 SMP\n" + _SHELL_PROMPT.encode())
                    elif line.startswith("cat /proc/cpuinfo"):
                        writer.write(b"processor : 0\nmodel name : ARMv7\n" + _SHELL_PROMPT.encode())
                    elif line.startswith("id"):
                        writer.write(b"uid=0(root) gid=0(root)\n" + _SHELL_PROMPT.encode())
                    elif line.startswith("ps"):
                        writer.write(b"  PID USER  COMMAND\n    1 root  /sbin/init\n" + _SHELL_PROMPT.encode())
                    else:
                        writer.write(_SHELL_PROMPT.encode())
                    await writer.drain()
                except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                    break

        except Exception as e:
            log.debug("Honeypot session error from %s: %s", ip, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            session["raw_session"] = "\n".join(raw_buf)
            session["botnet"]      = _classify_botnet(session["commands"])
            session["url_count"]   = len(session["urls"])
            _save_capture(session)
            log.info(
                "HONEYPOT CAPTURE %s | creds:%d | cmds:%d | botnet:%s | urls:%s",
                ip, len(session["credentials"]), len(session["commands"]),
                session["botnet"], session["urls"][:2]
            )

    async def _serve(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.port,
            limit=4096)
        self._running = True
        async with self._server:
            await self._server.serve_forever()

    def start_background(self) -> None:
        loop = asyncio.new_event_loop()
        t = threading.Thread(
            target=lambda: loop.run_until_complete(self._serve()),
            daemon=True, name=f"honeypot-{self.port}")
        t.start()


# ── Tools pubblici ───────────────────────────────────────────────────────────

def honeypot_start(port: int = 2323) -> dict:
    """
    Avvia il honeypot IoT sulla porta specificata (default 2323).
    Emula un dispositivo BusyBox/router vulnerabile che cattura
    credenziali, comandi e URL di download malware.
    """
    global _active_servers
    if port in _active_servers:
        return {"status": "already_running", "port": port}

    try:
        hp = _TelnetHoneypot(port=port)
        hp.start_background()
        _active_servers[port] = {"port": port, "started": datetime.now(timezone.utc).isoformat()}
        _HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)
        _PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)

        return {
            "status":  "started",
            "port":    port,
            "emulates": "BusyBox IoT device (router/cam/DVR)",
            "captures_file": str(_CAPTURES_FILE),
            "note":    f"Apri porta {port} su UFW: ufw allow {port}/tcp",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def honeypot_stop(port: int = 2323) -> dict:
    """Ferma il honeypot sulla porta specificata."""
    if port not in _active_servers:
        return {"status": "not_running", "port": port}
    _active_servers.pop(port, None)
    return {"status": "stopped", "port": port, "note": "Il thread daemon si chiuderà al prossimo restart ARGOS"}


def honeypot_status() -> dict:
    """Stato dei honeypot attivi e statistiche catture."""
    captures = []
    if _CAPTURES_FILE.exists():
        for line in _CAPTURES_FILE.read_text(errors="replace").splitlines()[-1000:]:
            try:
                captures.append(json.loads(line))
            except Exception:
                pass

    ip_counts: dict[str, int] = {}
    botnets: dict[str, int]   = {}
    urls: list[str]            = []
    cred_pairs: list[tuple]    = []

    for c in captures:
        ip = c.get("source_ip", "?")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        b = c.get("botnet", "unknown")
        if b != "unknown":
            botnets[b] = botnets.get(b, 0) + 1
        urls.extend(c.get("urls", []))
        for cred in c.get("credentials", []):
            cred_pairs.append((cred.get("username", ""), cred.get("password", "")))

    top_creds: dict[str, int] = {}
    for u, p in cred_pairs:
        k = f"{u}:{p}"
        top_creds[k] = top_creds.get(k, 0) + 1

    return {
        "active_honeypots":    list(_active_servers.values()),
        "total_sessions":      len(captures),
        "unique_attackers":    len(ip_counts),
        "top_attackers":       dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        "botnets_detected":    botnets,
        "malware_urls":        list(set(urls))[:20],
        "top_credentials":     dict(sorted(top_creds.items(), key=lambda x: x[1], reverse=True)[:15]),
        "captures_file":       str(_CAPTURES_FILE),
    }


def honeypot_get_captures(hours: int = 24, limit: int = 50) -> dict:
    """
    Restituisce le sessioni catturate nelle ultime N ore.
    Ogni sessione include IP, credenziali provate, comandi eseguiti,
    URL di download malware e famiglia botnet identificata.
    """
    if not _CAPTURES_FILE.exists():
        return {"captures": [], "message": "Nessuna cattura ancora. Avvia con honeypot_start()."}

    cutoff = time.time() - hours * 3600
    captures = []
    for line in _CAPTURES_FILE.read_text(errors="replace").splitlines():
        try:
            c = json.loads(line)
            ts = datetime.fromisoformat(c.get("timestamp", "")).timestamp()
            if ts >= cutoff:
                captures.append(c)
        except Exception:
            pass

    captures = captures[-limit:]
    return {
        "period_hours": hours,
        "count":        len(captures),
        "captures":     captures,
    }


def honeypot_analyze_session(source_ip: str) -> dict:
    """
    Analisi dettagliata di tutte le sessioni da un IP specifico.
    Mostra pattern di attacco, credenziali tentate, comandi e botnet.
    """
    if not _CAPTURES_FILE.exists():
        return {"error": "Nessuna cattura disponibile"}

    sessions = []
    for line in _CAPTURES_FILE.read_text(errors="replace").splitlines():
        try:
            c = json.loads(line)
            if c.get("source_ip") == source_ip:
                sessions.append(c)
        except Exception:
            pass

    if not sessions:
        return {"source_ip": source_ip, "message": "Nessuna sessione trovata per questo IP"}

    all_creds = [f"{c['username']}:{c['password']}" for s in sessions for c in s.get("credentials", [])]
    all_cmds  = [cmd for s in sessions for cmd in s.get("commands", [])]
    all_urls  = [url for s in sessions for url in s.get("urls", [])]
    botnets   = list({s.get("botnet", "unknown") for s in sessions} - {"unknown"})

    return {
        "source_ip":        source_ip,
        "total_sessions":   len(sessions),
        "first_seen":       sessions[0].get("timestamp"),
        "last_seen":        sessions[-1].get("timestamp"),
        "credentials_tried": list(set(all_creds)),
        "commands_used":    list(set(all_cmds)),
        "malware_urls":     list(set(all_urls)),
        "botnets":          botnets,
        "persistence": "LIKELY" if any("cron" in c or "rc.local" in c or ".bashrc" in c for c in all_cmds) else "NOT_DETECTED",
    }


TOOLS = {
    "honeypot_start": {
        "fn": honeypot_start,
        "description": "Avvia honeypot IoT telnet su porta specificata (default 2323). Emula BusyBox router/cam. Cattura automaticamente credenziali, comandi e URL malware degli attaccanti.",
        "parameters": {
            "port": {"type": "integer", "description": "Porta TCP (default 2323). Consigliato anche 23 (telnet standard) se disponibile.", "required": False},
        },
    },
    "honeypot_stop": {
        "fn": honeypot_stop,
        "description": "Ferma il honeypot su una porta.",
        "parameters": {
            "port": {"type": "integer", "description": "Porta da fermare (default 2323)", "required": False},
        },
    },
    "honeypot_status": {
        "fn": honeypot_status,
        "description": "Stato honeypot attivi, statistiche catture: top attaccanti, botnet rilevate, credenziali più usate, URL malware.",
        "parameters": {},
    },
    "honeypot_get_captures": {
        "fn": honeypot_get_captures,
        "description": "Sessioni catturate nelle ultime N ore con dettagli completi: IP, credenziali, comandi, URL download malware, famiglia botnet.",
        "parameters": {
            "hours": {"type": "integer", "description": "Finestra temporale in ore (default 24)", "required": False},
            "limit": {"type": "integer", "description": "Numero massimo di sessioni da restituire (default 50)", "required": False},
        },
    },
    "honeypot_analyze_session": {
        "fn": honeypot_analyze_session,
        "description": "Analisi approfondita di tutte le sessioni da un IP specifico: pattern, credenziali, comandi, botnet identificata.",
        "parameters": {
            "source_ip": {"type": "string", "description": "IP dell'attaccante da analizzare", "required": True},
        },
    },
}
