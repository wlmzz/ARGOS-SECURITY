"""
ARGOS Plugin: Metasploit Framework
Integrazione con Metasploit Framework via msfrpc (JSON-RPC over HTTP).

REQUISITI:
  Avviare msfrpcd prima di usare questo plugin:
    msfrpcd -P password -S -a 127.0.0.1

Variabile d'ambiente:
  MSFRPC_PASSWORD  — password RPC (default: "msf123")

USO AUTORIZZATO: solo per pentest, CTF e security research con permesso esplicito.
"""

import json
import os
import time
import urllib.request
import urllib.error
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "metasploit",
    "name": "Metasploit Framework",
    "description": (
        "Integrazione con Metasploit Framework via msfrpc JSON-RPC. "
        "Permette di cercare moduli, eseguire exploit, gestire sessioni "
        "e interagire con shell/meterpreter. "
        "Richiede msfrpcd in ascolto: msfrpcd -P password -S -a 127.0.0.1"
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# MSFClient
# ---------------------------------------------------------------------------

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 55553
_DEFAULT_PASSWORD = os.environ.get("MSFRPC_PASSWORD", "msf123")
_DEFAULT_USER = "msf"
_TOKEN_TTL = 270  # secondi — i token msfrpc scadono a 300 s di default


class MSFClient:
    """Client leggero per l'API JSON-RPC di msfrpcd."""

    def __init__(
        self,
        host: str = _DEFAULT_HOST,
        port: int = _DEFAULT_PORT,
        password: str = _DEFAULT_PASSWORD,
        user: str = _DEFAULT_USER,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.user = user
        self._token: str | None = None
        self._token_ts: float = 0.0
        self._base_url = f"http://{host}:{port}/api/"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call(self, method: str, args: list[Any]) -> Any:
        """Esegue una chiamata JSON-RPC a msfrpcd."""
        payload = json.dumps([method] + args).encode()
        req = urllib.request.Request(
            self._base_url,
            data=payload,
            headers={
                "Content-Type": "binary/message-pack",
                "Accept": "binary/message-pack",
            },
        )
        # msfrpcd accetta anche JSON se Content-Type è text/json
        req = urllib.request.Request(
            self._base_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                return json.loads(raw)
        except urllib.error.URLError as exc:
            raise ConnectionError(f"msfrpcd non raggiungibile: {exc}") from exc

    def _auth(self) -> None:
        """Autentica con msfrpcd e memorizza il token."""
        result = self._call("auth.login", [self.user, self.password])
        if result.get("result") == "success":
            self._token = result["token"]
            self._token_ts = time.monotonic()
        else:
            raise PermissionError(f"Auth fallita: {result}")

    def _ensure_auth(self) -> str:
        """Restituisce un token valido, rinegoziando se necessario."""
        if self._token is None or (time.monotonic() - self._token_ts) > _TOKEN_TTL:
            self._auth()
        return self._token  # type: ignore[return-value]

    def rpc(self, method: str, *args: Any) -> Any:
        """Chiamata RPC autenticata."""
        token = self._ensure_auth()
        return self._call(method, [token] + list(args))


# ---------------------------------------------------------------------------
# Singleton client (lazy)
# ---------------------------------------------------------------------------

_client: MSFClient | None = None


def _get_client(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
) -> MSFClient:
    global _client
    if (
        _client is None
        or _client.host != host
        or _client.port != port
        or _client.password != password
    ):
        _client = MSFClient(host=host, port=port, password=password)
    return _client


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def msf_status(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
) -> dict:
    """
    Verifica se msfrpcd è in ascolto e restituisce la versione del framework.

    Returns:
        {"running": bool, "version": str, "ruby": str, "api": str}
    """
    try:
        client = _get_client(host, port, password)
        result = client.rpc("core.version")
        return {
            "running": True,
            "version": result.get("version", ""),
            "ruby": result.get("ruby", ""),
            "api": result.get("api", ""),
        }
    except ConnectionError as exc:
        return {"running": False, "version": "", "ruby": "", "api": "", "error": str(exc)}
    except PermissionError as exc:
        return {"running": True, "version": "", "ruby": "", "api": "", "error": str(exc)}
    except Exception as exc:
        return {"running": False, "version": "", "ruby": "", "api": "", "error": str(exc)}


def msf_search(
    query: str,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
) -> dict:
    """
    Cerca moduli Metasploit per nome, tipo o CVE.

    Args:
        query: Termine di ricerca (es. "eternalblue", "type:exploit rank:excellent")

    Returns:
        {"modules": [{"name": str, "type": str, "rank": str, "description": str}], "total": int}
    """
    try:
        client = _get_client(host, port, password)
        result = client.rpc("module.search", query)
        modules = []
        for mod in result if isinstance(result, list) else []:
            modules.append(
                {
                    "name": mod.get("fullname", mod.get("name", "")),
                    "type": mod.get("type", ""),
                    "rank": mod.get("rank", ""),
                    "description": mod.get("description", ""),
                }
            )
        return {"modules": modules, "total": len(modules)}
    except ConnectionError:
        return {
            "error": "msfrpcd not installed or not running. "
            "Install Metasploit and start: msfrpcd -P password -S -a 127.0.0.1"
        }
    except Exception as exc:
        return {"error": str(exc), "modules": [], "total": 0}


def msf_run_exploit(
    module: str,
    target_host: str,
    target_port: int = 0,
    options: dict | None = None,
    payload: str = "generic/shell_reverse_tcp",
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
    wait_seconds: int = 15,
) -> dict:
    """
    Esegue un modulo exploit/auxiliary/post tramite console msfrpc.

    Args:
        module:      Nome modulo (es. "exploit/multi/handler")
        target_host: Host bersaglio (RHOSTS)
        target_port: Porta bersaglio (RPORT), 0 = non impostare
        options:     Dict di opzioni aggiuntive {LHOST: "...", LPORT: 4444, ...}
        payload:     Payload da usare
        wait_seconds: Secondi di attesa dopo 'run' prima di leggere output

    Returns:
        {"output": str, "success": bool, "sessions": list}
    """
    try:
        client = _get_client(host, port, password)

        # Crea console
        console_result = client.rpc("console.create")
        console_id = str(console_result.get("id", "0"))

        def console_send(cmd: str) -> None:
            client.rpc("console.write", console_id, cmd + "\n")
            time.sleep(0.5)

        def console_read() -> str:
            result = client.rpc("console.read", console_id)
            return result.get("data", "") if isinstance(result, dict) else ""

        # Svuota buffer iniziale
        time.sleep(1)
        console_read()

        # Comandi di configurazione
        console_send(f"use {module}")
        console_send(f"set RHOSTS {target_host}")
        if target_port:
            console_send(f"set RPORT {target_port}")
        if options:
            for key, val in options.items():
                console_send(f"set {key} {val}")
        console_send(f"set PAYLOAD {payload}")
        console_send("run")

        # Attendi esecuzione
        time.sleep(wait_seconds)
        output = console_read()

        # Raccogli sessioni attive
        sessions_raw = client.rpc("session.list")
        sessions = []
        if isinstance(sessions_raw, dict):
            for sid, info in sessions_raw.items():
                sessions.append(
                    {
                        "id": sid,
                        "type": info.get("type", ""),
                        "info": info.get("info", ""),
                        "via_exploit": info.get("via_exploit", ""),
                    }
                )

        success = "error" not in output.lower() and len(sessions) > 0 or "success" in output.lower()

        # Distruggi console
        try:
            client.rpc("console.destroy", console_id)
        except Exception:
            pass

        return {"output": output, "success": bool(success), "sessions": sessions}

    except ConnectionError:
        return {
            "error": "msfrpcd not installed or not running. "
            "Install Metasploit and start: msfrpcd -P password -S -a 127.0.0.1"
        }
    except Exception as exc:
        return {"error": str(exc), "output": "", "success": False, "sessions": []}


def msf_sessions(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
) -> dict:
    """
    Elenca le sessioni Metasploit attive (meterpreter / shell).

    Returns:
        {"sessions": [{"id": int, "type": str, "info": str, "via_exploit": str}]}
    """
    try:
        client = _get_client(host, port, password)
        raw = client.rpc("session.list")
        sessions = []
        if isinstance(raw, dict):
            for sid, info in raw.items():
                sessions.append(
                    {
                        "id": sid,
                        "type": info.get("type", ""),
                        "info": info.get("info", ""),
                        "via_exploit": info.get("via_exploit", ""),
                    }
                )
        return {"sessions": sessions}
    except ConnectionError:
        return {
            "error": "msfrpcd not installed or not running. "
            "Install Metasploit and start: msfrpcd -P password -S -a 127.0.0.1"
        }
    except Exception as exc:
        return {"error": str(exc), "sessions": []}


def msf_run_command(
    session_id: int,
    command: str,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    password: str = _DEFAULT_PASSWORD,
    wait_seconds: int = 5,
) -> dict:
    """
    Esegue un comando in una sessione meterpreter o shell attiva.

    Args:
        session_id: ID della sessione (da msf_sessions)
        command:    Comando da eseguire
        wait_seconds: Attesa risposta in secondi

    Returns:
        {"output": str, "session_id": int}
    """
    try:
        client = _get_client(host, port, password)

        # Determina il tipo di sessione
        sessions_raw = client.rpc("session.list")
        session_info = {}
        if isinstance(sessions_raw, dict):
            session_info = sessions_raw.get(str(session_id), {})

        session_type = session_info.get("type", "")
        output = ""

        if "meterpreter" in session_type.lower():
            client.rpc("session.meterpreter_run_single", str(session_id), command)
            time.sleep(wait_seconds)
            read_result = client.rpc("session.meterpreter_read", str(session_id))
            output = read_result.get("data", "") if isinstance(read_result, dict) else str(read_result)
        else:
            # Shell generica
            client.rpc("session.shell_write", str(session_id), command + "\n")
            time.sleep(wait_seconds)
            read_result = client.rpc("session.shell_read", str(session_id))
            output = read_result.get("data", "") if isinstance(read_result, dict) else str(read_result)

        return {"output": output, "session_id": session_id}

    except ConnectionError:
        return {
            "error": "msfrpcd not installed or not running. "
            "Install Metasploit and start: msfrpcd -P password -S -a 127.0.0.1"
        }
    except Exception as exc:
        return {"error": str(exc), "output": "", "session_id": session_id}


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "msf_status": {
        "fn": msf_status,
        "description": (
            "Verifica se msfrpcd è in ascolto e restituisce versione Metasploit/Ruby/API. "
            "Configurazione default: host=127.0.0.1, port=55553, password da MSFRPC_PASSWORD env."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host msfrpcd (default: 127.0.0.1)"},
                "port": {"type": "integer", "description": "Porta msfrpcd (default: 55553)"},
                "password": {"type": "string", "description": "Password RPC (default: env MSFRPC_PASSWORD o 'msf123')"},
            },
            "required": [],
        },
    },
    "msf_search": {
        "fn": msf_search,
        "description": (
            "Cerca moduli Metasploit (exploit, auxiliary, post, payload) per nome, tipo o CVE. "
            "Esempi: 'eternalblue', 'type:auxiliary rank:excellent', 'CVE-2021-44228'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Termine di ricerca"},
                "host": {"type": "string", "description": "Host msfrpcd"},
                "port": {"type": "integer", "description": "Porta msfrpcd"},
                "password": {"type": "string", "description": "Password RPC"},
            },
            "required": ["query"],
        },
    },
    "msf_run_exploit": {
        "fn": msf_run_exploit,
        "description": (
            "Esegue un modulo exploit/auxiliary/post su un target. "
            "Crea una console msf, configura il modulo e legge l'output. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Nome modulo (es. exploit/multi/handler)"},
                "target_host": {"type": "string", "description": "Host bersaglio (RHOSTS)"},
                "target_port": {"type": "integer", "description": "Porta bersaglio (RPORT)"},
                "options": {
                    "type": "object",
                    "description": "Opzioni aggiuntive {LHOST: '...', LPORT: 4444}",
                    "additionalProperties": {"type": "string"},
                },
                "payload": {"type": "string", "description": "Payload (default: generic/shell_reverse_tcp)"},
                "host": {"type": "string", "description": "Host msfrpcd"},
                "port": {"type": "integer", "description": "Porta msfrpcd"},
                "password": {"type": "string", "description": "Password RPC"},
                "wait_seconds": {"type": "integer", "description": "Secondi di attesa dopo run (default: 15)"},
            },
            "required": ["module", "target_host"],
        },
    },
    "msf_sessions": {
        "fn": msf_sessions,
        "description": "Elenca le sessioni Metasploit attive (meterpreter e shell).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host msfrpcd"},
                "port": {"type": "integer", "description": "Porta msfrpcd"},
                "password": {"type": "string", "description": "Password RPC"},
            },
            "required": [],
        },
    },
    "msf_run_command": {
        "fn": msf_run_command,
        "description": (
            "Esegue un comando in una sessione Metasploit attiva. "
            "Supporta sessioni meterpreter e shell generiche. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "integer", "description": "ID sessione (da msf_sessions)"},
                "command": {"type": "string", "description": "Comando da eseguire"},
                "host": {"type": "string", "description": "Host msfrpcd"},
                "port": {"type": "integer", "description": "Porta msfrpcd"},
                "password": {"type": "string", "description": "Password RPC"},
                "wait_seconds": {"type": "integer", "description": "Secondi di attesa risposta (default: 5)"},
            },
            "required": ["session_id", "command"],
        },
    },
}
