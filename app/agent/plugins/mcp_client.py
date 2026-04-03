"""
ARGOS Plugin: MCP Client (Model Context Protocol)
==================================================
Permette ad ARGOS di connettersi a server MCP esterni (stdio o HTTP)
e di usarne i tool tramite JSON-RPC 2.0.

Dipendenze: solo stdlib Python (subprocess, json, threading, urllib, etc.)
Config:     /opt/argos/configs/mcp_servers.json
"""

import json
import os
import subprocess
import threading
import time
import urllib.request
import urllib.error
from typing import Any

# ---------------------------------------------------------------------------
# Manifest del plugin
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "mcp_client",
    "name": "MCP Client",
    "version": "1.0.0",
    "description": (
        "Client Model Context Protocol (MCP): connette ARGOS a server MCP "
        "esterni via stdio o HTTP e ne espone i tool."
    ),
    "author": "ARGOS",
    "requires": [],
}

# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------
MCP_CONFIG_PATH = "/opt/argos/configs/mcp_servers.json"
MCP_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TIMEOUT = 30  # secondi
_JSON_RPC_VERSION = "2.0"

# ---------------------------------------------------------------------------
# Stato interno del plugin
# ---------------------------------------------------------------------------

# Connessioni attive: server_name -> istanza Transport
_active_connections: dict[str, "_Transport"] = {}

# Lock per accesso thread-safe alle strutture condivise
_connections_lock = threading.Lock()

# Tool dinamici scoperti tramite mcp_auto_discover
# Chiave: "mcp__{server}__{tool_name}" → dict con fn, description, parameters
_mcp_dynamic_tools: dict[str, dict] = {}

# Counter globale per gli id JSON-RPC (non critico per correttezza, comodo)
_rpc_id_counter = 0
_rpc_id_lock = threading.Lock()


def _next_rpc_id() -> int:
    """Genera un id incrementale thread-safe per le richieste JSON-RPC."""
    global _rpc_id_counter
    with _rpc_id_lock:
        _rpc_id_counter += 1
        return _rpc_id_counter


# ---------------------------------------------------------------------------
# Lettura configurazione
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """
    Carica e restituisce la configurazione dei server MCP.
    Restituisce {"servers": {}} se il file non esiste o è malformato.
    """
    if not os.path.exists(MCP_CONFIG_PATH):
        return {"servers": {}}
    try:
        with open(MCP_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "servers" not in data or not isinstance(data["servers"], dict):
            return {"servers": {}}
        return data
    except (json.JSONDecodeError, OSError) as exc:
        return {"servers": {}, "_load_error": str(exc)}


# ---------------------------------------------------------------------------
# Classi di trasporto
# ---------------------------------------------------------------------------

class _Transport:
    """Interfaccia base per i trasporti MCP."""

    def send_request(self, method: str, params: dict) -> dict:
        raise NotImplementedError

    def close(self):
        pass

    @property
    def is_alive(self) -> bool:
        return True


class StdioTransport(_Transport):
    """
    Trasporto MCP via processo stdio.
    Spawna il processo e comunica con esso tramite stdin/stdout usando JSON-RPC.
    """

    def __init__(self, command: str, args: list[str], env: dict | None = None,
                 timeout: int = DEFAULT_TIMEOUT):
        self.command = command
        self.args = args
        self.timeout = timeout
        self._process: subprocess.Popen | None = None
        self._lock = threading.Lock()

        # Costruisce l'ambiente del processo figlio
        proc_env = os.environ.copy()
        if env:
            proc_env.update({k: v for k, v in env.items() if v})  # ignora valori vuoti

        full_cmd = [command] + args
        try:
            self._process = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=proc_env,
                text=True,           # modalità testo (str, non bytes)
                bufsize=1,           # line-buffered
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Comando '{command}' non trovato. "
                f"Assicurati che sia installato e nel PATH. Dettaglio: {exc}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Impossibile avviare il processo: {exc}") from exc

    @property
    def is_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def send_request(self, method: str, params: dict) -> dict:
        """
        Invia una richiesta JSON-RPC al processo e attende la risposta.
        Gestisce timeout e errori di parsing.
        """
        if not self.is_alive:
            return {"error": {"code": -32000, "message": "Processo non attivo"}}

        rpc_id = _next_rpc_id()
        request = {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": rpc_id,
            "method": method,
            "params": params,
        }
        request_line = json.dumps(request) + "\n"

        with self._lock:
            # --- Scrittura ---
            try:
                self._process.stdin.write(request_line)
                self._process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                return {"error": {"code": -32000, "message": f"Scrittura stdin fallita: {exc}"}}

            # --- Lettura con timeout ---
            response_line: str | None = None
            result_holder: list[str] = []
            error_holder: list[str] = []

            def _read():
                try:
                    line = self._process.stdout.readline()
                    result_holder.append(line)
                except OSError as e:
                    error_holder.append(str(e))

            reader = threading.Thread(target=_read, daemon=True)
            reader.start()
            reader.join(timeout=self.timeout)

            if reader.is_alive():
                # Timeout: termina il processo
                self._kill()
                return {
                    "error": {
                        "code": -32000,
                        "message": f"Timeout ({self.timeout}s) in attesa della risposta",
                    }
                }

            if error_holder:
                return {"error": {"code": -32000, "message": f"Lettura stdout fallita: {error_holder[0]}"}}

            response_line = result_holder[0] if result_holder else ""

        if not response_line or not response_line.strip():
            # Processo terminato senza risposta
            stderr_output = ""
            if self._process and self._process.stderr:
                try:
                    # Leggi stderr non bloccante (già disponibile)
                    import select as _select
                    if _select.select([self._process.stderr], [], [], 0.1)[0]:
                        stderr_output = self._process.stderr.read(4096)
                except Exception:
                    pass
            return {
                "error": {
                    "code": -32000,
                    "message": f"Risposta vuota dal processo. Stderr: {stderr_output[:500]}",
                }
            }

        try:
            return json.loads(response_line.strip())
        except json.JSONDecodeError as exc:
            return {
                "error": {
                    "code": -32700,
                    "message": f"JSON parse error: {exc}. Raw: {response_line[:200]}",
                }
            }

    def _kill(self):
        """Termina forzatamente il processo."""
        if self._process:
            try:
                self._process.kill()
            except OSError:
                pass
            self._process = None

    def close(self):
        """Chiude il trasporto terminando il processo figlio."""
        if self._process and self._process.poll() is None:
            try:
                self._process.stdin.close()
            except OSError:
                pass
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kill()
            except OSError:
                pass
        self._process = None


class HTTPTransport(_Transport):
    """
    Trasporto MCP via HTTP POST (JSON-RPC su HTTP).
    Usa urllib.request per evitare dipendenze esterne.
    """

    def __init__(self, url: str, timeout: int = DEFAULT_TIMEOUT,
                 headers: dict | None = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}

    @property
    def is_alive(self) -> bool:
        # Per HTTP non c'è uno stato persistente: consideriamo sempre vivo
        return True

    def send_request(self, method: str, params: dict) -> dict:
        """
        Invia una richiesta JSON-RPC via HTTP POST e restituisce la risposta.
        """
        rpc_id = _next_rpc_id()
        payload = {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": rpc_id,
            "method": method,
            "params": params,
        }
        body = json.dumps(payload).encode("utf-8")

        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        default_headers.update(self.headers)

        req = urllib.request.Request(
            self.url,
            data=body,
            headers=default_headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return {
                "error": {
                    "code": -32000,
                    "message": f"HTTP {exc.code}: {exc.reason}",
                }
            }
        except urllib.error.URLError as exc:
            return {
                "error": {
                    "code": -32000,
                    "message": f"Connessione fallita a {self.url}: {exc.reason}",
                }
            }
        except TimeoutError:
            return {
                "error": {
                    "code": -32000,
                    "message": f"Timeout ({self.timeout}s) durante la richiesta HTTP",
                }
            }

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            return {
                "error": {
                    "code": -32700,
                    "message": f"JSON parse error: {exc}. Raw: {raw[:200]}",
                }
            }

    def close(self):
        # Nessuna risorsa persistente da liberare
        pass


# ---------------------------------------------------------------------------
# Sessione MCP: astrazione su trasporto + stato handshake
# ---------------------------------------------------------------------------

class MCPSession:
    """
    Rappresenta una sessione attiva con un server MCP.
    Gestisce il handshake iniziale e mantiene la lista dei tool disponibili.
    """

    def __init__(self, server_name: str, transport: _Transport):
        self.server_name = server_name
        self.transport = transport
        self.initialized = False
        self.server_info: dict = {}
        self.available_tools: list[dict] = []  # tool così come restituiti da tools/list

    def initialize(self) -> dict:
        """
        Esegue la fase di initialize del protocollo MCP.
        Restituisce il risultato del server o un dict di errore.
        """
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "argos", "version": "1.0"},
        }
        resp = self.transport.send_request("initialize", params)
        if "error" in resp:
            return resp
        self.server_info = resp.get("result", {})
        self.initialized = True

        # Notifica al server che il client è pronto (initialized notification)
        # È un JSON-RPC notification (nessun id, nessuna risposta attesa)
        # Alcuni server la richiedono, la inviamo in best-effort
        notif = {"jsonrpc": _JSON_RPC_VERSION, "method": "notifications/initialized", "params": {}}
        try:
            if hasattr(self.transport, "_process") and self.transport._process:
                line = json.dumps(notif) + "\n"
                self.transport._process.stdin.write(line)
                self.transport._process.stdin.flush()
        except Exception:
            pass  # notifica opzionale

        return {"result": self.server_info}

    def list_tools(self) -> dict:
        """
        Recupera la lista dei tool dal server MCP.
        Popola self.available_tools e restituisce la risposta raw.
        """
        if not self.initialized:
            init_result = self.initialize()
            if "error" in init_result:
                return init_result

        resp = self.transport.send_request("tools/list", {})
        if "error" in resp:
            return resp

        result = resp.get("result", {})
        self.available_tools = result.get("tools", [])
        return {"result": self.available_tools}

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Invoca un tool sul server MCP.
        """
        if not self.initialized:
            init_result = self.initialize()
            if "error" in init_result:
                return init_result

        params = {"name": tool_name, "arguments": arguments}
        resp = self.transport.send_request("tools/call", params)
        return resp

    def close(self):
        self.transport.close()
        self.initialized = False

    @property
    def is_alive(self) -> bool:
        return self.transport.is_alive


# ---------------------------------------------------------------------------
# Helpers interni
# ---------------------------------------------------------------------------

def _build_transport(server_cfg: dict) -> _Transport:
    """
    Costruisce il trasporto appropriato in base alla configurazione del server.
    Solleva RuntimeError se la configurazione è invalida.
    """
    transport_type = server_cfg.get("transport", "").lower()

    if transport_type == "stdio":
        command = server_cfg.get("command")
        if not command:
            raise RuntimeError("Configurazione mancante: campo 'command' richiesto per trasporto stdio")
        args = server_cfg.get("args", [])
        env = server_cfg.get("env", {})
        return StdioTransport(command=command, args=args, env=env)

    elif transport_type == "http":
        url = server_cfg.get("url")
        if not url:
            raise RuntimeError("Configurazione mancante: campo 'url' richiesto per trasporto http")
        headers = server_cfg.get("headers", {})
        return HTTPTransport(url=url, headers=headers)

    else:
        raise RuntimeError(
            f"Tipo di trasporto non supportato: '{transport_type}'. "
            "Valori accettati: 'stdio', 'http'"
        )


def _get_or_create_session(server_name: str) -> tuple[MCPSession | None, str]:
    """
    Restituisce la sessione attiva per il server, oppure ne crea una nuova.
    Ritorna (session, error_message). Se session è None, error_message descrive il problema.
    """
    with _connections_lock:
        # Sessione già attiva e viva?
        if server_name in _active_connections:
            session = _active_connections[server_name]
            if session.is_alive:
                return session, ""
            else:
                # Processo morto: rimuovi e ricrea
                try:
                    session.close()
                except Exception:
                    pass
                del _active_connections[server_name]

        # Crea nuova sessione
        config = _load_config()
        servers = config.get("servers", {})
        if server_name not in servers:
            return None, f"Server '{server_name}' non trovato in {MCP_CONFIG_PATH}"

        server_cfg = servers[server_name]
        if not server_cfg.get("enabled", False):
            return None, (
                f"Server '{server_name}' è disabilitato nella configurazione. "
                "Impostare 'enabled': true per attivarlo."
            )

        try:
            transport = _build_transport(server_cfg)
        except RuntimeError as exc:
            return None, str(exc)

        session = MCPSession(server_name=server_name, transport=transport)
        _active_connections[server_name] = session
        return session, ""


def _make_dynamic_tool_fn(server_name: str, tool_name: str) -> Any:
    """
    Factory che genera una funzione Python chiamabile da ARGOS
    per invocare un tool MCP specifico.
    """
    def _dynamic_fn(**kwargs) -> dict:
        return _mcp_call_tool_impl(server=server_name, tool=tool_name, arguments=kwargs)
    _dynamic_fn.__name__ = f"mcp__{server_name}__{tool_name}"
    _dynamic_fn.__doc__ = f"Tool MCP '{tool_name}' su server '{server_name}'"
    return _dynamic_fn


# ---------------------------------------------------------------------------
# Implementazioni dei tool ARGOS
# ---------------------------------------------------------------------------

def _mcp_list_servers(**kwargs) -> dict:
    """
    Elenca i server MCP configurati e il loro stato (connesso/disconnesso/disabilitato).
    """
    config = _load_config()
    if "_load_error" in config:
        return {
            "error": f"Impossibile caricare la configurazione: {config['_load_error']}",
            "config_path": MCP_CONFIG_PATH,
        }

    servers = config.get("servers", {})
    if not servers:
        return {
            "servers": [],
            "message": f"Nessun server configurato in {MCP_CONFIG_PATH}",
        }

    result = []
    with _connections_lock:
        active_snapshot = dict(_active_connections)

    for name, cfg in servers.items():
        enabled = cfg.get("enabled", False)
        connected = False
        alive = False

        if name in active_snapshot:
            session = active_snapshot[name]
            connected = True
            alive = session.is_alive

        entry = {
            "name": name,
            "transport": cfg.get("transport", "unknown"),
            "enabled": enabled,
            "connected": connected,
            "alive": alive,
        }

        # Aggiungi dettagli trasporto
        if cfg.get("transport") == "stdio":
            entry["command"] = cfg.get("command", "")
            entry["args"] = cfg.get("args", [])
        elif cfg.get("transport") == "http":
            entry["url"] = cfg.get("url", "")

        result.append(entry)

    return {"servers": result, "total": len(result)}


def _mcp_connect(server: str, **kwargs) -> dict:
    """
    Si connette a un server MCP, esegue il handshake e restituisce i tool disponibili.
    """
    if not server:
        return {"error": "Parametro 'server' obbligatorio"}

    session, err = _get_or_create_session(server)
    if session is None:
        return {"error": err, "server": server}

    # Inizializza se non già fatto
    if not session.initialized:
        init_result = session.initialize()
        if "error" in init_result:
            # Rimuovi sessione fallita
            with _connections_lock:
                _active_connections.pop(server, None)
            try:
                session.close()
            except Exception:
                pass
            return {
                "error": f"Handshake fallito: {init_result['error']}",
                "server": server,
            }

    # Scopri tool
    tools_result = session.list_tools()
    if "error" in tools_result:
        return {
            "error": f"Impossibile recuperare la lista dei tool: {tools_result['error']}",
            "server": server,
        }

    tools = tools_result.get("result", [])
    return {
        "server": server,
        "status": "connected",
        "server_info": session.server_info,
        "tools": tools,
        "tool_count": len(tools),
    }


def _mcp_call_tool_impl(server: str, tool: str, arguments: dict) -> dict:
    """
    Implementazione condivisa per chiamare un tool MCP.
    Usata sia dal tool ARGOS `mcp_call_tool` sia dai tool dinamici.
    """
    if not server:
        return {"error": "Parametro 'server' obbligatorio"}
    if not tool:
        return {"error": "Parametro 'tool' obbligatorio"}

    session, err = _get_or_create_session(server)
    if session is None:
        return {"error": err, "server": server}

    # Assicura inizializzazione
    if not session.initialized:
        init_result = session.initialize()
        if "error" in init_result:
            with _connections_lock:
                _active_connections.pop(server, None)
            return {
                "error": f"Handshake fallito: {init_result['error']}",
                "server": server,
            }

    # Verifica che il tool esista (best-effort: lista potrebbe essere vuota se non ancora caricata)
    if session.available_tools:
        tool_names = [t.get("name") for t in session.available_tools]
        if tool not in tool_names:
            return {
                "error": f"Tool '{tool}' non trovato sul server '{server}'",
                "available_tools": tool_names,
            }

    resp = session.call_tool(tool_name=tool, arguments=arguments)

    if "error" in resp:
        return {
            "error": f"Errore dal server MCP: {resp['error']}",
            "server": server,
            "tool": tool,
        }

    # Estrai il contenuto della risposta
    result = resp.get("result", resp)
    return {
        "server": server,
        "tool": tool,
        "result": result,
    }


def _mcp_call_tool(server: str = "", tool: str = "",
                   arguments: dict | None = None, **kwargs) -> dict:
    """
    Chiama un tool su un server MCP specificato.

    Parametri:
        server    - Nome del server MCP (es. "filesystem")
        tool      - Nome del tool da invocare (es. "read_file")
        arguments - Dizionario con gli argomenti del tool
    """
    if not server:
        return {"error": "Parametro 'server' obbligatorio"}
    if not tool:
        return {"error": "Parametro 'tool' obbligatorio"}
    if arguments is None:
        arguments = {}

    return _mcp_call_tool_impl(server=server, tool=tool, arguments=arguments)


def _mcp_disconnect(server: str = "", **kwargs) -> dict:
    """
    Disconnette un server MCP attivo e libera le risorse.
    """
    if not server:
        return {"error": "Parametro 'server' obbligatorio"}

    with _connections_lock:
        session = _active_connections.pop(server, None)

    if session is None:
        return {
            "server": server,
            "status": "not_connected",
            "message": f"Nessuna connessione attiva con '{server}'",
        }

    try:
        session.close()
        status = "disconnected"
        msg = f"Server '{server}' disconnesso correttamente"
    except Exception as exc:
        status = "error_on_close"
        msg = f"Errore durante la disconnessione di '{server}': {exc}"

    # Rimuovi eventuali tool dinamici associati a questo server
    prefix = f"mcp__{server}__"
    keys_to_remove = [k for k in _mcp_dynamic_tools if k.startswith(prefix)]
    for k in keys_to_remove:
        del _mcp_dynamic_tools[k]

    return {"server": server, "status": status, "message": msg,
            "removed_dynamic_tools": keys_to_remove}


def _mcp_auto_discover(**kwargs) -> dict:
    """
    Si connette a tutti i server MCP abilitati, scopre i loro tool
    e li registra come tool dinamici nella forma mcp__{server}__{tool_name}.
    """
    config = _load_config()
    if "_load_error" in config:
        return {
            "error": f"Impossibile caricare la configurazione: {config['_load_error']}",
            "config_path": MCP_CONFIG_PATH,
        }

    servers = config.get("servers", {})
    enabled_servers = [name for name, cfg in servers.items() if cfg.get("enabled", False)]

    if not enabled_servers:
        return {
            "message": "Nessun server MCP abilitato trovato nella configurazione",
            "config_path": MCP_CONFIG_PATH,
            "discovered_tools": [],
        }

    results = []
    all_discovered: list[str] = []

    for server_name in enabled_servers:
        connect_result = _mcp_connect(server=server_name)

        if "error" in connect_result:
            results.append({
                "server": server_name,
                "status": "error",
                "error": connect_result["error"],
                "tools_registered": [],
            })
            continue

        tools = connect_result.get("tools", [])
        registered = []

        for tool_info in tools:
            tool_name = tool_info.get("name", "")
            if not tool_name:
                continue

            dynamic_key = f"mcp__{server_name}__{tool_name}"

            # Costruisce la definizione del tool nel formato ARGOS
            tool_description = tool_info.get("description", f"Tool MCP '{tool_name}' su server '{server_name}'")

            # Mappa lo schema dei parametri MCP → formato ARGOS
            input_schema = tool_info.get("inputSchema", {})
            argos_parameters = _mcp_schema_to_argos_params(input_schema)

            # Genera la funzione callable
            fn = _make_dynamic_tool_fn(server_name, tool_name)

            _mcp_dynamic_tools[dynamic_key] = {
                "fn": fn,
                "description": tool_description,
                "parameters": argos_parameters,
                "_mcp_meta": {
                    "server": server_name,
                    "tool": tool_name,
                    "original_schema": input_schema,
                },
            }
            registered.append(dynamic_key)
            all_discovered.append(dynamic_key)

        results.append({
            "server": server_name,
            "status": "ok",
            "tools_found": len(tools),
            "tools_registered": registered,
        })

    return {
        "servers_processed": len(enabled_servers),
        "total_tools_discovered": len(all_discovered),
        "discovered_tools": all_discovered,
        "details": results,
    }


# ---------------------------------------------------------------------------
# Conversione schema MCP → parametri ARGOS
# ---------------------------------------------------------------------------

def _mcp_schema_to_argos_params(input_schema: dict) -> dict:
    """
    Converte un JSON Schema (come usato da MCP per inputSchema)
    nel formato parametri usato da ARGOS:
    {
        "param_name": {
            "type": "string",
            "description": "...",
            "required": True/False,
        },
        ...
    }
    """
    if not input_schema:
        return {}

    properties = input_schema.get("properties", {})
    required_fields = set(input_schema.get("required", []))
    result = {}

    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        # Normalizza array di tipi (es. ["string", "null"]) → primo tipo non null
        if isinstance(prop_type, list):
            non_null = [t for t in prop_type if t != "null"]
            prop_type = non_null[0] if non_null else "string"

        result[prop_name] = {
            "type": prop_type,
            "description": prop_schema.get("description", ""),
            "required": prop_name in required_fields,
        }

        # Propagate enum se presente
        if "enum" in prop_schema:
            result[prop_name]["enum"] = prop_schema["enum"]

        # Default value se presente
        if "default" in prop_schema:
            result[prop_name]["default"] = prop_schema["default"]

    return result


# ---------------------------------------------------------------------------
# API pubblica per l'agent ARGOS
# ---------------------------------------------------------------------------

def get_dynamic_tools() -> dict[str, dict]:
    """
    Restituisce il dizionario dei tool MCP scoperti dinamicamente.
    Questo metodo viene chiamato dall'agent ARGOS per registrare
    i tool MCP come tool nativi del sistema.

    Struttura restituita:
        {
            "mcp__filesystem__read_file": {
                "fn": <callable>,
                "description": "...",
                "parameters": {...},
                "_mcp_meta": {...},
            },
            ...
        }
    """
    return dict(_mcp_dynamic_tools)


# ---------------------------------------------------------------------------
# Definizione TOOLS (formato ARGOS)
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "mcp_list_servers": {
        "fn": _mcp_list_servers,
        "description": (
            "Elenca tutti i server MCP configurati in "
            f"{MCP_CONFIG_PATH} con il loro stato (connesso/disconnesso/disabilitato)."
        ),
        "parameters": {},
    },
    "mcp_connect": {
        "fn": _mcp_connect,
        "description": (
            "Si connette a un server MCP, esegue il handshake di inizializzazione "
            "e restituisce la lista dei tool disponibili sul server."
        ),
        "parameters": {
            "server": {
                "type": "string",
                "description": "Nome del server MCP come definito nella configurazione (es. 'filesystem')",
                "required": True,
            },
        },
    },
    "mcp_call_tool": {
        "fn": _mcp_call_tool,
        "description": (
            "Chiama un tool specifico su un server MCP. "
            "Esempio: mcp_call_tool(server='filesystem', tool='read_file', "
            "arguments={'path': '/tmp/test.txt'})"
        ),
        "parameters": {
            "server": {
                "type": "string",
                "description": "Nome del server MCP (es. 'filesystem')",
                "required": True,
            },
            "tool": {
                "type": "string",
                "description": "Nome del tool da invocare (es. 'read_file')",
                "required": True,
            },
            "arguments": {
                "type": "object",
                "description": "Dizionario con gli argomenti del tool (dipende dal tool specifico)",
                "required": False,
            },
        },
    },
    "mcp_disconnect": {
        "fn": _mcp_disconnect,
        "description": (
            "Disconnette un server MCP attivo, termina il processo (se stdio) "
            "e libera le risorse. Rimuove anche i tool dinamici registrati per quel server."
        ),
        "parameters": {
            "server": {
                "type": "string",
                "description": "Nome del server MCP da disconnettere",
                "required": True,
            },
        },
    },
    "mcp_auto_discover": {
        "fn": _mcp_auto_discover,
        "description": (
            "Si connette a tutti i server MCP abilitati nella configurazione e registra "
            "automaticamente i loro tool come tool dinamici ARGOS nella forma "
            "mcp__{server}__{tool_name}. Usare get_dynamic_tools() per recuperare i tool registrati."
        ),
        "parameters": {},
    },
}
