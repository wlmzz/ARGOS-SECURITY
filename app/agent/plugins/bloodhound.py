"""
ARGOS Plugin: BloodHound CE (Community Edition)
Integrazione con BloodHound Community Edition via REST API.

BloodHound CE espone una REST API su http://localhost:8080 (default).

Variabili d'ambiente:
  BLOODHOUND_HOST   — hostname/IP (default: localhost)
  BLOODHOUND_PORT   — porta (default: 8080)
  BLOODHOUND_TOKEN  — JWT token di autenticazione

USO AUTORIZZATO: solo per pentest, Active Directory assessments e
security research con permesso esplicito del proprietario dell'infrastruttura.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "bloodhound",
    "name": "BloodHound CE",
    "description": (
        "Integrazione con BloodHound Community Edition via REST API. "
        "Analisi degli attack path in Active Directory: domini, nodi, "
        "percorsi più brevi tra utenti/computer/gruppi, Kerberoasting, "
        "ingestione dati SharpHound/AzureHound. "
        "Richiede BloodHound CE in ascolto su BLOODHOUND_HOST:BLOODHOUND_PORT "
        "e un token JWT valido in BLOODHOUND_TOKEN."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_HOST = os.environ.get("BLOODHOUND_HOST", "localhost")
_DEFAULT_PORT = int(os.environ.get("BLOODHOUND_PORT", "8890"))
_DEFAULT_TOKEN = os.environ.get("BLOODHOUND_TOKEN", "")

_NOT_INSTALLED_ERROR = (
    "BloodHound CE not reachable. "
    "Install and start BloodHound CE: https://github.com/SpecterOps/BloodHound "
    "then set BLOODHOUND_HOST, BLOODHOUND_PORT, BLOODHOUND_TOKEN env vars."
)

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _api_request(
    method: str,
    path: str,
    host: str,
    port: int,
    token: str,
    body: bytes | None = None,
    content_type: str = "application/json",
    timeout: int = 120,
) -> Any:
    """
    Esegue una chiamata HTTP alla REST API di BloodHound CE.

    Raises:
        ConnectionError: se BloodHound CE non è raggiungibile.
        PermissionError: se il token non è valido (401/403).
        RuntimeError: per errori HTTP generici.
    """
    url = f"http://{host}:{port}{path}"
    headers: dict[str, str] = {
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = content_type

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise PermissionError(
                f"Autenticazione fallita (HTTP {exc.code}). "
                "Verificare BLOODHOUND_TOKEN."
            ) from exc
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body_text}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(f"BloodHound CE non raggiungibile: {exc}") from exc


def _get(path: str, host: str, port: int, token: str, timeout: int = 120) -> Any:
    return _api_request("GET", path, host, port, token, timeout=timeout)


def _post(
    path: str,
    host: str,
    port: int,
    token: str,
    body: bytes,
    content_type: str = "application/json",
    timeout: int = 120,
) -> Any:
    return _api_request("POST", path, host, port, token, body=body,
                         content_type=content_type, timeout=timeout)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def bloodhound_status(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Verifica la connessione a BloodHound CE e restituisce informazioni
    sull'utente autenticato e sulla versione del server.

    Chiama: GET /api/v2/self

    Returns:
        {"connected": bool, "user": str, "role": str, "server_version": str}
    """
    try:
        data = _get("/api/v2/self", host, port, token)
        # BloodHound CE /api/v2/self → {"data": {"id": ..., "principal_name": ..., ...}}
        inner = data.get("data", data)
        return {
            "connected": True,
            "user": inner.get("principal_name", inner.get("name", "")),
            "role": inner.get("roles", [{}])[0].get("name", "") if inner.get("roles") else "",
            "server_version": data.get("server_version", ""),
        }
    except ConnectionError:
        return {"connected": False, "user": "", "role": "", "server_version": "",
                "error": _NOT_INSTALLED_ERROR}
    except PermissionError as exc:
        return {"connected": True, "user": "", "role": "", "server_version": "",
                "error": str(exc)}
    except Exception as exc:
        return {"connected": False, "user": "", "role": "", "server_version": "",
                "error": str(exc)}


def bloodhound_domains(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Elenca i domini Active Directory ingestiti in BloodHound CE.

    Chiama: GET /api/v2/available-domains

    Returns:
        {"domains": [{"id": str, "name": str, "collected": bool}], "total": int}
    """
    try:
        data = _get("/api/v2/available-domains", host, port, token)
        raw_domains = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(raw_domains, dict):
            raw_domains = raw_domains.get("domains", [])
        domains = []
        for d in (raw_domains or []):
            domains.append({
                "id": d.get("id", d.get("objectid", "")),
                "name": d.get("name", d.get("label", "")),
                "collected": bool(d.get("collected", d.get("has_sessions", False))),
            })
        return {"domains": domains, "total": len(domains)}
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "domains": [], "total": 0}
    except PermissionError as exc:
        return {"error": str(exc), "domains": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "domains": [], "total": 0}


def bloodhound_shortest_path(
    start_node: str,
    end_node: str,
    domain: str = "",
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Trova il percorso più breve tra due nodi AD (es. utente → Domain Admins).

    Chiama: GET /api/v2/graphs/shortest-path?start_node={}&end_node={}

    Args:
        start_node: objectid o nome del nodo di partenza
        end_node:   objectid o nome del nodo di destinazione
        domain:     dominio opzionale per disambiguare

    Returns:
        {"nodes": [...], "edges": [...], "path_length": int}
    """
    try:
        params: dict[str, str] = {
            "start_node": start_node,
            "end_node": end_node,
        }
        if domain:
            params["domain"] = domain
        qs = urllib.parse.urlencode(params)
        data = _get(f"/api/v2/graphs/shortest-path?{qs}", host, port, token)
        inner = data.get("data", data) if isinstance(data, dict) else {}
        nodes = inner.get("nodes", [])
        edges = inner.get("edges", inner.get("relationships", []))
        return {
            "nodes": nodes,
            "edges": edges,
            "path_length": len(edges),
        }
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "nodes": [], "edges": [], "path_length": 0}
    except PermissionError as exc:
        return {"error": str(exc), "nodes": [], "edges": [], "path_length": 0}
    except Exception as exc:
        return {"error": str(exc), "nodes": [], "edges": [], "path_length": 0}


def bloodhound_attack_paths(
    domain: str,
    finding_type: str = "all",
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Recupera gli attack path per un dominio AD.

    Chiama: GET /api/v2/domains/{domain_id}/attack-paths

    Args:
        domain:       ID o nome del dominio AD (ottenuto da bloodhound_domains)
        finding_type: Filtro severità: all, critical, high, medium

    Returns:
        {"attack_paths": [...], "total": int, "domain": str}
    """
    _valid_types = {"all", "critical", "high", "medium"}
    if finding_type not in _valid_types:
        return {"error": f"finding_type deve essere uno tra: {', '.join(_valid_types)}",
                "attack_paths": [], "total": 0, "domain": domain}
    try:
        path = f"/api/v2/domains/{urllib.parse.quote(domain)}/attack-paths"
        if finding_type != "all":
            path += f"?finding_type={finding_type}"
        data = _get(path, host, port, token)
        raw = data.get("data", data) if isinstance(data, dict) else data
        paths = raw if isinstance(raw, list) else raw.get("attack_paths", []) if isinstance(raw, dict) else []
        return {"attack_paths": paths, "total": len(paths), "domain": domain}
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "attack_paths": [], "total": 0, "domain": domain}
    except PermissionError as exc:
        return {"error": str(exc), "attack_paths": [], "total": 0, "domain": domain}
    except Exception as exc:
        return {"error": str(exc), "attack_paths": [], "total": 0, "domain": domain}


def bloodhound_search(
    query: str,
    node_type: str = "",
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Cerca nodi nell'ambiente AD per nome o proprietà.

    Chiama: GET /api/v2/search?q={query}&type={node_type}

    Args:
        query:     Termine di ricerca (es. "john.doe", "DC01", "Domain Admins")
        node_type: Filtro tipo nodo: User, Computer, Group, Domain, GPO, OU
                   (stringa vuota = tutti i tipi)

    Returns:
        {"results": [{"id": str, "name": str, "type": str, "properties": dict}], "total": int}
    """
    _valid_types = {"", "User", "Computer", "Group", "Domain", "GPO", "OU"}
    if node_type not in _valid_types:
        return {"error": f"node_type deve essere uno tra: {', '.join(t for t in _valid_types if t)}",
                "results": [], "total": 0}
    try:
        params: dict[str, str] = {"q": query}
        if node_type:
            params["type"] = node_type
        qs = urllib.parse.urlencode(params)
        data = _get(f"/api/v2/search?{qs}", host, port, token)
        raw = data.get("data", data) if isinstance(data, dict) else data
        items = raw if isinstance(raw, list) else raw.get("results", []) if isinstance(raw, dict) else []
        results = []
        for item in items:
            results.append({
                "id": item.get("objectid", item.get("id", "")),
                "name": item.get("name", item.get("label", "")),
                "type": item.get("type", item.get("kind", "")),
                "properties": item.get("properties", {}),
            })
        return {"results": results, "total": len(results)}
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "results": [], "total": 0}
    except PermissionError as exc:
        return {"error": str(exc), "results": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "results": [], "total": 0}


def bloodhound_node_info(
    node_id: str,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Recupera informazioni dettagliate su un nodo AD (utente, computer, gruppo, ecc.).

    Chiama: GET /api/v2/nodes/{node_id}

    Args:
        node_id: objectid del nodo (ottenuto da bloodhound_search)

    Returns:
        {"id": str, "name": str, "type": str, "properties": dict, "admin_rights": list, "sessions": list}
    """
    try:
        data = _get(f"/api/v2/nodes/{urllib.parse.quote(node_id)}", host, port, token)
        inner = data.get("data", data) if isinstance(data, dict) else {}
        return {
            "id": inner.get("objectid", inner.get("id", node_id)),
            "name": inner.get("name", inner.get("label", "")),
            "type": inner.get("type", inner.get("kind", "")),
            "properties": inner.get("properties", {}),
            "admin_rights": inner.get("admin_rights", []),
            "sessions": inner.get("sessions", []),
        }
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "id": node_id, "name": "", "type": "",
                "properties": {}, "admin_rights": [], "sessions": []}
    except PermissionError as exc:
        return {"error": str(exc), "id": node_id, "name": "", "type": "",
                "properties": {}, "admin_rights": [], "sessions": []}
    except Exception as exc:
        return {"error": str(exc), "id": node_id, "name": "", "type": "",
                "properties": {}, "admin_rights": [], "sessions": []}


def bloodhound_ingest(
    zip_file: str,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    token: str = _DEFAULT_TOKEN,
) -> dict:
    """
    Carica un file ZIP con dati SharpHound o AzureHound per l'ingestione in BloodHound CE.

    Chiama: POST /api/v2/file-upload

    Args:
        zip_file: Percorso assoluto al file ZIP da caricare

    Returns:
        {"success": bool, "task_id": str, "message": str, "file": str}
    """
    import mimetypes

    if not zip_file:
        return {"error": "zip_file è obbligatorio.", "success": False,
                "task_id": "", "message": "", "file": ""}

    import os as _os
    if not _os.path.isfile(zip_file):
        return {"error": f"File non trovato: {zip_file}", "success": False,
                "task_id": "", "message": "", "file": zip_file}

    try:
        with open(zip_file, "rb") as fh:
            raw_bytes = fh.read()

        filename = _os.path.basename(zip_file)
        boundary = "----ARGOSBloodHoundBoundary7a3f9c"
        mime_type = mimetypes.guess_type(filename)[0] or "application/zip"

        # Costruiamo il multipart/form-data manualmente (stdlib only)
        body_parts: list[bytes] = []
        body_parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: {mime_type}\r\n\r\n"
            ).encode()
        )
        body_parts.append(raw_bytes)
        body_parts.append(f"\r\n--{boundary}--\r\n".encode())
        body = b"".join(body_parts)

        data = _post(
            "/api/v2/file-upload",
            host,
            port,
            token,
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        inner = data.get("data", data) if isinstance(data, dict) else {}
        return {
            "success": True,
            "task_id": str(inner.get("task_id", inner.get("id", ""))),
            "message": inner.get("message", "File ingestito correttamente."),
            "file": zip_file,
        }
    except ConnectionError:
        return {"error": _NOT_INSTALLED_ERROR, "success": False,
                "task_id": "", "message": "", "file": zip_file}
    except PermissionError as exc:
        return {"error": str(exc), "success": False,
                "task_id": "", "message": "", "file": zip_file}
    except Exception as exc:
        return {"error": str(exc), "success": False,
                "task_id": "", "message": "", "file": zip_file}


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "bloodhound_status": {
        "fn": bloodhound_status,
        "description": (
            "Verifica la connessione a BloodHound CE e restituisce le informazioni "
            "sull'utente autenticato. "
            "Configurazione via env: BLOODHOUND_HOST, BLOODHOUND_PORT, BLOODHOUND_TOKEN."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host BloodHound CE (default: env BLOODHOUND_HOST o localhost)"},
                "port": {"type": "integer", "description": "Porta BloodHound CE (default: env BLOODHOUND_PORT o 8080)"},
                "token": {"type": "string", "description": "JWT token (default: env BLOODHOUND_TOKEN)"},
            },
            "required": [],
        },
    },
    "bloodhound_domains": {
        "fn": bloodhound_domains,
        "description": (
            "Elenca i domini Active Directory ingestiti in BloodHound CE. "
            "Restituisce id, nome e flag di raccolta dati per ogni dominio."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": [],
        },
    },
    "bloodhound_shortest_path": {
        "fn": bloodhound_shortest_path,
        "description": (
            "Trova il percorso più breve tra due nodi AD in BloodHound CE. "
            "Utile per analizzare come un utente può raggiungere Domain Admins. "
            "USO AUTORIZZATO: solo per AD assessments con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "start_node": {"type": "string", "description": "objectid o nome del nodo di partenza (es. utente)"},
                "end_node": {"type": "string", "description": "objectid o nome del nodo di destinazione (es. Domain Admins)"},
                "domain": {"type": "string", "description": "Dominio per disambiguare (opzionale)"},
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": ["start_node", "end_node"],
        },
    },
    "bloodhound_attack_paths": {
        "fn": bloodhound_attack_paths,
        "description": (
            "Recupera tutti gli attack path per un dominio AD. "
            "Filtrabile per severità: all, critical, high, medium. "
            "USO AUTORIZZATO: solo per AD assessments con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "ID o nome del dominio AD (da bloodhound_domains)"},
                "finding_type": {
                    "type": "string",
                    "enum": ["all", "critical", "high", "medium"],
                    "description": "Filtro severità (default: all)",
                },
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": ["domain"],
        },
    },
    "bloodhound_search": {
        "fn": bloodhound_search,
        "description": (
            "Cerca nodi AD in BloodHound CE per nome o proprietà. "
            "Filtrabile per tipo: User, Computer, Group, Domain, GPO, OU."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Termine di ricerca (es. 'john.doe', 'Domain Admins', 'DC01')"},
                "node_type": {
                    "type": "string",
                    "enum": ["", "User", "Computer", "Group", "Domain", "GPO", "OU"],
                    "description": "Tipo nodo da filtrare (default: tutti)",
                },
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": ["query"],
        },
    },
    "bloodhound_node_info": {
        "fn": bloodhound_node_info,
        "description": (
            "Recupera informazioni dettagliate su un nodo AD (utente, computer, gruppo, GPO, ecc.). "
            "Include proprietà, diritti amministrativi e sessioni attive."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string", "description": "objectid del nodo (da bloodhound_search)"},
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": ["node_id"],
        },
    },
    "bloodhound_ingest": {
        "fn": bloodhound_ingest,
        "description": (
            "Carica un file ZIP con dati SharpHound o AzureHound per l'ingestione in BloodHound CE. "
            "Il file deve essere un archivio ZIP prodotto da SharpHound (AD) o AzureHound (Azure AD). "
            "USO AUTORIZZATO: solo per AD assessments con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "zip_file": {"type": "string", "description": "Percorso assoluto al file ZIP SharpHound/AzureHound"},
                "host": {"type": "string", "description": "Host BloodHound CE"},
                "port": {"type": "integer", "description": "Porta BloodHound CE"},
                "token": {"type": "string", "description": "JWT token"},
            },
            "required": ["zip_file"],
        },
    },
}
