"""
ARGOS Plugin: Tool Hooks (Hook Middleware)
==========================================
Ispirato al sistema PreToolUse/PostToolUse di Claw Code.

Ogni tool call ARGOS può essere intercettata da hook che girano PRIMA
(pre-hook) o DOPO (post-hook) l'esecuzione del tool reale.

Hook directory:  /opt/argos/hooks/pre/   e   /opt/argos/hooks/post/
Audit log:       /opt/argos/logs/tool_audit.jsonl

Built-in hooks (hardcoded, nessun file esterno richiesto):
  - audit_log           — registra ogni chiamata nel log JSONL
  - rate_limiter        — throttle per tool (N chiamate in M secondi)
  - dangerous_tool_gate — warning/blocco per tool pericolosi

Dipendenze: solo stdlib Python.
"""

import fnmatch
import importlib.util
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

# ---------------------------------------------------------------------------
# Manifest del plugin
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "tool_hooks",
    "name": "Tool Hooks",
    "version": "1.0.0",
    "description": (
        "Hook middleware Pre/Post tool call per ARGOS. "
        "Supporta audit log, rate limiting, dangerous-tool gate "
        "e hook personalizzati via script Python o Shell."
    ),
    "author": "ARGOS",
    "requires": [],
}

# ---------------------------------------------------------------------------
# Costanti e percorsi
# ---------------------------------------------------------------------------
HOOKS_BASE_DIR = "/opt/argos/hooks"
HOOKS_PRE_DIR = f"{HOOKS_BASE_DIR}/pre"
HOOKS_POST_DIR = f"{HOOKS_BASE_DIR}/post"
AUDIT_LOG_PATH = "/opt/argos/logs/tool_audit.jsonl"

# Tool considerati pericolosi — richiedono conferma esplicita
DANGEROUS_TOOLS = [
    "bash",
    "ban_ip",
    "run_pentest_pipeline",
    "auto_harden",
]

# Configurazione rate limiter: massimo N chiamate in M secondi per tool
RATE_LIMIT_MAX_CALLS = 20
RATE_LIMIT_WINDOW_SEC = 60

logger = logging.getLogger("argos.tool_hooks")

# ---------------------------------------------------------------------------
# Stato interno
# ---------------------------------------------------------------------------

# Hook personalizzati registrati a runtime (non su disco):
# {
#   "hook_name": {
#       "stage": "pre" | "post",
#       "tool_pattern": "nmap_*",     # glob pattern
#       "code": "...",                  # sorgente Python
#       "compiled": <code object>,
#   }
# }
_runtime_hooks: dict[str, dict] = {}
_runtime_hooks_lock = threading.Lock()

# Rate limiter: tool_name -> lista di timestamp (float)
_rate_limit_calls: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Helper: assicura che le directory necessarie esistano
# ---------------------------------------------------------------------------

def _ensure_dirs() -> None:
    """Crea le directory di hooks e log se non esistono ancora."""
    for path in (HOOKS_PRE_DIR, HOOKS_POST_DIR, os.path.dirname(AUDIT_LOG_PATH)):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Built-in hook: audit_log
# ---------------------------------------------------------------------------

def _builtin_audit_log_pre(tool: str, args: dict, session_id: str) -> dict:
    """Registra nel log JSONL l'avvio di una tool call."""
    _ensure_dirs()
    entry = {
        "ts": time.time(),
        "stage": "pre",
        "tool": tool,
        "session_id": session_id,
        "args_keys": list(args.keys()),  # non logga i valori per sicurezza
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.warning("audit_log pre: impossibile scrivere su %s: %s", AUDIT_LOG_PATH, exc)
    return {"action": "allow"}


def _builtin_audit_log_post(tool: str, args: dict, result: Any, session_id: str) -> dict:
    """Registra nel log JSONL il completamento di una tool call."""
    _ensure_dirs()
    # Stima dimensione result per il log senza copiare tutto
    result_str = result if isinstance(result, str) else json.dumps(result)
    entry = {
        "ts": time.time(),
        "stage": "post",
        "tool": tool,
        "session_id": session_id,
        "result_bytes": len(result_str.encode("utf-8", errors="replace")),
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.warning("audit_log post: impossibile scrivere su %s: %s", AUDIT_LOG_PATH, exc)
    return {"action": "passthrough"}


# ---------------------------------------------------------------------------
# Built-in hook: rate_limiter
# ---------------------------------------------------------------------------

def _builtin_rate_limiter_pre(tool: str, args: dict, session_id: str) -> dict:
    """
    Consente al massimo RATE_LIMIT_MAX_CALLS chiamate allo stesso tool
    nell'arco di RATE_LIMIT_WINDOW_SEC secondi (sliding window).
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SEC

    with _rate_limit_lock:
        timestamps = _rate_limit_calls.get(tool, [])
        # Scarta le chiamate fuori dalla finestra
        timestamps = [t for t in timestamps if t > cutoff]
        timestamps.append(now)
        _rate_limit_calls[tool] = timestamps
        count = len(timestamps)

    if count > RATE_LIMIT_MAX_CALLS:
        reason = (
            f"Rate limit superato per '{tool}': "
            f"{count} chiamate negli ultimi {RATE_LIMIT_WINDOW_SEC}s "
            f"(massimo {RATE_LIMIT_MAX_CALLS})."
        )
        logger.warning("rate_limiter: %s", reason)
        return {"action": "deny", "reason": reason}

    return {"action": "allow"}


# ---------------------------------------------------------------------------
# Built-in hook: dangerous_tool_gate
# ---------------------------------------------------------------------------

def _builtin_dangerous_gate_pre(tool: str, args: dict, session_id: str) -> dict:
    """
    Emette un WARNING nel log per tool nella lista pericolosi.
    In modalità produzione questo hook può essere promosso a 'deny';
    in questa implementazione di default registra e consente il passaggio
    (il sistema di audit è il punto di controllo).
    """
    if tool in DANGEROUS_TOOLS:
        logger.warning(
            "dangerous_tool_gate: tool PERICOLOSO '%s' richiesto dalla sessione '%s'. "
            "args_keys=%s",
            tool,
            session_id,
            list(args.keys()),
        )
        # Scrivi anche nel log di audit come evento speciale
        _ensure_dirs()
        entry = {
            "ts": time.time(),
            "stage": "pre",
            "event": "DANGEROUS_TOOL_WARNING",
            "tool": tool,
            "session_id": session_id,
            "args_keys": list(args.keys()),
        }
        try:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    return {"action": "allow"}


# ---------------------------------------------------------------------------
# Registro degli hook built-in
# ---------------------------------------------------------------------------

# Struttura:
# {
#   "hook_name": {
#       "stage": "pre" | "post",
#       "tool_pattern": "*",      # glob; "*" = tutti i tool
#       "builtin": True,
#       "fn_pre" | "fn_post": callable,
#   }
# }
_BUILTIN_HOOKS: dict[str, dict] = {
    "audit_log": {
        "stage": "both",
        "tool_pattern": "*",
        "builtin": True,
        "fn_pre": _builtin_audit_log_pre,
        "fn_post": _builtin_audit_log_post,
        "description": "Registra ogni tool call nel log JSONL con timestamp.",
    },
    "rate_limiter": {
        "stage": "pre",
        "tool_pattern": "*",
        "builtin": True,
        "fn_pre": _builtin_rate_limiter_pre,
        "description": (
            f"Blocca se lo stesso tool viene chiamato >{RATE_LIMIT_MAX_CALLS} volte "
            f"in {RATE_LIMIT_WINDOW_SEC}s."
        ),
    },
    "dangerous_tool_gate": {
        "stage": "pre",
        "tool_pattern": "*",
        "builtin": True,
        "fn_pre": _builtin_dangerous_gate_pre,
        "description": (
            f"Emette WARNING per tool pericolosi: {DANGEROUS_TOOLS}. "
            "Promuovere ad 'action: deny' per blocco automatico."
        ),
    },
}

# Ordine di esecuzione degli hook built-in (importante: audit_log per primo)
_BUILTIN_HOOK_ORDER = ["audit_log", "rate_limiter", "dangerous_tool_gate"]


# ---------------------------------------------------------------------------
# Helper: carica gli hook da file nella directory
# ---------------------------------------------------------------------------

def _load_file_hooks(stage: str) -> list[dict]:
    """
    Scansiona HOOKS_PRE_DIR o HOOKS_POST_DIR e restituisce la lista degli hook
    trovati come dict {"name": ..., "path": ..., "ext": ".py"|".sh"}.
    """
    base = HOOKS_PRE_DIR if stage == "pre" else HOOKS_POST_DIR
    hooks = []
    if not os.path.isdir(base):
        return hooks
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return hooks
    for name in entries:
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            continue
        if name.endswith(".py") or name.endswith(".sh"):
            hooks.append({
                "name": os.path.splitext(name)[0],
                "path": path,
                "ext": os.path.splitext(name)[1],
                "stage": stage,
                "builtin": False,
            })
    return hooks


# ---------------------------------------------------------------------------
# Helper: esegui un hook-file (Python o Shell)
# ---------------------------------------------------------------------------

def _run_file_hook(hook: dict, payload: dict) -> dict:
    """
    Esegue un singolo hook-file passandogli il payload via stdin JSON.
    Restituisce il dict di risposta dell'hook oppure {"action": "allow"} in caso di errore.
    """
    ext = hook["ext"]
    path = hook["path"]
    payload_str = json.dumps(payload)

    try:
        if ext == ".py":
            cmd = [sys.executable, path]
        else:
            cmd = ["/bin/sh", path]

        proc = subprocess.run(
            cmd,
            input=payload_str,
            capture_output=True,
            text=True,
            timeout=10,
        )

        stdout = proc.stdout.strip()
        if not stdout:
            return {"action": "allow"}

        try:
            result = json.loads(stdout)
            if not isinstance(result, dict) or "action" not in result:
                logger.warning(
                    "hook '%s': risposta JSON non valida (manca 'action'): %s",
                    hook["name"], stdout[:200]
                )
                return {"action": "allow"}
            return result
        except json.JSONDecodeError as exc:
            logger.warning(
                "hook '%s': stdout non è JSON valido (%s): %s",
                hook["name"], exc, stdout[:200]
            )
            return {"action": "allow"}

    except subprocess.TimeoutExpired:
        logger.warning("hook '%s': timeout (10s) — skipped", hook["name"])
        return {"action": "allow"}
    except OSError as exc:
        logger.warning("hook '%s': errore di esecuzione: %s", hook["name"], exc)
        return {"action": "allow"}


# ---------------------------------------------------------------------------
# Helper: esegui un hook runtime (Python inline)
# ---------------------------------------------------------------------------

def _run_runtime_hook(hook_def: dict, payload: dict) -> dict:
    """
    Esegue un hook registrato a runtime (codice Python inline).
    Il codice deve definire una funzione 'run(payload: dict) -> dict'.
    """
    compiled = hook_def.get("compiled")
    if compiled is None:
        return {"action": "allow"}

    ns: dict[str, Any] = {}
    try:
        exec(compiled, ns)  # noqa: S102
        run_fn = ns.get("run")
        if not callable(run_fn):
            logger.warning("hook runtime '%s': nessuna funzione 'run' trovata", hook_def["name"])
            return {"action": "allow"}
        result = run_fn(payload)
        if not isinstance(result, dict) or "action" not in result:
            return {"action": "allow"}
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("hook runtime '%s': eccezione durante l'esecuzione: %s", hook_def["name"], exc)
        return {"action": "allow"}


# ---------------------------------------------------------------------------
# API pubblica: run_pre_hooks / run_post_hooks
# ---------------------------------------------------------------------------

def run_pre_hooks(tool_name: str, args: dict, session_id: str) -> dict:
    """
    Esegue tutti i pre-hook applicabili al tool_name indicato.

    Ritorna:
        {
            "allowed": True | False,
            "reason": "...",       # solo se allowed=False
            "args": {...},         # args eventualmente riscritti (action: rewrite)
        }
    """
    current_args = dict(args)
    payload = {"tool": tool_name, "args": current_args, "session_id": session_id}

    # 1. Hook built-in nell'ordine definito
    for hook_name in _BUILTIN_HOOK_ORDER:
        hook_def = _BUILTIN_HOOKS.get(hook_name)
        if hook_def is None:
            continue
        stage = hook_def.get("stage")
        if stage not in ("pre", "both"):
            continue
        pattern = hook_def.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        fn = hook_def.get("fn_pre")
        if not callable(fn):
            continue
        try:
            resp = fn(tool=tool_name, args=current_args, session_id=session_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("builtin hook '%s' pre: eccezione: %s", hook_name, exc)
            resp = {"action": "allow"}

        action = resp.get("action", "allow")
        if action == "deny":
            return {
                "allowed": False,
                "reason": resp.get("reason", f"Bloccato dall'hook built-in '{hook_name}'"),
                "args": current_args,
            }
        if action == "rewrite":
            current_args = resp.get("args", current_args)
            payload["args"] = current_args

    # 2. Hook file da disco
    for file_hook in _load_file_hooks("pre"):
        pattern = file_hook.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        payload["args"] = current_args
        resp = _run_file_hook(file_hook, payload)
        action = resp.get("action", "allow")
        if action == "deny":
            return {
                "allowed": False,
                "reason": resp.get("reason", f"Bloccato dall'hook file '{file_hook['name']}'"),
                "args": current_args,
            }
        if action == "rewrite":
            current_args = resp.get("args", current_args)

    # 3. Hook runtime registrati
    with _runtime_hooks_lock:
        runtime_snapshot = dict(_runtime_hooks)

    for hook_name, hook_def in runtime_snapshot.items():
        if hook_def.get("stage") != "pre":
            continue
        pattern = hook_def.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        payload["args"] = current_args
        resp = _run_runtime_hook({"name": hook_name, **hook_def}, payload)
        action = resp.get("action", "allow")
        if action == "deny":
            return {
                "allowed": False,
                "reason": resp.get("reason", f"Bloccato dall'hook runtime '{hook_name}'"),
                "args": current_args,
            }
        if action == "rewrite":
            current_args = resp.get("args", current_args)

    return {"allowed": True, "reason": "", "args": current_args}


def run_post_hooks(tool_name: str, args: dict, result: str, session_id: str) -> str:
    """
    Esegue tutti i post-hook applicabili al tool_name indicato.

    Ritorna:
        La stringa result, eventualmente trasformata da hook con action='transform'.
    """
    current_result = result
    payload = {
        "tool": tool_name,
        "args": args,
        "result": current_result,
        "session_id": session_id,
    }

    # 1. Hook built-in
    for hook_name in _BUILTIN_HOOK_ORDER:
        hook_def = _BUILTIN_HOOKS.get(hook_name)
        if hook_def is None:
            continue
        stage = hook_def.get("stage")
        if stage not in ("post", "both"):
            continue
        pattern = hook_def.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        fn = hook_def.get("fn_post")
        if not callable(fn):
            continue
        try:
            resp = fn(tool=tool_name, args=args, result=current_result, session_id=session_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("builtin hook '%s' post: eccezione: %s", hook_name, exc)
            resp = {"action": "passthrough"}
        if resp.get("action") == "transform":
            current_result = resp.get("result", current_result)
            payload["result"] = current_result

    # 2. Hook file da disco
    for file_hook in _load_file_hooks("post"):
        pattern = file_hook.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        payload["result"] = current_result
        resp = _run_file_hook(file_hook, payload)
        if resp.get("action") == "transform":
            current_result = resp.get("result", current_result)

    # 3. Hook runtime registrati
    with _runtime_hooks_lock:
        runtime_snapshot = dict(_runtime_hooks)

    for hook_name, hook_def in runtime_snapshot.items():
        if hook_def.get("stage") != "post":
            continue
        pattern = hook_def.get("tool_pattern", "*")
        if not fnmatch.fnmatch(tool_name, pattern):
            continue
        payload["result"] = current_result
        resp = _run_runtime_hook({"name": hook_name, **hook_def}, payload)
        if resp.get("action") == "transform":
            current_result = resp.get("result", current_result)

    return current_result


# ---------------------------------------------------------------------------
# Implementazioni dei tool ARGOS
# ---------------------------------------------------------------------------

def _hooks_list(**kwargs) -> dict:
    """
    Elenca tutti gli hook attivi: built-in, da file e registrati a runtime.
    """
    result = {"builtin": [], "file": [], "runtime": []}

    # Built-in
    for name, hdef in _BUILTIN_HOOKS.items():
        result["builtin"].append({
            "name": name,
            "stage": hdef.get("stage"),
            "tool_pattern": hdef.get("tool_pattern", "*"),
            "description": hdef.get("description", ""),
        })

    # File pre/post
    for stage in ("pre", "post"):
        for fh in _load_file_hooks(stage):
            result["file"].append({
                "name": fh["name"],
                "stage": stage,
                "path": fh["path"],
                "ext": fh["ext"],
            })

    # Runtime
    with _runtime_hooks_lock:
        runtime_snapshot = dict(_runtime_hooks)
    for name, hdef in runtime_snapshot.items():
        result["runtime"].append({
            "name": name,
            "stage": hdef.get("stage"),
            "tool_pattern": hdef.get("tool_pattern", "*"),
        })

    result["total"] = (
        len(result["builtin"]) + len(result["file"]) + len(result["runtime"])
    )
    return result


def _hooks_register(
    name: str = "",
    stage: str = "pre",
    code: str = "",
    tool_pattern: str = "*",
    **kwargs,
) -> dict:
    """
    Registra un nuovo hook Python runtime.

    Parametri:
        name         - Nome univoco dell'hook
        stage        - "pre" oppure "post"
        code         - Codice Python; deve definire: def run(payload: dict) -> dict
        tool_pattern - Glob pattern dei tool a cui si applica (es. "nmap_*", "*")
    """
    if not name:
        return {"error": "Parametro 'name' obbligatorio"}
    if stage not in ("pre", "post"):
        return {"error": "Il parametro 'stage' deve essere 'pre' oppure 'post'"}
    if not code:
        return {"error": "Parametro 'code' obbligatorio"}
    if name in _BUILTIN_HOOKS:
        return {"error": f"Il nome '{name}' è riservato agli hook built-in"}

    # Compila preventivamente per catturare errori di sintassi
    try:
        compiled = compile(code, f"<hook:{name}>", "exec")
    except SyntaxError as exc:
        return {"error": f"Errore di sintassi nel codice dell'hook: {exc}"}

    # Verifica che contenga una funzione 'run'
    ns: dict[str, Any] = {}
    try:
        exec(compiled, ns)  # noqa: S102
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Errore durante l'esecuzione del codice hook: {exc}"}
    if not callable(ns.get("run")):
        return {"error": "Il codice hook deve definire una funzione 'run(payload: dict) -> dict'"}

    with _runtime_hooks_lock:
        _runtime_hooks[name] = {
            "stage": stage,
            "tool_pattern": tool_pattern,
            "code": code,
            "compiled": compiled,
        }

    return {
        "status": "registered",
        "name": name,
        "stage": stage,
        "tool_pattern": tool_pattern,
    }


def _hooks_delete(name: str = "", **kwargs) -> dict:
    """
    Elimina un hook runtime per nome. Non è possibile eliminare gli hook built-in.
    """
    if not name:
        return {"error": "Parametro 'name' obbligatorio"}
    if name in _BUILTIN_HOOKS:
        return {"error": f"L'hook built-in '{name}' non può essere eliminato"}

    with _runtime_hooks_lock:
        existed = name in _runtime_hooks
        if existed:
            del _runtime_hooks[name]

    if not existed:
        # Prova a cercarlo su disco
        removed_paths = []
        for stage in ("pre", "post"):
            for ext in (".py", ".sh"):
                base = HOOKS_PRE_DIR if stage == "pre" else HOOKS_POST_DIR
                path = os.path.join(base, name + ext)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                        removed_paths.append(path)
                    except OSError as exc:
                        return {"error": f"Impossibile eliminare il file '{path}': {exc}"}
        if removed_paths:
            return {"status": "deleted_file", "name": name, "paths": removed_paths}
        return {"error": f"Hook '{name}' non trovato (né runtime né su disco)"}

    return {"status": "deleted", "name": name}


def _hooks_test(name: str = "", payload: dict | None = None, **kwargs) -> dict:
    """
    Testa un hook con un payload di esempio e restituisce la risposta.

    Parametri:
        name    - Nome dell'hook da testare
        payload - Payload JSON di esempio (opzionale; usa default se assente)
    """
    if not name:
        return {"error": "Parametro 'name' obbligatorio"}

    default_payload = {
        "tool": "nmap_scan",
        "args": {"target": "192.168.1.1", "ports": "1-1024"},
        "session_id": "test-session-000",
    }
    test_payload = payload if isinstance(payload, dict) else default_payload

    # Cerca built-in
    if name in _BUILTIN_HOOKS:
        hdef = _BUILTIN_HOOKS[name]
        stage = hdef.get("stage")
        try:
            if stage in ("pre", "both"):
                fn = hdef.get("fn_pre")
                resp = fn(
                    tool=test_payload.get("tool", "test_tool"),
                    args=test_payload.get("args", {}),
                    session_id=test_payload.get("session_id", "test"),
                ) if callable(fn) else {"action": "allow"}
            else:
                fn = hdef.get("fn_post")
                resp = fn(
                    tool=test_payload.get("tool", "test_tool"),
                    args=test_payload.get("args", {}),
                    result=test_payload.get("result", "test result"),
                    session_id=test_payload.get("session_id", "test"),
                ) if callable(fn) else {"action": "passthrough"}
            return {"hook": name, "type": "builtin", "payload": test_payload, "response": resp}
        except Exception as exc:  # noqa: BLE001
            return {"hook": name, "type": "builtin", "error": str(exc)}

    # Cerca runtime
    with _runtime_hooks_lock:
        hook_def = _runtime_hooks.get(name)
    if hook_def:
        resp = _run_runtime_hook({"name": name, **hook_def}, test_payload)
        return {"hook": name, "type": "runtime", "payload": test_payload, "response": resp}

    # Cerca su disco
    for stage in ("pre", "post"):
        for fh in _load_file_hooks(stage):
            if fh["name"] == name:
                resp = _run_file_hook(fh, test_payload)
                return {
                    "hook": name,
                    "type": "file",
                    "path": fh["path"],
                    "payload": test_payload,
                    "response": resp,
                }

    return {"error": f"Hook '{name}' non trovato"}


def _hooks_get_audit_log(
    limit: int = 50,
    tool_filter: str = "",
    **kwargs,
) -> dict:
    """
    Legge gli ultimi N eventi dal log di audit.

    Parametri:
        limit       - Numero massimo di eventi da restituire (default 50)
        tool_filter - Filtra per nome tool esatto (opzionale)
    """
    if not os.path.isfile(AUDIT_LOG_PATH):
        return {
            "events": [],
            "total_returned": 0,
            "log_path": AUDIT_LOG_PATH,
            "message": "Il file di audit non esiste ancora (nessun tool chiamato).",
        }

    lines: list[str] = []
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return {"error": f"Impossibile leggere il log: {exc}", "log_path": AUDIT_LOG_PATH}

    events: list[dict] = []
    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if tool_filter and entry.get("tool") != tool_filter:
            continue
        events.append(entry)

    # Ultimi N eventi
    tail = events[-limit:] if limit > 0 else events
    return {
        "events": tail,
        "total_in_log": len(events),
        "total_returned": len(tail),
        "log_path": AUDIT_LOG_PATH,
        "filter_applied": tool_filter or None,
    }


# ---------------------------------------------------------------------------
# Definizione TOOLS (formato ARGOS)
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "hooks_list": {
        "fn": _hooks_list,
        "description": (
            "Elenca tutti gli hook attivi: built-in (audit_log, rate_limiter, "
            "dangerous_tool_gate), hook da file in /opt/argos/hooks/ e hook "
            "registrati a runtime."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "hooks_register": {
        "fn": _hooks_register,
        "description": (
            "Registra un nuovo hook Python runtime. "
            "Il codice deve definire 'def run(payload: dict) -> dict'. "
            "Pre-hook: restituisce {action: allow|deny|rewrite, ...}. "
            "Post-hook: restituisce {action: passthrough|transform, result: ...}."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nome univoco dell'hook (es. 'my_filter')",
                },
                "stage": {
                    "type": "string",
                    "description": "'pre' per eseguire prima del tool, 'post' per dopo",
                    "enum": ["pre", "post"],
                },
                "code": {
                    "type": "string",
                    "description": (
                        "Codice Python dell'hook. "
                        "Deve contenere: def run(payload: dict) -> dict"
                    ),
                },
                "tool_pattern": {
                    "type": "string",
                    "description": (
                        "Glob pattern dei tool a cui si applica l'hook. "
                        "Es: '*' per tutti, 'nmap_*' per tutti gli nmap tool."
                    ),
                },
            },
            "required": ["name", "stage", "code"],
        },
    },
    "hooks_delete": {
        "fn": _hooks_delete,
        "description": (
            "Elimina un hook per nome. "
            "Rimuove hook runtime (registrati con hooks_register) "
            "oppure file script da disco. "
            "Gli hook built-in non possono essere eliminati."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nome dell'hook da eliminare",
                },
            },
            "required": ["name"],
        },
    },
    "hooks_test": {
        "fn": _hooks_test,
        "description": (
            "Testa un hook con un payload di esempio e restituisce la risposta. "
            "Utile per verificare il comportamento di un hook senza eseguire tool reali."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nome dell'hook da testare",
                },
                "payload": {
                    "type": "object",
                    "description": (
                        "Payload JSON di test. "
                        "Struttura: {tool, args, session_id} per pre-hook; "
                        "{tool, args, result, session_id} per post-hook. "
                        "Se omesso usa un payload di default con nmap_scan."
                    ),
                },
            },
            "required": ["name"],
        },
    },
    "hooks_get_audit_log": {
        "fn": _hooks_get_audit_log,
        "description": (
            f"Legge gli ultimi N eventi dal log di audit ({AUDIT_LOG_PATH}). "
            "Ogni entry contiene: timestamp, stage (pre/post), tool, session_id."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Numero massimo di eventi da restituire (default 50)",
                },
                "tool_filter": {
                    "type": "string",
                    "description": "Filtra gli eventi per nome tool esatto (opzionale)",
                },
            },
            "required": [],
        },
    },
}
