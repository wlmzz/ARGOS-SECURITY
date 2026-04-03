"""
ARGOS Plugin: Claw Features
============================
Feature dal progetto Claw Code integrate in ARGOS:
  - Token tracking e costo stimato per sessione
  - Session compaction (tenere solo gli ultimi N messaggi)
  - Permission mode check (readonly / workspace_write / danger_full_access)
  - Parity audit tool ARGOS vs baseline
  - Stima costo agente prima dell'esecuzione
  - Lista sessioni salvate

Directory sessioni: /opt/argos/agent/sessions/
Baseline parity:    /opt/argos/configs/parity_baseline.json

Dipendenze: solo stdlib Python.
"""

import json
import os
import time
from typing import Any

# ---------------------------------------------------------------------------
# Manifest del plugin
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "claw_features",
    "name": "Claw Features",
    "version": "1.0.0",
    "description": (
        "Feature ispirate a Claw Code: token tracking, session compaction, "
        "permission mode check, parity audit, cost estimation, session list."
    ),
    "author": "ARGOS",
    "requires": [],
}

# ---------------------------------------------------------------------------
# Costanti e percorsi
# ---------------------------------------------------------------------------
SESSIONS_DIR = "/opt/argos/agent/sessions"
PARITY_BASELINE_PATH = "/opt/argos/configs/parity_baseline.json"

# Prezzi Anthropic API (USD per 1M token) — aggiornare se cambiano
_CLAUDE_INPUT_PRICE_PER_1M = 3.00   # claude-3.5-sonnet
_CLAUDE_OUTPUT_PRICE_PER_1M = 15.00

# Modello locale — nessun costo, ma stima tempo di elaborazione
_LOCAL_MODEL_TOKENS_PER_SEC = 40  # stima: 40 token/s su hardware tipico server

# ---------------------------------------------------------------------------
# Permission modes
# ---------------------------------------------------------------------------

# Tool bloccati per ciascun mode
_READONLY_BLOCKED = frozenset([
    "bash",
    "ban_ip",
    "unban_ip",
    "auto_harden",
    "harden_ssh",
    "setup_ufw",
    "run_pentest_pipeline",
    "nuclei_scan",
    "masscan_scan",
])

_WORKSPACE_WRITE_BLOCKED = frozenset([
    "auto_harden",
    "harden_ssh",
])

# danger_full_access: nessun blocco
_VALID_MODES = ("readonly", "workspace_write", "danger_full_access")


# ---------------------------------------------------------------------------
# Helper: stima token da testo
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """
    Stima approssimativa del numero di token.
    Formula: len(text.split()) * 1.3  (media empirica per testo misto EN/IT)
    """
    if not text:
        return 0
    return int(len(text.split()) * 1.3)


# ---------------------------------------------------------------------------
# Helper: assicura directory sessioni
# ---------------------------------------------------------------------------

def _ensure_sessions_dir() -> None:
    try:
        os.makedirs(SESSIONS_DIR, exist_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Helper: leggi file sessione JSONL
# ---------------------------------------------------------------------------

def _read_session_file(session_id: str) -> list[dict]:
    """
    Carica i messaggi da /opt/argos/agent/sessions/{session_id}.jsonl.
    Ogni riga è un dict JSON. Restituisce lista vuota se il file non esiste.
    """
    path = os.path.join(SESSIONS_DIR, f"{session_id}.jsonl")
    if not os.path.isfile(path):
        return []
    messages: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    messages.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return messages


def _write_session_file(session_id: str, messages: list[dict]) -> bool:
    """
    Sovrascrive il file sessione con la lista di messaggi fornita.
    Restituisce True se operazione riuscita.
    """
    _ensure_sessions_dir()
    path = os.path.join(SESSIONS_DIR, f"{session_id}.jsonl")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for msg in messages:
                fh.write(json.dumps(msg, ensure_ascii=False) + "\n")
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Implementazione tool: session_token_usage
# ---------------------------------------------------------------------------

def _session_token_usage(session_id: str = "", **kwargs) -> dict:
    """
    Mostra i token usati nella sessione corrente con stima del costo USD.

    La sessione viene letta da /opt/argos/agent/sessions/{session_id}.jsonl.
    Ogni riga del file deve essere un dict con campo "role" ("user"/"assistant")
    e "content" (stringa o lista di parti).
    """
    if not session_id:
        return {"error": "Parametro 'session_id' obbligatorio"}

    messages = _read_session_file(session_id)
    if not messages:
        path = os.path.join(SESSIONS_DIR, f"{session_id}.jsonl")
        return {
            "session_id": session_id,
            "message_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost_usd": 0.0,
            "note": f"Sessione non trovata o vuota ({path})",
        }

    input_tokens = 0
    output_tokens = 0

    for msg in messages:
        content = msg.get("content", "")
        # Il content può essere stringa o lista di parti (multimodal)
        if isinstance(content, list):
            text = " ".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        else:
            text = str(content)

        tokens = _estimate_tokens(text)
        role = msg.get("role", "user")
        if role == "assistant":
            output_tokens += tokens
        else:
            # user + system + tool_result
            input_tokens += tokens

    total = input_tokens + output_tokens
    cost_usd = (
        (input_tokens / 1_000_000) * _CLAUDE_INPUT_PRICE_PER_1M
        + (output_tokens / 1_000_000) * _CLAUDE_OUTPUT_PRICE_PER_1M
    )

    return {
        "session_id": session_id,
        "message_count": len(messages),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total,
        "estimated_cost_usd": round(cost_usd, 6),
        "pricing_note": (
            f"Prezzi Claude API: input ${_CLAUDE_INPUT_PRICE_PER_1M}/1M tok, "
            f"output ${_CLAUDE_OUTPUT_PRICE_PER_1M}/1M tok. "
            "Stima token: words * 1.3."
        ),
    }


# ---------------------------------------------------------------------------
# Implementazione tool: session_compact
# ---------------------------------------------------------------------------

def _session_compact(
    session_id: str = "",
    keep_last: int = 10,
    **kwargs,
) -> dict:
    """
    Compatta la sessione mantenendo solo gli ultimi keep_last messaggi.
    I messaggi rimossi vengono riassunti e salvati come entry speciale "compaction_summary".

    Parametri:
        session_id - ID della sessione da compattare
        keep_last  - Numero di messaggi recenti da mantenere (default 10)
    """
    if not session_id:
        return {"error": "Parametro 'session_id' obbligatorio"}
    if keep_last < 1:
        return {"error": "Il parametro 'keep_last' deve essere >= 1"}

    messages = _read_session_file(session_id)
    total_before = len(messages)

    if total_before <= keep_last:
        return {
            "session_id": session_id,
            "status": "no_compaction_needed",
            "messages_before": total_before,
            "messages_after": total_before,
            "messages_removed": 0,
            "tokens_saved_estimate": 0,
        }

    removed = messages[:-keep_last]
    kept = messages[-keep_last:]
    messages_removed = len(removed)

    # Stima token rimossi
    tokens_saved = 0
    for msg in removed:
        content = msg.get("content", "")
        if isinstance(content, list):
            text = " ".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        else:
            text = str(content)
        tokens_saved += _estimate_tokens(text)

    # Crea summary entry dei messaggi rimossi
    summary_roles = {}
    for msg in removed:
        role = msg.get("role", "unknown")
        summary_roles[role] = summary_roles.get(role, 0) + 1

    compaction_entry = {
        "role": "system",
        "content": (
            f"[COMPACTION SUMMARY] {messages_removed} messaggi rimossi durante la compattazione. "
            f"Distribuzione ruoli: {summary_roles}. "
            f"Token stimati rimossi: {tokens_saved}. "
            f"Timestamp compattazione: {time.time():.0f}."
        ),
        "compaction": True,
        "compacted_at": time.time(),
        "messages_removed": messages_removed,
        "tokens_removed_estimate": tokens_saved,
    }

    # Scrivi: summary + messaggi mantenuti
    new_messages = [compaction_entry] + kept
    ok = _write_session_file(session_id, new_messages)
    if not ok:
        return {
            "error": f"Impossibile scrivere il file sessione per '{session_id}'",
            "session_id": session_id,
        }

    return {
        "session_id": session_id,
        "status": "compacted",
        "messages_before": total_before,
        "messages_after": len(new_messages),
        "messages_removed": messages_removed,
        "tokens_saved_estimate": tokens_saved,
        "compaction_summary_saved": True,
    }


# ---------------------------------------------------------------------------
# Implementazione tool: permission_check
# ---------------------------------------------------------------------------

def _permission_check(
    tool_name: str = "",
    mode: str = "readonly",
    **kwargs,
) -> dict:
    """
    Controlla se un tool è permesso nel permission mode indicato.

    Modi disponibili:
      readonly          — solo lettura/OSINT; blocca tool che modificano il sistema
      workspace_write   — tutto tranne hardening di sistema
      danger_full_access — nessun blocco

    Parametri:
        tool_name - Nome del tool da controllare
        mode      - Permission mode da applicare
    """
    if not tool_name:
        return {"error": "Parametro 'tool_name' obbligatorio"}
    if mode not in _VALID_MODES:
        return {
            "error": f"Mode '{mode}' non valido. Valori accettati: {_VALID_MODES}",
        }

    if mode == "danger_full_access":
        return {
            "tool_name": tool_name,
            "mode": mode,
            "allowed": True,
            "reason": "danger_full_access: nessuna restrizione attiva.",
        }

    if mode == "readonly":
        if tool_name in _READONLY_BLOCKED:
            return {
                "tool_name": tool_name,
                "mode": mode,
                "allowed": False,
                "reason": (
                    f"'{tool_name}' non è permesso in modalità readonly. "
                    "Questa modalità consente solo operazioni di lettura e OSINT."
                ),
                "blocked_tools": sorted(_READONLY_BLOCKED),
            }
        return {
            "tool_name": tool_name,
            "mode": mode,
            "allowed": True,
            "reason": f"'{tool_name}' è consentito in modalità readonly.",
        }

    if mode == "workspace_write":
        if tool_name in _WORKSPACE_WRITE_BLOCKED:
            return {
                "tool_name": tool_name,
                "mode": mode,
                "allowed": False,
                "reason": (
                    f"'{tool_name}' non è permesso in modalità workspace_write. "
                    "Questa modalità blocca le operazioni di hardening di sistema."
                ),
                "blocked_tools": sorted(_WORKSPACE_WRITE_BLOCKED),
            }
        return {
            "tool_name": tool_name,
            "mode": mode,
            "allowed": True,
            "reason": f"'{tool_name}' è consentito in modalità workspace_write.",
        }

    # Fallback (non raggiungibile con validazione sopra)
    return {"tool_name": tool_name, "mode": mode, "allowed": False, "reason": "Mode sconosciuto"}


# ---------------------------------------------------------------------------
# Implementazione tool: parity_audit
# ---------------------------------------------------------------------------

def _parity_audit(registry: dict | None = None, **kwargs) -> dict:
    """
    Audit di tutti i tool ARGOS vs una baseline salvata.

    Parametri:
        registry - Dizionario {tool_name: {...}} dei tool ARGOS correnti.
                   Se non fornito, tenta di importare i tool dall'agent principale
                   (fallback: restituisce solo statistiche dalla baseline).

    Il report contiene:
      - total_tools: totale tool correnti
      - by_plugin: tool raggruppati per plugin/categoria
      - new_since_baseline: tool non presenti nella baseline
      - missing_from_baseline: tool nella baseline ma non più presenti
      - baseline_path: percorso della baseline
    """
    # Costruisci dizionario tool correnti
    current_tools: dict[str, Any] = {}

    if registry and isinstance(registry, dict):
        current_tools = registry
    else:
        # Tenta auto-discovery dai plugin nella stessa directory
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        for fname in os.listdir(plugin_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            module_name = fname[:-3]
            plugin_path = os.path.join(plugin_dir, fname)
            try:
                import importlib.util as _ilu
                spec = _ilu.spec_from_file_location(module_name, plugin_path)
                if spec is None or spec.loader is None:
                    continue
                mod = _ilu.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
                plugin_tools = getattr(mod, "TOOLS", None)
                if isinstance(plugin_tools, dict):
                    for tname, tdef in plugin_tools.items():
                        current_tools[tname] = {
                            "_plugin": module_name,
                            "description": tdef.get("description", ""),
                        }
            except Exception:  # noqa: BLE001
                pass

    # Raggruppa per plugin
    by_plugin: dict[str, list[str]] = {}
    for tname, tdef in current_tools.items():
        plugin = (
            tdef.get("_plugin", "unknown")
            if isinstance(tdef, dict)
            else "unknown"
        )
        by_plugin.setdefault(plugin, []).append(tname)

    total_tools = len(current_tools)
    current_set = set(current_tools.keys())

    # Leggi baseline
    baseline: dict[str, Any] = {}
    baseline_exists = os.path.isfile(PARITY_BASELINE_PATH)
    if baseline_exists:
        try:
            with open(PARITY_BASELINE_PATH, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            baseline = {"_load_error": str(exc)}

    baseline_tools_set = set(baseline.get("tools", {}).keys() if "tools" in baseline else [])

    new_since_baseline = sorted(current_set - baseline_tools_set)
    missing_from_baseline = sorted(baseline_tools_set - current_set)

    report = {
        "total_tools": total_tools,
        "by_plugin": {k: sorted(v) for k, v in sorted(by_plugin.items())},
        "new_since_baseline": new_since_baseline,
        "missing_from_baseline": missing_from_baseline,
        "baseline_path": PARITY_BASELINE_PATH,
        "baseline_exists": baseline_exists,
        "baseline_tool_count": len(baseline_tools_set),
    }

    if "_load_error" in baseline:
        report["baseline_load_error"] = baseline["_load_error"]

    return report


# ---------------------------------------------------------------------------
# Implementazione tool: agent_cost_estimate
# ---------------------------------------------------------------------------

# Modelli riconosciuti e loro caratteristiche
_MODEL_PROFILES: dict[str, dict] = {
    # Modello locale ARGOS
    "seneca-32b": {
        "local": True,
        "cost_per_1m_input": 0.0,
        "cost_per_1m_output": 0.0,
        "tokens_per_sec": _LOCAL_MODEL_TOKENS_PER_SEC,
    },
    "seneca-7b": {
        "local": True,
        "cost_per_1m_input": 0.0,
        "cost_per_1m_output": 0.0,
        "tokens_per_sec": 80,
    },
    # Claude via API (escalation)
    "claude-3-5-sonnet": {
        "local": False,
        "cost_per_1m_input": 3.00,
        "cost_per_1m_output": 15.00,
        "tokens_per_sec": 150,
    },
    "claude-3-5-haiku": {
        "local": False,
        "cost_per_1m_input": 0.80,
        "cost_per_1m_output": 4.00,
        "tokens_per_sec": 200,
    },
    "claude-opus-4": {
        "local": False,
        "cost_per_1m_input": 15.00,
        "cost_per_1m_output": 75.00,
        "tokens_per_sec": 80,
    },
}

# Stima empirica: parole nel task_description → numero di tool calls
_WORDS_PER_TOOL_CALL = 8  # es. "scan 1000 hosts" → ~3 chiamate nmap + 1 summary
# Token per turn di contesto medio
_TOKENS_PER_TURN_INPUT = 800
_TOKENS_PER_TURN_OUTPUT = 400


def _agent_cost_estimate(
    task_description: str = "",
    model: str = "seneca-32b",
    **kwargs,
) -> dict:
    """
    Stima il costo e la durata di un'operazione agente prima di eseguirla.

    Parametri:
        task_description - Descrizione testuale del task
        model            - Modello da usare (seneca-32b, claude-3-5-sonnet, ecc.)

    Restituisce:
        - estimated_tool_calls: numero stimato di tool calls
        - estimated_input_tokens / estimated_output_tokens
        - estimated_duration_minutes
        - estimated_cost_usd (0.0 per modelli locali)
    """
    if not task_description:
        return {"error": "Parametro 'task_description' obbligatorio"}

    # Normalizza nome modello (case-insensitive, alias comuni)
    model_key = model.lower().strip()
    # Alias
    _aliases = {
        "sonnet": "claude-3-5-sonnet",
        "haiku": "claude-3-5-haiku",
        "opus": "claude-opus-4",
    }
    model_key = _aliases.get(model_key, model_key)

    profile = _MODEL_PROFILES.get(model_key)
    if profile is None:
        # Modello sconosciuto — usa profilo generico claude
        profile = {
            "local": False,
            "cost_per_1m_input": _CLAUDE_INPUT_PRICE_PER_1M,
            "cost_per_1m_output": _CLAUDE_OUTPUT_PRICE_PER_1M,
            "tokens_per_sec": 100,
        }
        model_note = f"Modello '{model}' non nel registro. Usando prezzi Claude default."
    else:
        model_note = None

    word_count = len(task_description.split())
    # Stima tool calls: ogni N parole → 1 tool call, minimo 1
    estimated_tool_calls = max(1, word_count // _WORDS_PER_TOOL_CALL)

    # Token stimati: ogni tool call genera 1 turno input + 1 turno output
    input_tokens = estimated_tool_calls * _TOKENS_PER_TURN_INPUT
    output_tokens = estimated_tool_calls * _TOKENS_PER_TURN_OUTPUT
    total_tokens = input_tokens + output_tokens

    # Durata: tokens / (tokens/sec) → secondi → minuti
    tps = profile.get("tokens_per_sec", 100)
    duration_sec = total_tokens / tps
    duration_min = round(duration_sec / 60, 2)

    # Costo
    cost_usd = (
        (input_tokens / 1_000_000) * profile["cost_per_1m_input"]
        + (output_tokens / 1_000_000) * profile["cost_per_1m_output"]
    )

    result: dict[str, Any] = {
        "task_description": task_description,
        "model": model,
        "model_type": "local" if profile["local"] else "api",
        "estimated_tool_calls": estimated_tool_calls,
        "estimated_input_tokens": input_tokens,
        "estimated_output_tokens": output_tokens,
        "estimated_total_tokens": total_tokens,
        "estimated_duration_minutes": duration_min,
        "estimated_cost_usd": round(cost_usd, 6),
    }

    if profile["local"]:
        result["cost_note"] = (
            f"Modello locale {model}: costo $0.00. "
            f"Stima tempo: {duration_min} min a ~{tps} tok/s."
        )
    else:
        result["cost_note"] = (
            f"Modello API {model}: "
            f"input ${profile['cost_per_1m_input']}/1M tok, "
            f"output ${profile['cost_per_1m_output']}/1M tok."
        )

    if model_note:
        result["model_note"] = model_note

    return result


# ---------------------------------------------------------------------------
# Implementazione tool: session_list
# ---------------------------------------------------------------------------

def _session_list(**kwargs) -> dict:
    """
    Elenca tutte le sessioni salvate in SESSIONS_DIR con statistiche per ciascuna.

    Per ogni sessione restituisce:
        id, message_count, last_access (epoch), token_estimate, path
    """
    _ensure_sessions_dir()

    if not os.path.isdir(SESSIONS_DIR):
        return {
            "sessions": [],
            "total": 0,
            "sessions_dir": SESSIONS_DIR,
            "message": "Directory sessioni non trovata.",
        }

    sessions: list[dict] = []
    try:
        entries = os.listdir(SESSIONS_DIR)
    except OSError as exc:
        return {"error": f"Impossibile leggere la directory sessioni: {exc}"}

    for fname in sorted(entries):
        if not fname.endswith(".jsonl"):
            continue
        session_id = fname[:-6]  # rimuove ".jsonl"
        path = os.path.join(SESSIONS_DIR, fname)

        try:
            stat = os.stat(path)
            last_access = stat.st_mtime
            file_size_bytes = stat.st_size
        except OSError:
            last_access = 0.0
            file_size_bytes = 0

        messages = _read_session_file(session_id)
        msg_count = len(messages)

        # Stima token totali della sessione
        total_tokens = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                text = " ".join(
                    part.get("text", "") if isinstance(part, dict) else str(part)
                    for part in content
                )
            else:
                text = str(content)
            total_tokens += _estimate_tokens(text)

        # Conta messaggi per ruolo
        roles: dict[str, int] = {}
        for msg in messages:
            role = msg.get("role", "unknown")
            roles[role] = roles.get(role, 0) + 1

        sessions.append({
            "id": session_id,
            "path": path,
            "message_count": msg_count,
            "last_access": last_access,
            "last_access_human": _format_epoch(last_access),
            "token_estimate": total_tokens,
            "file_size_bytes": file_size_bytes,
            "roles": roles,
        })

    # Ordina per last_access decrescente (più recente prima)
    sessions.sort(key=lambda s: s["last_access"], reverse=True)

    return {
        "sessions": sessions,
        "total": len(sessions),
        "sessions_dir": SESSIONS_DIR,
    }


def _format_epoch(ts: float) -> str:
    """Converte un epoch float in stringa ISO 8601 senza dipendenze esterne."""
    if ts <= 0:
        return "unknown"
    import datetime
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return str(ts)


# ---------------------------------------------------------------------------
# Definizione TOOLS (formato ARGOS)
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "session_token_usage": {
        "fn": _session_token_usage,
        "description": (
            "Mostra il numero di token usati nella sessione (input/output/totale) "
            "e il costo stimato in USD ai prezzi API Anthropic. "
            f"Legge da {SESSIONS_DIR}/{{session_id}}.jsonl."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "ID della sessione (es. 'abc123')",
                },
            },
            "required": ["session_id"],
        },
    },
    "session_compact": {
        "fn": _session_compact,
        "description": (
            "Compatta la sessione mantenendo solo gli ultimi N messaggi. "
            "I messaggi rimossi vengono riassunti in una entry 'compaction_summary'. "
            "Restituisce: messaggi rimossi, token risparmiati stimati."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "ID della sessione da compattare",
                },
                "keep_last": {
                    "type": "integer",
                    "description": "Numero di messaggi recenti da mantenere (default 10)",
                },
            },
            "required": ["session_id"],
        },
    },
    "permission_check": {
        "fn": _permission_check,
        "description": (
            "Controlla se un tool è permesso in un dato permission mode. "
            "Modi: readonly (solo lettura/OSINT), "
            "workspace_write (tutto tranne hardening di sistema), "
            "danger_full_access (nessun blocco). "
            "Esempio: permission_check(tool_name='bash', mode='readonly') "
            "→ {allowed: false, reason: '...'}."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "Nome del tool da verificare (es. 'bash', 'nmap_scan')",
                },
                "mode": {
                    "type": "string",
                    "description": "Permission mode da applicare",
                    "enum": list(_VALID_MODES),
                },
            },
            "required": ["tool_name", "mode"],
        },
    },
    "parity_audit": {
        "fn": _parity_audit,
        "description": (
            "Audit di tutti i tool ARGOS rispetto a una baseline. "
            "Conta tool totali, raggruppa per plugin, identifica "
            "tool nuovi (non in baseline) e tool mancanti (in baseline ma rimossi). "
            f"Baseline: {PARITY_BASELINE_PATH}."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "registry": {
                    "type": "object",
                    "description": (
                        "Dizionario tool correnti {tool_name: {...}} (opzionale). "
                        "Se omesso, i tool vengono scoperti automaticamente dai plugin."
                    ),
                },
            },
            "required": [],
        },
    },
    "agent_cost_estimate": {
        "fn": _agent_cost_estimate,
        "description": (
            "Stima il costo e la durata di un'operazione agente PRIMA di eseguirla. "
            "Per modelli locali (seneca-32b) stima solo il tempo. "
            "Per Claude API stima il costo in USD. "
            "Modelli supportati: seneca-32b, seneca-7b, "
            "claude-3-5-sonnet, claude-3-5-haiku, claude-opus-4."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task_description": {
                    "type": "string",
                    "description": "Descrizione testuale del task da eseguire (es. 'scan 1000 hosts with nmap')",
                },
                "model": {
                    "type": "string",
                    "description": (
                        "Modello da usare per la stima. "
                        "Default: 'seneca-32b' (modello locale, costo $0)."
                    ),
                },
            },
            "required": ["task_description"],
        },
    },
    "session_list": {
        "fn": _session_list,
        "description": (
            f"Elenca tutte le sessioni salvate in {SESSIONS_DIR}. "
            "Per ogni sessione: id, numero messaggi, ultimo accesso, "
            "stima token, dimensione file."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}
