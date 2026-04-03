"""
ARGOS Plugin: SQLMap
Automazione di SQL injection testing tramite sqlmap.

USO AUTORIZZATO: solo per pentest, CTF e security research con permesso esplicito.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "sqlmap",
    "name": "SQLMap",
    "description": (
        "Automazione di SQL injection testing tramite sqlmap. "
        "Rileva vulnerabilità SQLi, enumera database e tabelle, "
        "estrae dati e tenta di ottenere OS shell su target vulnerabili. "
        "Richiede sqlmap installato (pip install sqlmap o apt install sqlmap). "
        "USO AUTORIZZATO: solo per pentest, CTF e security research."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SQLMAP_BIN = "sqlmap"
_DEFAULT_OUTPUT_DIR = "/tmp/sqlmap_out"


def _tool_installed() -> bool:
    return shutil.which(_SQLMAP_BIN) is not None


def _not_installed_error() -> dict:
    return {
        "error": (
            "sqlmap not installed. "
            "Install: pip install sqlmap  OR  sudo apt install sqlmap  OR  "
            "see https://sqlmap.org"
        )
    }


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    """Esegue sqlmap catturando stdout/stderr."""
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=True,
        text=True,
    )


def _build_base_cmd(
    url: str,
    output_dir: str,
    data: str = "",
    method: str = "GET",
    dbms: str = "",
    cookies: str = "",
    headers: str = "",
    level: int = 1,
    risk: int = 1,
) -> list[str]:
    """Costruisce il comando sqlmap di base con opzioni comuni."""
    cmd = [
        _SQLMAP_BIN,
        "-u", url,
        "--batch",
        "--output-dir", output_dir,
        f"--level={level}",
        f"--risk={risk}",
    ]
    if data:
        cmd += ["--data", data]
        if method.upper() == "POST":
            cmd += ["--method", "POST"]
    if dbms:
        cmd += ["--dbms", dbms]
    if cookies:
        cmd += ["--cookie", cookies]
    if headers:
        # headers come "Header1: val1\nHeader2: val2"
        for hdr in headers.splitlines():
            hdr = hdr.strip()
            if hdr:
                cmd += ["--headers", hdr]
    return cmd


def _parse_session_json(output_dir: str, url: str) -> dict[str, Any]:
    """
    Legge il file JSON di output generato da sqlmap nella directory di sessione.
    sqlmap scrive in <output_dir>/<hostname>/session.sqlite e log/,
    ma con --format=json scrive anche un report JSON.
    Questa funzione prova a leggere i file .json trovati nell'output_dir.
    """
    result: dict[str, Any] = {
        "vulnerable": False,
        "injection_points": [],
        "dbms": "",
        "techniques": [],
    }

    out_path = Path(output_dir)
    if not out_path.exists():
        return result

    # Cerca eventuali file JSON nelle sottocartelle
    for json_file in out_path.rglob("*.json"):
        try:
            data = json.loads(json_file.read_text(errors="replace"))
            if isinstance(data, dict):
                # Struttura tipica del report JSON di sqlmap
                for target_url, target_data in data.items():
                    if not isinstance(target_data, dict):
                        continue
                    data_inner = target_data.get("data", {})
                    if data_inner:
                        result["vulnerable"] = True
                        for place, params in data_inner.items():
                            if isinstance(params, dict):
                                for param_name, param_data in params.items():
                                    injection = {
                                        "place": place,
                                        "parameter": param_name,
                                        "type": param_data.get("type", ""),
                                        "title": param_data.get("title", ""),
                                        "payload": param_data.get("payload", ""),
                                    }
                                    result["injection_points"].append(injection)
                                    techs = param_data.get("data", {})
                                    for tech in techs.values():
                                        t_name = tech.get("title", "")
                                        if t_name and t_name not in result["techniques"]:
                                            result["techniques"].append(t_name)
                    dbms_info = target_data.get("dbms", "")
                    if dbms_info and not result["dbms"]:
                        result["dbms"] = dbms_info
        except Exception:
            continue

    return result


def _parse_stdout_for_dbs(stdout: str) -> list[str]:
    """Estrae nomi database dall'output testuale di sqlmap --dbs."""
    databases = []
    in_block = False
    for line in stdout.splitlines():
        line = line.strip()
        if "available databases" in line.lower():
            in_block = True
            continue
        if in_block:
            # Le righe con db hanno formato "[*] dbname" o "| dbname |"
            m = re.match(r"^\[[\*\d]+\]\s+(.+)$", line)
            if m:
                databases.append(m.group(1).strip())
            elif line.startswith("|") and "|" in line[1:]:
                val = line.strip("|").strip()
                if val and "database" not in val.lower():
                    databases.append(val)
            elif line == "" or line.startswith("["):
                if databases:
                    in_block = False
    return databases


def _parse_stdout_for_tables(stdout: str, db: str) -> list[str]:
    """Estrae nomi tabelle dall'output testuale di sqlmap --tables."""
    tables = []
    in_block = False
    for line in stdout.splitlines():
        line = line.strip()
        if f"database: {db}" in line.lower() or "tables" in line.lower():
            in_block = True
            continue
        if in_block:
            m = re.match(r"^\[[\*\d]+\]\s+(.+)$", line)
            if m:
                tables.append(m.group(1).strip())
            elif line.startswith("|") and "|" in line[1:]:
                val = line.strip("|").strip()
                if val and "table" not in val.lower():
                    tables.append(val)
            elif line == "" and tables:
                break
    return tables


def _parse_stdout_for_dump(stdout: str) -> list[dict]:
    """
    Estrae righe di dati dal dump testuale di sqlmap.
    Il formato tipico è una tabella ASCII con header e righe pipe-separated.
    """
    rows = []
    headers: list[str] = []
    in_table = False

    for line in stdout.splitlines():
        line_stripped = line.strip()
        # Rileva separatore orizzontale  "+---+---+"
        if re.match(r"^\+-+", line_stripped):
            in_table = True
            continue
        if in_table and line_stripped.startswith("|"):
            cells = [c.strip() for c in line_stripped.strip("|").split("|")]
            if not headers:
                headers = cells
            else:
                if len(cells) == len(headers):
                    rows.append(dict(zip(headers, cells)))
    return rows


def _parse_stdout_for_dbms(stdout: str) -> str:
    """Estrae il nome del DBMS dall'output di sqlmap."""
    for line in stdout.splitlines():
        m = re.search(r"back-end DBMS:\s+(.+)", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def sqlmap_scan(
    url: str,
    data: str = "",
    method: str = "GET",
    level: int = 1,
    risk: int = 1,
    dbms: str = "",
    cookies: str = "",
    headers: str = "",
    timeout: int = 60,
) -> dict:
    """
    Esegue una scansione SQLi di base sull'URL target.

    Args:
        url:     URL target (es. "http://target/page.php?id=1")
        data:    Dati POST (es. "user=foo&pass=bar")
        method:  Metodo HTTP (GET o POST)
        level:   Profondità di test 1-5 (default: 1)
        risk:    Livello di rischio 1-3 (default: 1)
        dbms:    DBMS da forzare (es. "mysql", "postgresql")
        cookies: Cookie di sessione (es. "PHPSESSID=abc123")
        headers: Header HTTP aggiuntivi (uno per riga)
        timeout: Timeout in secondi per il processo (default: 60)

    Returns:
        {"vulnerable": bool, "injection_points": list, "dbms": str, "techniques": list}
    """
    if not _tool_installed():
        return _not_installed_error()

    output_dir = _DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    cmd = _build_base_cmd(
        url, output_dir, data=data, method=method,
        dbms=dbms, cookies=cookies, headers=headers,
        level=level, risk=risk,
    )
    # Aggiunge report JSON
    cmd += ["--format=json", "--flush-session"]

    try:
        proc = _run(cmd, timeout=max(timeout, 120))
        stdout = proc.stdout + proc.stderr

        # Prima prova a parsare il JSON di output
        result = _parse_session_json(output_dir, url)

        # Fallback: analisi testuale
        if not result["vulnerable"]:
            if "is vulnerable" in stdout.lower() or "parameter" in stdout.lower() and "injectable" in stdout.lower():
                result["vulnerable"] = True

        if not result["dbms"]:
            result["dbms"] = _parse_stdout_for_dbms(stdout)

        if not result["techniques"]:
            for tech in ["boolean-based blind", "time-based blind", "error-based",
                         "union query", "stacked queries", "inline queries"]:
                if tech in stdout.lower():
                    result["techniques"].append(tech)

        return result
    except subprocess.TimeoutExpired:
        return {"error": f"sqlmap timed out after {timeout}s", "vulnerable": False,
                "injection_points": [], "dbms": "", "techniques": []}
    except Exception as exc:
        return {"error": str(exc), "vulnerable": False,
                "injection_points": [], "dbms": "", "techniques": []}


def sqlmap_dbs(
    url: str,
    data: str = "",
    cookies: str = "",
) -> dict:
    """
    Enumera i database presenti sul server target tramite SQL injection.

    Args:
        url:     URL target vulnerabile
        data:    Dati POST opzionali
        cookies: Cookie di sessione opzionali

    Returns:
        {"databases": list[str], "dbms": str}
    """
    if not _tool_installed():
        return _not_installed_error()

    output_dir = _DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    cmd = _build_base_cmd(url, output_dir, data=data, cookies=cookies)
    cmd += ["--dbs"]

    try:
        proc = _run(cmd)
        stdout = proc.stdout + proc.stderr
        databases = _parse_stdout_for_dbs(stdout)
        dbms = _parse_stdout_for_dbms(stdout)
        return {"databases": databases, "dbms": dbms}
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap timed out", "databases": [], "dbms": ""}
    except Exception as exc:
        return {"error": str(exc), "databases": [], "dbms": ""}


def sqlmap_tables(
    url: str,
    db: str,
    data: str = "",
    cookies: str = "",
) -> dict:
    """
    Enumera le tabelle di un database specifico.

    Args:
        url:     URL target vulnerabile
        db:      Nome del database (es. "information_schema", "users_db")
        data:    Dati POST opzionali
        cookies: Cookie di sessione opzionali

    Returns:
        {"database": str, "tables": list[str]}
    """
    if not _tool_installed():
        return _not_installed_error()

    output_dir = _DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    cmd = _build_base_cmd(url, output_dir, data=data, cookies=cookies)
    cmd += ["-D", db, "--tables"]

    try:
        proc = _run(cmd)
        stdout = proc.stdout + proc.stderr
        tables = _parse_stdout_for_tables(stdout, db)
        return {"database": db, "tables": tables}
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap timed out", "database": db, "tables": []}
    except Exception as exc:
        return {"error": str(exc), "database": db, "tables": []}


def sqlmap_dump(
    url: str,
    db: str,
    table: str,
    columns: str = "",
    data: str = "",
    cookies: str = "",
) -> dict:
    """
    Estrae dati da una tabella specifica.

    Args:
        url:     URL target vulnerabile
        db:      Nome del database
        table:   Nome della tabella
        columns: Colonne da estrarre, separate da virgola (es. "username,password")
        data:    Dati POST opzionali
        cookies: Cookie di sessione opzionali

    Returns:
        {"database": str, "table": str, "rows": list[dict], "total": int}
    """
    if not _tool_installed():
        return _not_installed_error()

    output_dir = _DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    cmd = _build_base_cmd(url, output_dir, data=data, cookies=cookies)
    cmd += ["-D", db, "-T", table, "--dump"]
    if columns:
        cmd += ["-C", columns]

    try:
        proc = _run(cmd)
        stdout = proc.stdout + proc.stderr
        rows = _parse_stdout_for_dump(stdout)

        # Cerca anche CSV generati da sqlmap in output_dir
        csv_rows: list[dict] = []
        out_path = Path(output_dir)
        for csv_file in out_path.rglob(f"{table}.csv"):
            try:
                lines = csv_file.read_text(errors="replace").splitlines()
                if lines:
                    hdrs = [h.strip() for h in lines[0].split(",")]
                    for line in lines[1:]:
                        vals = [v.strip() for v in line.split(",")]
                        if len(vals) == len(hdrs):
                            csv_rows.append(dict(zip(hdrs, vals)))
            except Exception:
                pass

        final_rows = csv_rows if csv_rows else rows
        return {"database": db, "table": table, "rows": final_rows, "total": len(final_rows)}
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap timed out", "database": db, "table": table, "rows": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "database": db, "table": table, "rows": [], "total": 0}


def sqlmap_shell(
    url: str,
    data: str = "",
    cookies: str = "",
) -> dict:
    """
    Tenta di ottenere una OS shell tramite SQL injection (--os-shell).

    IMPORTANTE: Solo per uso autorizzato in ambienti di pentest/CTF.
    Richiede che sqlmap riesca a scrivere un file sul server (file privilege).

    Args:
        url:     URL target vulnerabile
        data:    Dati POST opzionali
        cookies: Cookie di sessione opzionali

    Returns:
        {"shell_obtained": bool, "output": str}
    """
    if not _tool_installed():
        return _not_installed_error()

    output_dir = _DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    cmd = _build_base_cmd(url, output_dir, data=data, cookies=cookies)
    # --os-shell in modalità batch non è interattivo; sqlmap tenterà di
    # creare un backdoor e uscirà senza input utente in modalità --batch
    cmd += ["--os-shell", "--batch"]

    try:
        proc = _run(cmd, timeout=120)
        stdout = proc.stdout + proc.stderr

        shell_obtained = (
            "os-shell>" in stdout.lower()
            or "shell prompt" in stdout.lower()
            or "command standard output:" in stdout.lower()
        )

        return {"shell_obtained": shell_obtained, "output": stdout}
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap timed out", "shell_obtained": False, "output": ""}
    except Exception as exc:
        return {"error": str(exc), "shell_obtained": False, "output": ""}


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "sqlmap_scan": {
        "fn": sqlmap_scan,
        "description": (
            "Scansione SQL injection su URL target. "
            "Rileva vulnerabilità, identifica il DBMS e le tecniche di injection. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL target (es. http://target/page.php?id=1)"},
                "data": {"type": "string", "description": "Dati POST (es. user=foo&pass=bar)"},
                "method": {"type": "string", "description": "Metodo HTTP: GET o POST (default: GET)"},
                "level": {"type": "integer", "description": "Profondità di test 1-5 (default: 1)"},
                "risk": {"type": "integer", "description": "Livello di rischio 1-3 (default: 1)"},
                "dbms": {"type": "string", "description": "Forza DBMS specifico (es. mysql, postgresql)"},
                "cookies": {"type": "string", "description": "Cookie di sessione (es. PHPSESSID=abc123)"},
                "headers": {"type": "string", "description": "Header HTTP aggiuntivi (uno per riga)"},
                "timeout": {"type": "integer", "description": "Timeout processo in secondi (default: 60)"},
            },
            "required": ["url"],
        },
    },
    "sqlmap_dbs": {
        "fn": sqlmap_dbs,
        "description": "Enumera i database accessibili tramite SQL injection sul target.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL target vulnerabile"},
                "data": {"type": "string", "description": "Dati POST opzionali"},
                "cookies": {"type": "string", "description": "Cookie di sessione opzionali"},
            },
            "required": ["url"],
        },
    },
    "sqlmap_tables": {
        "fn": sqlmap_tables,
        "description": "Enumera le tabelle di un database specifico tramite SQL injection.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL target vulnerabile"},
                "db": {"type": "string", "description": "Nome del database da esplorare"},
                "data": {"type": "string", "description": "Dati POST opzionali"},
                "cookies": {"type": "string", "description": "Cookie di sessione opzionali"},
            },
            "required": ["url", "db"],
        },
    },
    "sqlmap_dump": {
        "fn": sqlmap_dump,
        "description": (
            "Estrae dati da una tabella tramite SQL injection. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL target vulnerabile"},
                "db": {"type": "string", "description": "Nome del database"},
                "table": {"type": "string", "description": "Nome della tabella"},
                "columns": {"type": "string", "description": "Colonne da estrarre, separate da virgola"},
                "data": {"type": "string", "description": "Dati POST opzionali"},
                "cookies": {"type": "string", "description": "Cookie di sessione opzionali"},
            },
            "required": ["url", "db", "table"],
        },
    },
    "sqlmap_shell": {
        "fn": sqlmap_shell,
        "description": (
            "Tenta di ottenere una OS shell tramite SQL injection (--os-shell). "
            "Richiede privilege FILE sul DB. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL target vulnerabile"},
                "data": {"type": "string", "description": "Dati POST opzionali"},
                "cookies": {"type": "string", "description": "Cookie di sessione opzionali"},
            },
            "required": ["url"],
        },
    },
}
