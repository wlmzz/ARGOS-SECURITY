"""
ARGOS Plugin: ffuf (Fuzz Faster U Fool)
Web fuzzing per directory discovery, virtual host discovery,
parameter fuzzing e fuzzing generico.

USO AUTORIZZATO: solo per pentest, CTF e security research con permesso esplicito.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "ffuf",
    "name": "ffuf - Fuzz Faster U Fool",
    "description": (
        "Web fuzzer per directory/file discovery, virtual host enumeration, "
        "parameter discovery e fuzzing generico con placeholder custom. "
        "Richiede ffuf installato (go install github.com/ffuf/ffuf/v2@latest "
        "o apt install ffuf). "
        "USO AUTORIZZATO: solo per pentest, CTF e security research."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FFUF_BIN = "ffuf"
_WORDLIST_DIRS = ["/usr/share/wordlists", "/opt/argos/wordlists"]
_DEFAULT_WORDLIST_DIRS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
]
_DEFAULT_SUBDOMAINS = "/usr/share/wordlists/subdomains.txt"
_DEFAULT_PARAMS = "/usr/share/wordlists/burp-parameter-names.txt"


def _tool_installed() -> bool:
    return shutil.which(_FFUF_BIN) is not None


def _not_installed_error() -> dict:
    return {
        "error": (
            "ffuf not installed. "
            "Install: go install github.com/ffuf/ffuf/v2@latest  OR  "
            "sudo apt install ffuf  OR  "
            "see https://github.com/ffuf/ffuf"
        )
    }


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    """Esegue ffuf catturando stdout/stderr."""
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=True,
        text=True,
    )


def _parse_ffuf_json(json_path: str) -> list[dict[str, Any]]:
    """
    Legge e normalizza il JSON prodotto da ffuf (-of json).
    Restituisce una lista di risultati con campi: url, status, size, words, lines.
    """
    results: list[dict[str, Any]] = []
    try:
        path = Path(json_path)
        if not path.exists():
            return results
        data = json.loads(path.read_text(errors="replace"))
        for entry in data.get("results", []):
            results.append(
                {
                    "url": entry.get("url", ""),
                    "input": entry.get("input", {}),
                    "status": entry.get("status", 0),
                    "size": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "lines": entry.get("lines", 0),
                    "redirect_location": entry.get("redirectlocation", ""),
                }
            )
    except Exception:
        pass
    return results


def _pick_wordlist(candidates: list[str], default: str) -> str:
    """Ritorna il primo path candidato esistente, altrimenti default."""
    for path in candidates:
        if Path(path).exists():
            return path
    return default


def _count_lines(path: str) -> int:
    """Conta le righe di un file senza caricarlo tutto in memoria."""
    try:
        count = 0
        with open(path, "rb") as f:
            for _ in f:
                count += 1
        return count
    except Exception:
        return 0


def _file_size_mb(path: str) -> float:
    """Restituisce la dimensione del file in MB."""
    try:
        return round(os.path.getsize(path) / (1024 * 1024), 2)
    except Exception:
        return 0.0


def _detect_baseline_size(url: str, timeout: int = 10) -> int:
    """
    Rileva la dimensione di risposta baseline per un host.
    Usato per filtrare falsi positivi nel vhost fuzzing.
    Restituisce la dimensione in byte, 0 se non rilevabile.
    """
    import urllib.request
    import urllib.error

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            content = resp.read()
            return len(content)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def ffuf_dirs(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    threads: int = 40,
    filter_codes: str = "404",
) -> dict:
    """
    Directory e file discovery sull'URL target usando ffuf.

    Args:
        url:          URL base target (es. "http://target.com")
                      Il placeholder FUZZ viene aggiunto automaticamente come /{url}/FUZZ
        wordlist:     Path alla wordlist (default: /usr/share/wordlists/dirb/common.txt)
        extensions:   Estensioni da testare, separate da virgola (es. ".php,.html,.asp")
        threads:      Thread paralleli (default: 40)
        filter_codes: Codici HTTP da filtrare, separati da virgola (default: "404")

    Returns:
        {"found": [{"url": str, "status": int, "size": int, "words": int, "lines": int}],
         "total": int}
    """
    if not _tool_installed():
        return _not_installed_error()

    # Normalizza URL: rimuove slash finale
    target_url = url.rstrip("/") + "/FUZZ"

    # Fallback wordlist
    if not Path(wordlist).exists():
        alt = _pick_wordlist(_DEFAULT_WORDLIST_DIRS, wordlist)
        if Path(alt).exists():
            wordlist = alt
        else:
            return {"error": f"Wordlist not found: {wordlist}", "found": [], "total": 0}

    out_file = "/tmp/ffuf_dirs_out.json"

    cmd = [
        _FFUF_BIN,
        "-u", target_url,
        "-w", wordlist,
        "-t", str(threads),
        "-fc", filter_codes,
        "-o", out_file,
        "-of", "json",
        "-s",  # silent: sopprime il banner
    ]
    if extensions:
        cmd += ["-e", extensions]

    try:
        proc = _run(cmd)
        results = _parse_ffuf_json(out_file)

        # Pulizia file temporaneo
        try:
            Path(out_file).unlink(missing_ok=True)
        except Exception:
            pass

        if proc.returncode not in (0, 1) and not results:
            stderr = (proc.stderr or "").strip()
            if stderr:
                return {"error": stderr, "found": [], "total": 0}

        return {"found": results, "total": len(results)}
    except subprocess.TimeoutExpired:
        return {"error": "ffuf timed out after 120s", "found": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "found": [], "total": 0}


def ffuf_vhosts(
    domain: str,
    wordlist: str = "/usr/share/wordlists/subdomains.txt",
    ip: str = "",
    threads: int = 40,
) -> dict:
    """
    Virtual host discovery: trova sottodomini/vhost sul server target.

    Invia richieste con header "Host: FUZZ.<domain>" e filtra le risposte
    che differiscono dalla baseline (dimensione risposta della root).

    Args:
        domain:   Dominio principale (es. "target.com")
        wordlist: Wordlist di sottodomini (default: /usr/share/wordlists/subdomains.txt)
        ip:       IP del server (usato se il dominio non risolve, opzionale)
        threads:  Thread paralleli (default: 40)

    Returns:
        {"vhosts": [{"host": str, "status": int, "size": int}], "total": int}
    """
    if not _tool_installed():
        return _not_installed_error()

    # Fallback wordlist
    if not Path(wordlist).exists():
        alt_lists = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
        ]
        alt = _pick_wordlist(alt_lists, wordlist)
        if Path(alt).exists():
            wordlist = alt
        else:
            return {"error": f"Wordlist not found: {wordlist}", "vhosts": [], "total": 0}

    # Target URL: usa IP se fornito, altrimenti il dominio
    target = f"http://{ip}/" if ip else f"http://{domain}/"

    # Rileva baseline size
    baseline_size = _detect_baseline_size(target)

    out_file = "/tmp/ffuf_vhost_out.json"

    cmd = [
        _FFUF_BIN,
        "-u", target,
        "-H", f"Host: FUZZ.{domain}",
        "-w", wordlist,
        "-t", str(threads),
        "-o", out_file,
        "-of", "json",
        "-s",
    ]

    # Filtra per dimensione baseline se rilevata (±10%)
    if baseline_size > 0:
        margin = max(int(baseline_size * 0.1), 50)
        fs_min = baseline_size - margin
        fs_max = baseline_size + margin
        cmd += ["-fs", f"{fs_min},{fs_max}"]

    try:
        proc = _run(cmd)
        raw_results = _parse_ffuf_json(out_file)

        try:
            Path(out_file).unlink(missing_ok=True)
        except Exception:
            pass

        vhosts = []
        for entry in raw_results:
            # Estrai il valore del placeholder FUZZ dall'input
            fuzz_val = entry.get("input", {}).get("FUZZ", "")
            if not fuzz_val:
                # Prova a dedurlo dall'URL
                fuzz_val = entry.get("url", "")
            vhosts.append(
                {
                    "host": f"{fuzz_val}.{domain}" if fuzz_val else entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "size": entry.get("size", 0),
                    "words": entry.get("words", 0),
                }
            )

        return {"vhosts": vhosts, "total": len(vhosts)}
    except subprocess.TimeoutExpired:
        return {"error": "ffuf timed out after 120s", "vhosts": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "vhosts": [], "total": 0}


def ffuf_params(
    url: str,
    wordlist: str = "/usr/share/wordlists/burp-parameter-names.txt",
    method: str = "GET",
    data: str = "",
    threads: int = 40,
) -> dict:
    """
    Parameter fuzzing: scopre parametri GET/POST nascosti o non documentati.

    Modalità GET:  {url}?FUZZ=test
    Modalità POST: {url} con body "FUZZ=test"

    Args:
        url:      URL target (senza parametri, es. "http://target.com/api/endpoint")
        wordlist: Wordlist di nomi di parametri
        method:   Metodo HTTP: GET o POST (default: GET)
        data:     Dati POST base da aggiungere prima del parametro testato
        threads:  Thread paralleli (default: 40)

    Returns:
        {"parameters": [{"name": str, "status": int, "size": int}], "total": int}
    """
    if not _tool_installed():
        return _not_installed_error()

    if not Path(wordlist).exists():
        alt_lists = [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        ]
        alt = _pick_wordlist(alt_lists, wordlist)
        if Path(alt).exists():
            wordlist = alt
        else:
            return {"error": f"Wordlist not found: {wordlist}", "parameters": [], "total": 0}

    out_file = "/tmp/ffuf_params_out.json"
    method_upper = method.upper()

    if method_upper == "POST":
        post_data = f"{data}&FUZZ=test" if data else "FUZZ=test"
        cmd = [
            _FFUF_BIN,
            "-u", url,
            "-X", "POST",
            "-d", post_data,
            "-w", wordlist,
            "-t", str(threads),
            "-fc", "404",
            "-o", out_file,
            "-of", "json",
            "-s",
        ]
    else:
        target_url = url + ("&" if "?" in url else "?") + "FUZZ=test"
        cmd = [
            _FFUF_BIN,
            "-u", target_url,
            "-w", wordlist,
            "-t", str(threads),
            "-fc", "404",
            "-o", out_file,
            "-of", "json",
            "-s",
        ]

    try:
        proc = _run(cmd)
        raw_results = _parse_ffuf_json(out_file)

        try:
            Path(out_file).unlink(missing_ok=True)
        except Exception:
            pass

        parameters = []
        for entry in raw_results:
            fuzz_val = entry.get("input", {}).get("FUZZ", "")
            parameters.append(
                {
                    "name": fuzz_val,
                    "status": entry.get("status", 0),
                    "size": entry.get("size", 0),
                    "words": entry.get("words", 0),
                    "url": entry.get("url", ""),
                }
            )

        return {"parameters": parameters, "total": len(parameters)}
    except subprocess.TimeoutExpired:
        return {"error": "ffuf timed out after 120s", "parameters": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "parameters": [], "total": 0}


def ffuf_fuzz(
    url: str,
    wordlist: str,
    placeholder: str = "FUZZ",
    method: str = "GET",
    data: str = "",
    headers: dict | None = None,
    filter_codes: str = "404",
    threads: int = 40,
) -> dict:
    """
    Fuzzing generico con placeholder custom in URL, dati o header.

    Permette di testare qualsiasi punto dell'HTTP request (path, query string,
    body, header value) usando un placeholder custom al posto di FUZZ.

    Args:
        url:          URL con placeholder (es. "http://target/FUZZ" o "http://t/api/MYWORD/data")
        wordlist:     Path alla wordlist
        placeholder:  Placeholder nella request (default: "FUZZ")
        method:       Metodo HTTP: GET, POST, PUT, DELETE, ecc. (default: GET)
        data:         Body della request (può contenere il placeholder)
        headers:      Dict di header HTTP da aggiungere (es. {"Authorization": "Bearer FUZZ"})
        filter_codes: Codici HTTP da filtrare (default: "404")
        threads:      Thread paralleli (default: 40)

    Returns:
        {"results": [{"url": str, "status": int, "size": int, "words": int, "lines": int}],
         "total": int, "duration_seconds": float}
    """
    if not _tool_installed():
        return _not_installed_error()

    if not Path(wordlist).exists():
        return {"error": f"Wordlist not found: {wordlist}", "results": [], "total": 0, "duration_seconds": 0}

    # Sostituisce placeholder custom con FUZZ se diverso
    if placeholder != "FUZZ":
        url = url.replace(placeholder, "FUZZ")
        if data:
            data = data.replace(placeholder, "FUZZ")
        if headers:
            headers = {k: v.replace(placeholder, "FUZZ") for k, v in headers.items()}

    out_file = "/tmp/ffuf_fuzz_out.json"

    cmd = [
        _FFUF_BIN,
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "-fc", filter_codes,
        "-o", out_file,
        "-of", "json",
        "-s",
    ]

    if method.upper() != "GET":
        cmd += ["-X", method.upper()]

    if data:
        cmd += ["-d", data]

    if headers:
        for key, val in headers.items():
            cmd += ["-H", f"{key}: {val}"]

    start_time = time.monotonic()

    try:
        proc = _run(cmd)
        elapsed = round(time.monotonic() - start_time, 2)
        results = _parse_ffuf_json(out_file)

        try:
            Path(out_file).unlink(missing_ok=True)
        except Exception:
            pass

        if proc.returncode not in (0, 1) and not results:
            stderr = (proc.stderr or "").strip()
            if stderr:
                return {"error": stderr, "results": [], "total": 0, "duration_seconds": elapsed}

        return {"results": results, "total": len(results), "duration_seconds": elapsed}
    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - start_time, 2)
        return {"error": "ffuf timed out after 120s", "results": [], "total": 0, "duration_seconds": elapsed}
    except Exception as exc:
        elapsed = round(time.monotonic() - start_time, 2)
        return {"error": str(exc), "results": [], "total": 0, "duration_seconds": elapsed}


def ffuf_list_wordlists() -> dict:
    """
    Elenca le wordlist disponibili nelle directory standard di ARGOS/Kali.

    Cerca in:
      - /usr/share/wordlists/
      - /opt/argos/wordlists/

    Returns:
        {"wordlists": [{"path": str, "lines": int, "size_mb": float}]}
    """
    wordlists = []

    for base_dir in _WORDLIST_DIRS:
        base_path = Path(base_dir)
        if not base_path.exists():
            continue
        try:
            # Ricerca ricorsiva dei file .txt, .lst, .dict (limita a 500 risultati)
            count = 0
            for wl_file in sorted(base_path.rglob("*")):
                if count >= 500:
                    break
                if not wl_file.is_file():
                    continue
                if wl_file.suffix.lower() not in (".txt", ".lst", ".dict", ""):
                    continue
                # Salta file troppo grandi (>500 MB) per il conteggio righe
                size_mb = _file_size_mb(str(wl_file))
                if size_mb > 500:
                    line_count = -1  # troppo grande per contare
                else:
                    line_count = _count_lines(str(wl_file))
                wordlists.append(
                    {
                        "path": str(wl_file),
                        "lines": line_count,
                        "size_mb": size_mb,
                    }
                )
                count += 1
        except PermissionError:
            pass

    # Ordina per path
    wordlists.sort(key=lambda x: x["path"])

    return {"wordlists": wordlists}


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "ffuf_dirs": {
        "fn": ffuf_dirs,
        "description": (
            "Directory e file discovery tramite fuzzing. "
            "Trova path nascosti, pagine non linkate e file di configurazione esposti. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL base target (es. http://target.com)"},
                "wordlist": {
                    "type": "string",
                    "description": "Path wordlist (default: /usr/share/wordlists/dirb/common.txt)",
                },
                "extensions": {
                    "type": "string",
                    "description": "Estensioni da testare separate da virgola (es. .php,.html,.asp)",
                },
                "threads": {"type": "integer", "description": "Thread paralleli (default: 40)"},
                "filter_codes": {
                    "type": "string",
                    "description": "Codici HTTP da filtrare, separati da virgola (default: 404)",
                },
            },
            "required": ["url"],
        },
    },
    "ffuf_vhosts": {
        "fn": ffuf_vhosts,
        "description": (
            "Virtual host e sottodominio discovery tramite header Host fuzzing. "
            "Trova vhost nascosti sullo stesso IP server. "
            "USO AUTORIZZATO: solo per pentest e CTF con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Dominio principale (es. target.com)"},
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist sottodomini (default: /usr/share/wordlists/subdomains.txt)",
                },
                "ip": {
                    "type": "string",
                    "description": "IP del server (opzionale, usato se il dominio non risolve)",
                },
                "threads": {"type": "integer", "description": "Thread paralleli (default: 40)"},
            },
            "required": ["domain"],
        },
    },
    "ffuf_params": {
        "fn": ffuf_params,
        "description": (
            "Parameter discovery: trova parametri GET/POST nascosti o non documentati. "
            "Utile per scoprire funzionalità nascoste, debug endpoint, ecc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL target senza parametri (es. http://target.com/api/endpoint)",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist nomi parametri (default: /usr/share/wordlists/burp-parameter-names.txt)",
                },
                "method": {"type": "string", "description": "Metodo HTTP: GET o POST (default: GET)"},
                "data": {"type": "string", "description": "Dati POST base da aggiungere"},
                "threads": {"type": "integer", "description": "Thread paralleli (default: 40)"},
            },
            "required": ["url"],
        },
    },
    "ffuf_fuzz": {
        "fn": ffuf_fuzz,
        "description": (
            "Fuzzing generico con placeholder custom. "
            "Testa qualsiasi punto della HTTP request: path, query, body, header. "
            "Supporta autenticazione via header Bearer, Cookie, ecc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL con placeholder (es. http://target/FUZZ o http://t/api/MYWORD)",
                },
                "wordlist": {"type": "string", "description": "Path alla wordlist"},
                "placeholder": {
                    "type": "string",
                    "description": "Placeholder custom nella request (default: FUZZ)",
                },
                "method": {
                    "type": "string",
                    "description": "Metodo HTTP: GET, POST, PUT, DELETE (default: GET)",
                },
                "data": {"type": "string", "description": "Body della request (può contenere il placeholder)"},
                "headers": {
                    "type": "object",
                    "description": "Header HTTP aggiuntivi (es. {Authorization: 'Bearer token'})",
                    "additionalProperties": {"type": "string"},
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Codici HTTP da filtrare, separati da virgola (default: 404)",
                },
                "threads": {"type": "integer", "description": "Thread paralleli (default: 40)"},
            },
            "required": ["url", "wordlist"],
        },
    },
    "ffuf_list_wordlists": {
        "fn": ffuf_list_wordlists,
        "description": (
            "Elenca tutte le wordlist disponibili nelle directory standard "
            "(/usr/share/wordlists/ e /opt/argos/wordlists/) "
            "con numero di righe e dimensione."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}
