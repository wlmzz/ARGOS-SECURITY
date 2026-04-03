"""
ARGOS Plugin: DataSurgeon
Estrae IOC e dati sensibili da file, log, testo grezzo, dump di memoria.
Ispirato a Drew-Alleman/DataSurgeon — implementazione Python nativa
con fallback al binario DataSurgeon se installato.
Usato per incident response, threat hunting, forensics.
"""
from __future__ import annotations
import re, os, json, subprocess, hashlib
from pathlib import Path
from typing import Any

MANIFEST = {
    "id":          "datasurgeon",
    "name":        "DataSurgeon",
    "description": (
        "Estrae IOC e dati sensibili da file/log/testo: IP, domini, URL, email, "
        "hash (MD5/SHA1/SHA256), credenziali, CVE, chiavi API, token JWT, "
        "numeri carta di credito. Utile per incident response e threat hunting."
    ),
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

# ── Regex patterns ────────────────────────────────────────────────────────────

_PATTERNS = {
    "ipv4":         re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "ipv6":         re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}'),
    "domain":       re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|co|uk|de|fr|it|ru|cn|br|jp|au|info|biz|xyz|onion|local)\b', re.I),
    "url":          re.compile(r'https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+', re.I),
    "email":        re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
    "md5":          re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1":         re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256":       re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha512":       re.compile(r'\b[a-fA-F0-9]{128}\b'),
    "cve":          re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I),
    "jwt":          re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    "api_key":      re.compile(r'(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.I),
    "aws_key":      re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "private_key":  re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "password":     re.compile(r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', re.I),
    "credit_card":  re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
    "base64_secret": re.compile(r'(?:secret|key|token|password)\s*[=:]\s*["\']?([A-Za-z0-9+/]{32,}={0,2})["\']?', re.I),
}

_PRIVATE_IPS = re.compile(r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|255\.)')
_FALSE_POSITIVE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 empty
}


def _extract_from_text(text: str, include_private_ips: bool = False) -> dict:
    results: dict[str, list] = {}
    for name, pattern in _PATTERNS.items():
        matches = list(set(pattern.findall(text)))
        if name == "ipv4" and not include_private_ips:
            matches = [ip for ip in matches if not _PRIVATE_IPS.match(ip)]
        if name in ("md5", "sha1", "sha256"):
            matches = [h for h in matches if h.lower() not in _FALSE_POSITIVE_HASHES]
        # Per pattern con gruppi, estrai solo il gruppo
        if name in ("api_key", "password", "base64_secret") and matches:
            matches = [m if isinstance(m, str) else m[0] for m in matches]
        if matches:
            results[name] = sorted(set(str(m) for m in matches))
    return results


# ── Tools ─────────────────────────────────────────────────────────────────────

def extract_iocs_from_text(text: str, include_private_ips: bool = False) -> dict:
    """
    Estrae tutti gli IOC da testo grezzo: IP, domini, URL, email, hash,
    CVE, JWT, chiavi API, credenziali. Utile per analizzare log, email sospette,
    output di tool, dump di configurazioni.
    """
    if len(text) > 10_000_000:
        return {"error": "Testo troppo grande (max 10MB). Usa extract_iocs_from_file."}
    result = _extract_from_text(text, include_private_ips)
    total = sum(len(v) for v in result.values())
    return {
        "total_iocs": total,
        "categories": {k: len(v) for k, v in result.items()},
        "iocs":       result,
    }


def extract_iocs_from_file(path: str, include_private_ips: bool = False) -> dict:
    """
    Estrae IOC da un file (log, config, dump, pcap-text, etc.).
    Supporta file fino a 500MB leggendo in chunks.
    """
    p = Path(path)
    if not p.exists():
        return {"error": f"File non trovato: {path}"}
    if p.stat().st_size > 500_000_000:
        return {"error": "File > 500MB non supportato"}

    # Prova DataSurgeon binario se disponibile
    if _ds_available():
        return _datasurgeon_cli(path)

    try:
        text = p.read_text(errors="replace")
    except Exception as e:
        return {"error": str(e)}

    result = _extract_from_text(text, include_private_ips)
    total  = sum(len(v) for v in result.values())
    return {
        "file":       path,
        "size_bytes": p.stat().st_size,
        "total_iocs": total,
        "categories": {k: len(v) for k, v in result.items()},
        "iocs":       result,
    }


def scan_dir_for_iocs(directory: str, extensions: list[str] = None, recursive: bool = True) -> dict:
    """
    Scansiona una directory intera cercando IOC in tutti i file di testo.
    Utile per threat hunting su log di sistema, directory web, backup.
    Extensions default: .log, .txt, .conf, .cfg, .yaml, .yml, .json, .csv, .xml, .env, .sh, .py
    """
    exts = set(extensions or [".log", ".txt", ".conf", ".cfg", ".yaml", ".yml",
                               ".json", ".csv", ".xml", ".env", ".sh", ".py", ".ini"])
    base = Path(directory)
    if not base.exists():
        return {"error": f"Directory non trovata: {directory}"}

    glob_fn = base.rglob("*") if recursive else base.glob("*")
    files_scanned = 0
    aggregate: dict[str, set] = {k: set() for k in _PATTERNS}
    per_file: list[dict] = []

    for fp in glob_fn:
        if not fp.is_file() or fp.suffix.lower() not in exts:
            continue
        if fp.stat().st_size > 50_000_000:
            continue
        try:
            text = fp.read_text(errors="replace")
            found = _extract_from_text(text)
            if found:
                files_scanned += 1
                file_total = sum(len(v) for v in found.values())
                per_file.append({
                    "file":  str(fp),
                    "iocs":  file_total,
                    "types": list(found.keys()),
                })
                for k, v in found.items():
                    aggregate[k].update(v)
        except Exception:
            pass

    aggregate_clean = {k: sorted(v) for k, v in aggregate.items() if v}
    total = sum(len(v) for v in aggregate_clean.values())
    return {
        "directory":     directory,
        "files_scanned": files_scanned,
        "total_iocs":    total,
        "by_category":   {k: len(v) for k, v in aggregate_clean.items()},
        "top_files":     sorted(per_file, key=lambda x: x["iocs"], reverse=True)[:20],
        "iocs":          aggregate_clean,
    }


def extract_credentials(text: str = None, path: str = None) -> dict:
    """
    Cerca specificamente credenziali: password in chiaro, chiavi API,
    token JWT, chiavi private, chiavi AWS, segreti base64.
    Accetta testo diretto o path a file.
    """
    if path:
        fp = Path(path)
        if not fp.exists():
            return {"error": f"File non trovato: {path}"}
        text = fp.read_text(errors="replace")
    if not text:
        return {"error": "Fornisci text o path"}

    cred_patterns = {k: _PATTERNS[k] for k in
                     ["jwt", "api_key", "aws_key", "private_key", "password", "base64_secret"]}
    results: dict[str, list] = {}
    for name, pattern in cred_patterns.items():
        matches = pattern.findall(text)
        if matches:
            clean = list(set(str(m) if isinstance(m, str) else m[0] for m in matches))
            results[name] = clean[:50]  # max 50 per categoria

    risk = "CRITICAL" if any(k in results for k in ["private_key", "aws_key", "jwt"]) \
           else "HIGH" if results else "CLEAN"
    return {
        "source":     path or "text_input",
        "risk_level": risk,
        "found":      bool(results),
        "credentials": results,
        "total":      sum(len(v) for v in results.values()),
    }


def _ds_available() -> bool:
    try:
        subprocess.run(["datasurgeon", "--version"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False


def _datasurgeon_cli(path: str) -> dict:
    """Usa il binario DataSurgeon se installato."""
    try:
        out = subprocess.check_output(
            ["datasurgeon", "--file", path, "--json"],
            timeout=60, stderr=subprocess.DEVNULL).decode(errors="replace")
        return {"source": "datasurgeon_binary", "result": json.loads(out)}
    except Exception as e:
        return {"error": str(e)}


TOOLS = {
    "extract_iocs_from_text": {
        "fn": extract_iocs_from_text,
        "description": "Estrae IOC da testo grezzo: IP, domini, URL, email, hash MD5/SHA1/SHA256, CVE, JWT, chiavi API, password, credenziali AWS. Utile per analizzare log, email sospette, output di tool.",
        "parameters": {
            "text":               {"type": "string", "description": "Testo da analizzare", "required": True},
            "include_private_ips": {"type": "boolean", "description": "Includi IP privati (10.x, 192.168.x). Default: False", "required": False},
        },
    },
    "extract_iocs_from_file": {
        "fn": extract_iocs_from_file,
        "description": "Estrae IOC da un file: log, config, dump. Usa DataSurgeon binario se installato, altrimenti Python nativo.",
        "parameters": {
            "path":               {"type": "string", "description": "Path al file", "required": True},
            "include_private_ips": {"type": "boolean", "required": False},
        },
    },
    "scan_dir_for_iocs": {
        "fn": scan_dir_for_iocs,
        "description": "Scansiona directory intera cercando IOC in tutti i file di testo. Utile per threat hunting su /var/log, directory web, backup.",
        "parameters": {
            "directory":  {"type": "string", "description": "Directory da scansionare", "required": True},
            "extensions": {"type": "array", "items": {"type": "string"}, "description": "Estensioni da includere (default: .log .txt .conf .yaml .json .env ecc.)", "required": False},
            "recursive":  {"type": "boolean", "description": "Scansione ricorsiva (default: True)", "required": False},
        },
    },
    "extract_credentials": {
        "fn": extract_credentials,
        "description": "Cerca specificamente credenziali esposte: password in chiaro, JWT, API key, chiavi private SSH/RSA, AWS key, segreti base64. Accetta testo o path file.",
        "parameters": {
            "text": {"type": "string", "description": "Testo da analizzare", "required": False},
            "path": {"type": "string", "description": "Path al file", "required": False},
        },
    },
}
