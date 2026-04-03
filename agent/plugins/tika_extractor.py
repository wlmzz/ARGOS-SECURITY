"""
tika_extractor.py — ARGOS plugin
Document content extraction and analysis using Apache Tika.
Extracts text and metadata from 1000+ file formats: PDF, Office, archives, emails, code.
Useful for malware triage, DLP, and digital forensics.
https://github.com/apache/tika
"""

import subprocess
import json
import os
import re
import shutil
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "tika_extractor",
    "name": "Tika Extractor",
    "version": "1.0.0",
    "description": "Apache Tika: extract text/metadata from 1000+ file types — PDF, Office, archives",
    "author": "ARGOS",
    "category": "forensics",
    "tools": [
        "tika_extract_text",
        "tika_extract_metadata",
        "tika_scan_dir",
        "tika_detect_language",
        "tika_malware_triage",
    ],
}

TIKA_JAR = "/opt/argos/tika/tika-app.jar"
TIKA_DIR = "/opt/argos/tika"
RESULTS_DIR = "/opt/argos/logs/tika"
TIKA_VERSION = "2.9.2"

os.makedirs(TIKA_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


def _run(cmd: list, timeout: int = 120, input_data: bytes = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=input_data.decode("utf-8", errors="replace") if input_data else None,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _ensure_tika() -> tuple[bool, str]:
    """Download Tika app JAR if not present."""
    if os.path.exists(TIKA_JAR):
        return True, TIKA_JAR

    if not shutil.which("java"):
        return False, "Java not found. Install: apt install default-jre-headless"

    # Check Java version
    rc, out, _ = _run(["java", "-version"], timeout=10)
    # Some JVMs write version to stderr

    # Download Tika app JAR
    url = (f"https://downloads.apache.org/tika/{TIKA_VERSION}/"
           f"tika-app-{TIKA_VERSION}.jar")
    fallback_url = (f"https://archive.apache.org/dist/tika/{TIKA_VERSION}/"
                    f"tika-app-{TIKA_VERSION}.jar")

    for dl_url in [url, fallback_url]:
        rc, _, err = _run(
            ["curl", "-sL", dl_url, "-o", TIKA_JAR, "--connect-timeout", "30"],
            timeout=180,
        )
        if rc == 0 and os.path.exists(TIKA_JAR) and os.path.getsize(TIKA_JAR) > 100000:
            return True, TIKA_JAR

    return False, f"Could not download Tika JAR from {url}"


def _tika_cmd(mode: str, file_path: str, extra: list = None) -> list:
    """Build Tika command for given mode."""
    cmd = ["java", "-jar", TIKA_JAR]
    mode_flags = {
        "text": ["--text"],
        "metadata": ["--metadata", "--json"],
        "detect": ["--detect"],
        "language": ["--language"],
        "xml": ["--xml"],
    }
    cmd.extend(mode_flags.get(mode, [mode]))
    if extra:
        cmd.extend(extra)
    cmd.append(file_path)
    return cmd


def tika_extract_text(file_path: str, max_chars: int = 50000) -> dict:
    """
    Extract plain text content from any supported file format.
    Works on PDFs, Word/Excel/PowerPoint, HTML, emails (.eml/.msg), archives, code files.
    Useful for content-based malware detection and DLP.

    Args:
        file_path: Path to file (local or URL)
        max_chars: Maximum characters to return (default: 50000)

    Returns:
        Extracted text content, detected language, and content summary
    """
    if not os.path.exists(file_path) and not file_path.startswith("http"):
        return {"error": f"File not found: {file_path}"}

    ok, msg = _ensure_tika()
    if not ok:
        # Fallback: try python-docx, pdfplumber, etc.
        return _extract_text_fallback(file_path, max_chars)

    rc, out, err = _run(_tika_cmd("text", file_path), timeout=60)

    if rc != 0 and not out.strip():
        return {"error": f"Extraction failed: {err[:500]}", "file": file_path}

    text = out[:max_chars]
    words = len(text.split())

    # Quick content analysis
    suspicious_patterns = {
        "powershell_encoded": re.search(r"powershell.*-enc\w*\s+[A-Za-z0-9+/=]{20,}", text, re.I),
        "base64_blob": re.search(r"[A-Za-z0-9+/]{100,}={0,2}", text),
        "urls": re.findall(r"https?://[^\s\"'<>]+", text)[:20],
        "ips": list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)))[:20],
        "emails": list(set(re.findall(r"[\w\.\-]+@[\w\.\-]+\.\w+", text)))[:10],
        "cves": list(set(re.findall(r"CVE-\d{4}-\d+", text, re.I)))[:10],
        "api_keys_hint": bool(re.search(r"(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[=:]\s*\S+", text, re.I)),
    }

    return {
        "file": file_path,
        "text": text,
        "char_count": len(text),
        "word_count": words,
        "iocs": {
            "urls": suspicious_patterns["urls"],
            "ips": suspicious_patterns["ips"],
            "emails": suspicious_patterns["emails"],
            "cves": suspicious_patterns["cves"],
        },
        "suspicious": {
            "has_base64_blob": bool(suspicious_patterns["base64_blob"]),
            "has_powershell_encoded": bool(suspicious_patterns["powershell_encoded"]),
            "has_api_key_hints": suspicious_patterns["api_keys_hint"],
        },
        "extraction_time": datetime.utcnow().isoformat(),
    }


def _extract_text_fallback(file_path: str, max_chars: int) -> dict:
    """Fallback extraction without Tika."""
    ext = os.path.splitext(file_path)[1].lower()
    result = {"file": file_path, "note": "Tika unavailable — basic fallback",
              "extraction_time": datetime.utcnow().isoformat()}

    try:
        if ext == ".pdf":
            import pdfplumber
            with pdfplumber.open(file_path) as pdf:
                text = "\n".join(p.extract_text() or "" for p in pdf.pages)
            result["text"] = text[:max_chars]
            return result
    except ImportError:
        pass

    try:
        if ext in (".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm"):
            with open(file_path, errors="replace") as f:
                result["text"] = f.read(max_chars)
            return result
    except Exception as e:
        pass

    return {"error": "Tika and fallback parsers unavailable",
            "install": "apt install default-jre-headless && tika_extract_text() will auto-download Tika JAR",
            "file": file_path}


def tika_extract_metadata(file_path: str) -> dict:
    """
    Extract rich metadata from any file using Apache Tika.
    Returns content-type, author, creation dates, page count, encryption status, etc.

    Args:
        file_path: Path to file

    Returns:
        All metadata as key-value pairs, plus security-relevant highlights
    """
    if not os.path.exists(file_path) and not file_path.startswith("http"):
        return {"error": f"File not found: {file_path}"}

    ok, msg = _ensure_tika()
    if not ok:
        return {"error": msg}

    rc, out, err = _run(_tika_cmd("metadata", file_path), timeout=60)

    try:
        meta = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        # Parse key: value format
        meta = {}
        for line in out.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                meta[k.strip()] = v.strip()

    # Security-relevant metadata
    security = {}

    # Encryption/DRM
    if any("encrypt" in k.lower() or "drm" in k.lower() or "protected" in k.lower()
           for k in meta):
        security["encryption"] = {k: v for k, v in meta.items()
                                   if "encrypt" in k.lower() or "drm" in k.lower()}

    # Macros
    if any("macro" in str(v).lower() for v in meta.values()):
        security["macros"] = True

    # Embedded objects
    for k, v in meta.items():
        if "embedded" in k.lower() or "attachment" in k.lower():
            security.setdefault("embedded_objects", {})[k] = v

    # Author info
    author_keys = ["Author", "dc:creator", "meta:author", "Last-Author",
                   "cp:lastModifiedBy", "xmp:CreatorTool"]
    authors = {k: meta[k] for k in author_keys if k in meta}
    if authors:
        security["authors"] = authors

    # Content type detection
    content_type = meta.get("Content-Type", meta.get("content-type", "unknown"))

    return {
        "file": file_path,
        "content_type": content_type,
        "metadata": meta,
        "security": security,
        "extraction_time": datetime.utcnow().isoformat(),
    }


def tika_scan_dir(directory: str, extensions: list = None,
                   find_iocs: bool = True, export_json: bool = False) -> dict:
    """
    Batch content extraction and analysis of a directory.
    Identifies IOCs (URLs, IPs, emails), suspicious content, and risky file types.
    Useful for incident response and evidence processing.

    Args:
        directory: Directory to scan
        extensions: File extensions to include (e.g. ['.pdf', '.docx', '.xlsx'])
        find_iocs: Extract IOCs from file contents (default: True)
        export_json: Save results to JSON file (default: False)

    Returns:
        Per-file analysis with aggregated IOCs and risk assessment
    """
    if not os.path.isdir(directory):
        return {"error": f"Directory not found: {directory}"}

    ok, msg = _ensure_tika()
    if not ok:
        return {"error": msg}

    # Collect files
    risky_extensions = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                        ".rtf", ".odt", ".ods", ".eml", ".msg", ".zip", ".rar", ".7z"}

    all_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if extensions:
                if ext in extensions:
                    all_files.append(os.path.join(root, f))
            else:
                all_files.append(os.path.join(root, f))

    # Cap at 200 files
    all_files = all_files[:200]

    results = []
    all_urls = set()
    all_ips = set()
    all_emails = set()
    risky_files = []

    for fp in all_files:
        ext = os.path.splitext(fp)[1].lower()
        entry = {"file": fp, "extension": ext}

        try:
            # Quick metadata
            rc, out, _ = _run(
                ["java", "-jar", TIKA_JAR, "--metadata", "--json", fp],
                timeout=30,
            )
            if rc == 0 and out.strip():
                try:
                    meta = json.loads(out)
                    entry["content_type"] = meta.get("Content-Type", "")
                    entry["has_macros"] = any("macro" in str(v).lower()
                                              for v in meta.values())
                    if entry["has_macros"]:
                        risky_files.append({"file": fp, "risk": "macros"})
                except Exception:
                    pass

            # Text extraction for IOC hunting
            if find_iocs and ext in risky_extensions:
                rc2, text, _ = _run(
                    ["java", "-jar", TIKA_JAR, "--text", fp],
                    timeout=30,
                )
                if rc2 == 0 and text.strip():
                    urls = re.findall(r"https?://[^\s\"'<>]+", text)[:10]
                    ips = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)))[:5]
                    emails = list(set(re.findall(r"[\w\.\-]+@[\w\.\-]+\.\w+", text)))[:5]
                    all_urls.update(urls)
                    all_ips.update(ips)
                    all_emails.update(emails)
                    if urls or ips:
                        entry["iocs"] = {"urls": urls, "ips": ips, "emails": emails}

        except Exception as e:
            entry["error"] = str(e)

        results.append(entry)

    summary = {
        "directory": directory,
        "total_files": len(all_files),
        "risky_files": risky_files[:20],
        "aggregated_iocs": {
            "urls": list(all_urls)[:50],
            "ips": list(all_ips)[:50],
            "emails": list(all_emails)[:20],
        },
        "results": results[:50],
        "analysis_time": datetime.utcnow().isoformat(),
    }

    if export_json:
        outfile = os.path.join(RESULTS_DIR, f"tika_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
        with open(outfile, "w") as f:
            json.dump(summary, f, indent=2)
        summary["output_file"] = outfile

    return summary


def tika_detect_language(file_path: str) -> dict:
    """
    Detect the language of document content using Tika's language detection.
    Useful for threat intelligence analysis and attribution (e.g. Russian/Chinese APT documents).

    Args:
        file_path: Path to document or text file

    Returns:
        Detected language with confidence, useful for attribution analysis
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    ok, msg = _ensure_tika()
    if not ok:
        return {"error": msg}

    rc, out, err = _run(_tika_cmd("language", file_path), timeout=60)

    language_code = out.strip()

    # Map language codes to names
    lang_map = {
        "en": "English", "ru": "Russian", "zh": "Chinese",
        "ar": "Arabic", "fa": "Farsi/Persian", "ko": "Korean",
        "ja": "Japanese", "de": "German", "fr": "French",
        "es": "Spanish", "pt": "Portuguese", "it": "Italian",
        "uk": "Ukrainian", "pl": "Polish", "tr": "Turkish",
    }

    # APT attribution hints
    apt_hints = {
        "ru": "Possible Russian-speaking threat actor (APT28, APT29, Sandworm)",
        "zh": "Possible Chinese-speaking threat actor (APT1, APT10, APT41)",
        "ko": "Possible North Korean threat actor (Lazarus Group, Kimsuky)",
        "fa": "Possible Iranian threat actor (APT33, APT35, Charming Kitten)",
        "ar": "Possible Middle Eastern threat actor",
    }

    return {
        "file": file_path,
        "language_code": language_code,
        "language_name": lang_map.get(language_code, f"Unknown ({language_code})"),
        "apt_attribution_hint": apt_hints.get(language_code),
        "analysis_time": datetime.utcnow().isoformat(),
    }


def tika_malware_triage(file_path: str) -> dict:
    """
    Quick malware triage using content extraction and heuristic analysis.
    Checks for macros, embedded executables, suspicious URLs, obfuscation, and exploit indicators.

    Args:
        file_path: Path to potentially malicious file

    Returns:
        Risk score (0-100), indicators found, and recommended next steps
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    result = {
        "file": file_path,
        "risk_score": 0,
        "indicators": [],
        "analysis_time": datetime.utcnow().isoformat(),
    }

    ok, msg = _ensure_tika()
    if not ok:
        return {"error": msg}

    # Extract metadata first
    meta_result = tika_extract_metadata(file_path)
    meta = meta_result.get("metadata", {})

    # Extract text
    text_result = tika_extract_text(file_path, max_chars=100000)
    text = text_result.get("text", "")
    suspicious = text_result.get("suspicious", {})

    # --- Heuristic checks ---

    # 1. Macros (Office)
    if meta_result.get("security", {}).get("macros") or any(
        "macro" in str(v).lower() for v in meta.values()
    ):
        result["indicators"].append({"type": "MACROS", "severity": "HIGH",
                                      "detail": "Office macro code detected"})
        result["risk_score"] += 30

    # 2. Embedded executable
    for k, v in meta.items():
        if isinstance(v, str) and any(ext in v.lower()
                                       for ext in [".exe", ".dll", ".vbs", ".ps1", ".bat", ".com"]):
            result["indicators"].append({"type": "EMBEDDED_EXECUTABLE", "severity": "CRITICAL",
                                          "detail": f"{k}: {v}"})
            result["risk_score"] += 40

    # 3. Suspicious URLs in content
    urls = text_result.get("iocs", {}).get("urls", [])
    for url in urls:
        if any(x in url.lower() for x in [".tk", ".pw", ".cc", ".xyz", "pastebin",
                                            "ngrok", "bit.ly", "tinyurl"]):
            result["indicators"].append({"type": "SUSPICIOUS_URL", "severity": "HIGH",
                                          "detail": url})
            result["risk_score"] += 15

    # 4. PowerShell / encoded commands
    if suspicious.get("has_powershell_encoded"):
        result["indicators"].append({"type": "ENCODED_POWERSHELL", "severity": "CRITICAL",
                                      "detail": "PowerShell with encoded command detected"})
        result["risk_score"] += 35

    # 5. Large base64 blob
    if suspicious.get("has_base64_blob"):
        result["indicators"].append({"type": "BASE64_PAYLOAD", "severity": "HIGH",
                                      "detail": "Large base64-encoded blob found"})
        result["risk_score"] += 20

    # 6. API keys in document
    if suspicious.get("has_api_key_hints"):
        result["indicators"].append({"type": "CREDENTIAL_EXPOSURE", "severity": "MEDIUM",
                                      "detail": "Possible API key or token in document"})
        result["risk_score"] += 10

    # 7. Exploit CVE patterns
    cves = text_result.get("iocs", {}).get("cves", [])
    if cves:
        result["indicators"].append({"type": "CVE_REFERENCES", "severity": "MEDIUM",
                                      "detail": f"CVEs: {', '.join(cves[:5])}"})
        result["risk_score"] += 10

    # 8. File type mismatch (magic vs extension)
    content_type = meta_result.get("content_type", "")
    file_ext = os.path.splitext(file_path)[1].lower()
    type_map = {
        ".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats",
        ".xlsx": "application/vnd.openxmlformats", ".zip": "application/zip",
        ".exe": "application/x-msdownload",
    }
    expected = type_map.get(file_ext, "")
    if expected and expected not in content_type:
        result["indicators"].append({
            "type": "FILE_TYPE_MISMATCH", "severity": "HIGH",
            "detail": f"Extension: {file_ext}, Actual type: {content_type}",
        })
        result["risk_score"] += 25

    # Cap score
    result["risk_score"] = min(result["risk_score"], 100)

    # Risk level
    if result["risk_score"] >= 70:
        result["risk_level"] = "CRITICAL"
        result["recommendation"] = "Quarantine immediately. Submit to sandbox (Hybrid Analysis, ANY.RUN)."
    elif result["risk_score"] >= 40:
        result["risk_level"] = "HIGH"
        result["recommendation"] = "Sandbox analysis recommended. Do not open on production system."
    elif result["risk_score"] >= 20:
        result["risk_level"] = "MEDIUM"
        result["recommendation"] = "Review indicators manually. Check with VirusTotal."
    else:
        result["risk_level"] = "LOW"
        result["recommendation"] = "No immediate threat detected. Standard security practices apply."

    return result


TOOLS = {
    "tika_extract_text": tika_extract_text,
    "tika_extract_metadata": tika_extract_metadata,
    "tika_scan_dir": tika_scan_dir,
    "tika_detect_language": tika_detect_language,
    "tika_malware_triage": tika_malware_triage,
}
