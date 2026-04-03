"""
ARGOS Plugin: Cloakify — Data Exfiltration Obfuscation (Red Team)
Authorized red team tool for testing DLP controls and exfiltration detection.
Encodes data into innocuous-looking formats (emoji, Twitter trends, LOTR quotes, etc.)
to test if security controls can detect covert data exfiltration.

⚠️  AUTHORIZED RED TEAM / PENTEST ONLY.
    Tests whether your DLP solutions catch covert channel exfiltration.

Auto-installs to /opt/argos/tools/cloakify/
Repo: https://github.com/TryCatchHCF/Cloakify
"""
from __future__ import annotations
import os, subprocess, shutil, tempfile
from pathlib import Path

MANIFEST = {
    "id":          "cloakify",
    "name":        "Cloakify (DLP Evasion Testing)",
    "description": "Authorized red team: encode data into innocuous formats to test DLP/exfil detection. PENTEST ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_CLOAKIFY_DIR = Path("/opt/argos/tools/cloakify")


def _ensure_cloakify() -> bool:
    if _CLOAKIFY_DIR.exists():
        return True
    _CLOAKIFY_DIR.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         "https://github.com/TryCatchHCF/Cloakify.git", str(_CLOAKIFY_DIR)],
        capture_output=True, timeout=120
    )
    return r.returncode == 0


def list_cloakify_ciphers() -> dict:
    """List all available Cloakify ciphers (obfuscation formats).
    Returns the list of cipher files that can be used for encoding.
    Formats include: emoji, Twitter trends, LOTR quotes, sports teams, common words, etc.
    """
    if not _ensure_cloakify():
        return {"error": "Failed to install Cloakify"}

    ciphers_dir = _CLOAKIFY_DIR / "ciphers"
    if not ciphers_dir.exists():
        return {"error": "Ciphers directory not found"}

    cipher_files = sorted(p.name for p in ciphers_dir.iterdir() if p.is_file())
    return {
        "source":       "Cloakify",
        "ciphers_dir":  str(ciphers_dir),
        "cipher_count": len(cipher_files),
        "ciphers":      cipher_files,
        "usage":        "Pass cipher filename (e.g. 'desserts') to cloakify_encode()",
    }


def cloakify_encode(data: str, cipher: str = "desserts",
                    save_path: str = "") -> dict:
    """Encode data using Cloakify — obfuscates as innocent-looking text.
    Used in authorized red teams to test if DLP can detect covert exfiltration channels.
    ⚠️  AUTHORIZED RED TEAM / PENTEST ONLY.

    data:      string data to encode (text, base64, etc.)
    cipher:    cipher name from list_cloakify_ciphers() (default: 'desserts')
    save_path: optional path to save the encoded output
    """
    if not _ensure_cloakify():
        return {"error": "Failed to install Cloakify"}

    cipher_file = _CLOAKIFY_DIR / "ciphers" / cipher
    if not cipher_file.exists():
        # Try with .txt extension
        cipher_file = _CLOAKIFY_DIR / "ciphers" / f"{cipher}.txt"
        if not cipher_file.exists():
            return {"error": f"Cipher '{cipher}' not found. Use list_cloakify_ciphers() to see available ciphers."}

    # Write data to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(data)
        tmp_in = f.name

    try:
        r = subprocess.run(
            ["python3", str(_CLOAKIFY_DIR / "cloakifyFactory.py"),
             tmp_in, str(cipher_file)],
            capture_output=True, text=True, timeout=30,
            cwd=str(_CLOAKIFY_DIR)
        )
        encoded = (r.stdout + r.stderr).strip()

        result = {
            "source":       "Cloakify",
            "cipher_used":  cipher,
            "original_len": len(data),
            "encoded_len":  len(encoded),
            "encoded":      encoded[:3000],
            "note":         "AUTHORIZED RED TEAM TESTING ONLY — tests DLP detection",
        }

        if save_path:
            Path(save_path).write_text(encoded)
            result["saved_to"] = save_path

        return result
    except subprocess.TimeoutExpired:
        return {"error": "Encoding timed out"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        Path(tmp_in).unlink(missing_ok=True)


def cloakify_decode(encoded_data: str, cipher: str = "desserts") -> dict:
    """Decode Cloakify-encoded data back to original.
    Used to verify the encode/decode cycle works and test detection logic.
    ⚠️  AUTHORIZED RED TEAM / PENTEST ONLY.

    encoded_data: the cloakified text
    cipher:       cipher used for encoding (must match)
    """
    if not _ensure_cloakify():
        return {"error": "Failed to install Cloakify"}

    cipher_file = _CLOAKIFY_DIR / "ciphers" / cipher
    if not cipher_file.exists():
        cipher_file = _CLOAKIFY_DIR / "ciphers" / f"{cipher}.txt"
        if not cipher_file.exists():
            return {"error": f"Cipher '{cipher}' not found"}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(encoded_data)
        tmp_enc = f.name

    try:
        r = subprocess.run(
            ["python3", str(_CLOAKIFY_DIR / "decloakify.py"),
             tmp_enc, str(cipher_file)],
            capture_output=True, text=True, timeout=30,
            cwd=str(_CLOAKIFY_DIR)
        )
        decoded = (r.stdout + r.stderr).strip()
        return {
            "source":       "Cloakify",
            "cipher_used":  cipher,
            "decoded":      decoded[:3000],
            "note":         "AUTHORIZED RED TEAM TESTING ONLY",
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        Path(tmp_enc).unlink(missing_ok=True)


TOOLS = {
    "list_cloakify_ciphers": {
        "fn": list_cloakify_ciphers,
        "description": (
            "List all Cloakify obfuscation ciphers (emoji, Twitter trends, LOTR quotes, sports teams, etc.). "
            "Use with cloakify_encode() to test DLP evasion detection."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "cloakify_encode": {
        "fn": cloakify_encode,
        "description": (
            "Encode data into innocuous-looking text using Cloakify. "
            "Tests whether DLP/exfiltration detection can catch covert channels. "
            "⚠️ AUTHORIZED RED TEAM / PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "data":      {"type": "string",  "description": "Data to encode (text, base64, etc.)"},
                "cipher":    {"type": "string",  "description": "Cipher name (default: 'desserts'). Use list_cloakify_ciphers() to see options."},
                "save_path": {"type": "string",  "description": "Optional path to save encoded output"},
            },
            "required": ["data"]
        }
    },
    "cloakify_decode": {
        "fn": cloakify_decode,
        "description": (
            "Decode Cloakify-encoded data back to original. "
            "⚠️ AUTHORIZED RED TEAM / PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "encoded_data": {"type": "string", "description": "Cloakified text to decode"},
                "cipher":       {"type": "string", "description": "Cipher used for encoding (default: 'desserts')"},
            },
            "required": ["encoded_data"]
        }
    },
}
