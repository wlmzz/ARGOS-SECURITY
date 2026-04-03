"""
ARGOS Plugin: Hak5 Hardware Attack Payloads
Manage and retrieve payloads for Hak5 hardware attack devices:
  - O.MG Cable / O.MG Plug  (HID attack cable)
  - Bash Bunny              (multi-function USB attack)
  - Key Croc                (keylogger + HID injection)
  - Shark Jack              (network attack device)
  - USB Rubber Ducky        (HID keystroke injection)
  - Wifi Pineapple          (WiFi pentesting)

⚠️  AUTHORIZED PENETRATION TESTING ONLY.
    Hak5 devices require physical access. Use only on systems you own
    or have explicit written permission to test.

Auto-installs payload libraries to /opt/argos/tools/hak5/
Repos: wlmzz/omg-payloads, wlmzz/bashbunny-payloads,
       wlmzz/keycroc-payloads, wlmzz/sharkjack-payloads
"""
from __future__ import annotations
import os, subprocess, re
from pathlib import Path

MANIFEST = {
    "id":          "hak5_payloads",
    "name":        "Hak5 Hardware Payloads",
    "description": "Browse and retrieve payloads for O.MG, Bash Bunny, Key Croc, Shark Jack, Rubber Ducky. Authorized pentesting only.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_HAK5_BASE = Path("/opt/argos/tools/hak5")

_DEVICE_REPOS = {
    "omg":        ("wlmzz/omg-payloads",        _HAK5_BASE / "omg-payloads"),
    "bashbunny":  ("wlmzz/bashbunny-payloads",   _HAK5_BASE / "bashbunny-payloads"),
    "keycroc":    ("wlmzz/keycroc-payloads",     _HAK5_BASE / "keycroc-payloads"),
    "sharkjack":  ("wlmzz/sharkjack-payloads",   _HAK5_BASE / "sharkjack-payloads"),
    "ducky":      ("hak5/usbrubberducky-payloads", _HAK5_BASE / "ducky-payloads"),
}

_DEVICE_DESCRIPTIONS = {
    "omg":       "O.MG Cable/Plug — HID attack cable with WiFi, keystroke injection, exfil",
    "bashbunny": "Bash Bunny — multi-function USB: HID, mass storage, network attacks",
    "keycroc":   "Key Croc — inline keylogger + HID injection, WiFi, scripting",
    "sharkjack": "Shark Jack — portable network attack: recon, exploitation, exfil",
    "ducky":     "USB Rubber Ducky — classic keystroke injection device",
}


def _ensure_device_payloads(device: str) -> bool:
    if device not in _DEVICE_REPOS:
        return False
    repo, dest = _DEVICE_REPOS[device]
    if dest.exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         f"https://github.com/{repo}.git", str(dest)],
        capture_output=True, timeout=120
    )
    return r.returncode == 0


def hak5_list_devices() -> dict:
    """List Hak5 attack devices and their payload libraries.
    Shows which device payload libraries are installed.
    """
    devices = {}
    for device, (repo, dest) in _DEVICE_REPOS.items():
        installed = dest.exists()
        payload_count = 0
        if installed:
            # Count payload files
            payload_count = len([f for f in dest.rglob("*")
                                  if f.suffix in (".txt", ".sh", ".py", ".ps1", ".duckyscript")
                                  and f.is_file()])
        devices[device] = {
            "description": _DEVICE_DESCRIPTIONS.get(device, ""),
            "installed":   installed,
            "repo":        repo,
            "payload_count": payload_count,
            "path":        str(dest) if installed else "not installed (auto-clones on first use)",
        }
    return {
        "source":  "Hak5 Payload Libraries",
        "devices": devices,
        "note":    "AUTHORIZED PENETRATION TESTING ONLY — requires physical device access",
    }


def hak5_list_payloads(device: str, category: str = "",
                        search: str = "") -> dict:
    """List available payloads for a specific Hak5 device.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    device:   'omg' | 'bashbunny' | 'keycroc' | 'sharkjack' | 'ducky'
    category: filter by category/directory name
    search:   search payload names
    """
    if device not in _DEVICE_REPOS:
        return {"error": f"Unknown device '{device}'. Choose: {list(_DEVICE_REPOS.keys())}"}

    if not _ensure_device_payloads(device):
        return {"error": f"Failed to install {device} payload library"}

    _, dest = _DEVICE_REPOS[device]
    payloads = []

    for f in sorted(dest.rglob("*")):
        if not f.is_file():
            continue
        if f.suffix not in (".txt", ".sh", ".py", ".ps1", ".duckyscript", ".bb", ""):
            continue
        rel = str(f.relative_to(dest))
        if category and category.lower() not in rel.lower():
            continue
        if search and search.lower() not in rel.lower():
            continue
        payloads.append({
            "name":     f.name,
            "path":     rel,
            "size_kb":  round(f.stat().st_size / 1024, 1),
        })

    return {
        "device":    device,
        "source":    "Hak5 Payload Library",
        "category":  category or "all",
        "search":    search or "none",
        "count":     len(payloads),
        "payloads":  payloads[:40],
        "note":      "AUTHORIZED PENETRATION TESTING ONLY",
    }


def hak5_get_payload(device: str, payload_path: str) -> dict:
    """Read the content of a specific Hak5 device payload.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    device:       'omg' | 'bashbunny' | 'keycroc' | 'sharkjack' | 'ducky'
    payload_path: relative path from hak5_list_payloads() result
    """
    if device not in _DEVICE_REPOS:
        return {"error": f"Unknown device '{device}'"}

    if not _ensure_device_payloads(device):
        return {"error": f"Failed to install {device} payload library"}

    _, dest = _DEVICE_REPOS[device]
    full_path = dest / payload_path

    if not full_path.exists():
        return {"error": f"Payload '{payload_path}' not found", "device": device}

    try:
        content = full_path.read_text(errors="replace")
        return {
            "device":       device,
            "payload_path": payload_path,
            "content":      content[:5000],
            "size_kb":      round(full_path.stat().st_size / 1024, 1),
            "note":         "AUTHORIZED PENETRATION TESTING ONLY",
        }
    except Exception as e:
        return {"error": str(e)}


def hak5_search_payloads(query: str, device: str = "") -> dict:
    """Search across all Hak5 device payload libraries.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    query:  keyword to search in payload names and content
    device: limit to specific device (optional)
    """
    devices_to_search = [device] if device else list(_DEVICE_REPOS.keys())
    results = []

    for dev in devices_to_search:
        if not _DEVICE_REPOS[dev][1].exists():
            if not _ensure_device_payloads(dev):
                continue

        _, dest = _DEVICE_REPOS[dev]
        for f in sorted(dest.rglob("*")):
            if not f.is_file():
                continue
            rel = str(f.relative_to(dest))
            # Search in filename
            if query.lower() in rel.lower():
                results.append({"device": dev, "path": rel, "match": "filename"})
                continue
            # Search in content (text files only, small files)
            if f.stat().st_size < 50000 and f.suffix in (".txt", ".sh", ".py", ".ps1"):
                try:
                    if query.lower() in f.read_text(errors="replace").lower():
                        results.append({"device": dev, "path": rel, "match": "content"})
                except Exception:
                    pass

    return {
        "query":   query,
        "device":  device or "all",
        "source":  "Hak5 Payload Libraries",
        "count":   len(results),
        "results": results[:30],
        "note":    "AUTHORIZED PENETRATION TESTING ONLY",
    }


TOOLS = {
    "hak5_list_devices": {
        "fn": hak5_list_devices,
        "description": (
            "List Hak5 attack devices and their payload libraries: "
            "O.MG, Bash Bunny, Key Croc, Shark Jack, Rubber Ducky. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "hak5_list_payloads": {
        "fn": hak5_list_payloads,
        "description": (
            "List available payloads for a Hak5 device (omg, bashbunny, keycroc, sharkjack, ducky). "
            "Filter by category or search by name. ⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device":   {"type": "string", "description": "'omg' | 'bashbunny' | 'keycroc' | 'sharkjack' | 'ducky'"},
                "category": {"type": "string", "description": "Filter by category/directory name"},
                "search":   {"type": "string", "description": "Search payload names"},
            },
            "required": ["device"]
        }
    },
    "hak5_get_payload": {
        "fn": hak5_get_payload,
        "description": (
            "Read the content of a Hak5 device payload file. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device":       {"type": "string", "description": "Device name (omg, bashbunny, etc.)"},
                "payload_path": {"type": "string", "description": "Relative path from hak5_list_payloads()"},
            },
            "required": ["device", "payload_path"]
        }
    },
    "hak5_search_payloads": {
        "fn": hak5_search_payloads,
        "description": (
            "Search across all Hak5 payload libraries by keyword. "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query":  {"type": "string", "description": "Keyword to search"},
                "device": {"type": "string", "description": "Limit to specific device (optional)"},
            },
            "required": ["query"]
        }
    },
}
