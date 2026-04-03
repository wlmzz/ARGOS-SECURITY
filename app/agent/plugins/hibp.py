"""
ARGOS Plugin: Have I Been Pwned (HIBP)
Check if passwords or emails appear in known data breaches.
- Password check: FREE, no API key, k-anonymity model (privacy-safe)
- Email breach check: requires HIBP_API_KEY (~$3.50/month at haveibeenpwned.com/API/Key)
"""
from __future__ import annotations
import hashlib, json, os, urllib.request, urllib.error

MANIFEST = {
    "id":          "hibp",
    "name":        "Have I Been Pwned",
    "description": "Check passwords (free, k-anonymity) and emails against known data breaches. Password check needs no key.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_PWNED_PASSWORDS = "https://api.pwnedpasswords.com/range/{prefix}"
_HIBP_BREACHES   = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
_HIBP_PASTES     = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"


def _hibp_get(url: str, api_key: str) -> tuple[int, dict | str]:
    """Returns (status_code, parsed_body)."""
    headers = {
        "User-Agent":    "ARGOS/1.0",
        "hibp-api-key":  api_key,
        "Accept":        "application/json",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode()
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}


def hibp_password_check(password: str) -> dict:
    """Check if a password has appeared in any known data breach using k-anonymity.
    PRIVACY-SAFE: only the first 5 chars of SHA1 hash are sent — the actual password never leaves your machine."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = urllib.request.Request(
        _PWNED_PASSWORDS.format(prefix=prefix),
        headers={"User-Agent": "ARGOS/1.0", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode()
    except Exception as e:
        return {"error": str(e)}

    # Search for our hash suffix in the response
    count = 0
    for line in body.splitlines():
        if ":" not in line:
            continue
        h, n = line.split(":", 1)
        if h.strip() == suffix:
            count = int(n.strip())
            break

    return {
        "source":      "Have I Been Pwned",
        "pwned":       count > 0,
        "count":       count,
        "verdict":     f"COMPROMISED — seen {count:,} times in breaches. CHANGE THIS PASSWORD." if count > 0
                       else "SAFE — not found in any known breach",
        "privacy_note": "Password was never transmitted. Only SHA1 prefix used (k-anonymity).",
    }


def hibp_email_check(email: str) -> dict:
    """Check if an email address appears in known data breaches (requires HIBP_API_KEY).
    Returns list of breaches with data classes exposed (passwords, emails, phone numbers, etc.)."""
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return {"error": "HIBP_API_KEY not set. Get key at haveibeenpwned.com/API/Key (~$3.50/month)"}

    url = _HIBP_BREACHES.format(email=email) + "?truncateResponse=false"
    code, data = _hibp_get(url, api_key)

    if code == 404:
        return {
            "email":   email,
            "source":  "Have I Been Pwned",
            "pwned":   False,
            "verdict": "SAFE — email not found in any known breach",
            "breaches": [],
        }
    if code == 401:
        return {"error": "Invalid HIBP_API_KEY"}
    if code == 429:
        return {"error": "Rate limited by HIBP API — wait before retrying"}
    if code != 200 or not isinstance(data, list):
        return {"error": f"HIBP API error {code}: {str(data)[:200]}"}

    breaches = []
    for b in data:
        breaches.append({
            "name":         b.get("Name", ""),
            "title":        b.get("Title", ""),
            "domain":       b.get("Domain", ""),
            "breach_date":  b.get("BreachDate", ""),
            "pwn_count":    b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "verified":     b.get("IsVerified", False),
            "sensitive":    b.get("IsSensitive", False),
        })

    return {
        "email":          email,
        "source":         "Have I Been Pwned",
        "pwned":          True,
        "breach_count":   len(breaches),
        "verdict":        f"COMPROMISED — found in {len(breaches)} breach(es)",
        "breaches":       sorted(breaches, key=lambda x: x["breach_date"], reverse=True),
        "exposed_data":   list({dc for b in breaches for dc in b["data_classes"]}),
    }


TOOLS = {
    "hibp_password_check": {
        "fn": hibp_password_check,
        "description": (
            "Check if a password has appeared in any data breach. FREE, no API key needed. "
            "Privacy-safe k-anonymity: only a partial SHA1 prefix is sent, the actual password never leaves. "
            "Returns how many times the password was seen in breaches."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "Password to check (never transmitted in full)"}
            },
            "required": ["password"]
        }
    },
    "hibp_email_check": {
        "fn": hibp_email_check,
        "description": (
            "Check if an email address appears in known data breaches (LinkedIn, Adobe, RockYou2024, etc). "
            "Returns breach names, dates, exposed data types (passwords, emails, phone numbers). "
            "Requires HIBP_API_KEY (~$3.50/month at haveibeenpwned.com/API/Key)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "Email address to check"}
            },
            "required": ["email"]
        }
    },
}
