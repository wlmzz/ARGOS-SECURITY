"""
ARGOS Plugin: Username OSINT & Social Media Recon
Track usernames and social media presences across platforms.

Tools:
  - userrecon:      username availability check across 200+ platforms
  - SilverInstaEye: Instagram profile OSINT (followers, posts, bio, links)
  - URLextractor:   extract all URLs from a target webpage

Auto-installs to /opt/argos/tools/
  userrecon:      https://github.com/wishihab/userrecon (or p1ngul1n0/blackbird)
  SilverInstaEye: https://github.com/wlmzz/SilverInstaEye
  URLextractor:   https://github.com/wlmzz/URLextractor
"""
from __future__ import annotations
import os, subprocess, json, re, urllib.request
from pathlib import Path

MANIFEST = {
    "id":          "username_osint",
    "name":        "Username OSINT (userrecon + Instagram + URL extractor)",
    "description": "Username recon across 200+ platforms, Instagram OSINT, URL extraction from web pages.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TOOLS_BASE       = Path("/opt/argos/tools")
_USERRECON_DIR    = _TOOLS_BASE / "userrecon"
_INSTA_DIR        = _TOOLS_BASE / "SilverInstaEye"
_URLEXTRACT_DIR   = _TOOLS_BASE / "URLextractor"
_TIMEOUT          = 120


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


def userrecon_search(username: str, timeout: int = _TIMEOUT) -> dict:
    """Search a username across 200+ social media and online platforms.
    Uses userrecon (or falls back to Sherlock which is already installed).

    username: the username/handle to search for
    """
    # Try userrecon first
    if not _clone_tool("wishihab/userrecon", _USERRECON_DIR):
        _clone_tool("thewhiteh4t/nexfil", _USERRECON_DIR)

    script = next(
        (p for p in [
            _USERRECON_DIR / "userrecon.py",
            _USERRECON_DIR / "nexfil.py",
        ] if p.exists()),
        None
    )

    if script:
        try:
            r = subprocess.run(
                ["python3", str(script), username],
                capture_output=True, text=True, timeout=timeout,
                cwd=str(_USERRECON_DIR)
            )
            output = (r.stdout + r.stderr)[-5000:]
            # Parse found URLs
            urls = re.findall(r'https?://[^\s\'"<>]+', output)
            return {
                "username":   username,
                "tool":       script.name,
                "found_urls": urls[:30],
                "output":     output[-2000:],
                "source":     "ARGOS Username OSINT",
            }
        except subprocess.TimeoutExpired:
            pass

    # Fallback: Sherlock (already installed)
    if os.path.exists("/usr/local/bin/sherlock") or subprocess.run(
        ["which", "sherlock"], capture_output=True
    ).returncode == 0:
        try:
            r = subprocess.run(
                ["sherlock", "--print-found", username],
                capture_output=True, text=True, timeout=timeout
            )
            output = r.stdout + r.stderr
            urls = re.findall(r'https?://[^\s\'"<>]+', output)
            return {
                "username":   username,
                "tool":       "sherlock",
                "found_urls": urls[:30],
                "output":     output[-2000:],
                "source":     "ARGOS Username OSINT",
            }
        except Exception:
            pass

    return {"error": "userrecon/sherlock not available", "username": username}


def instagram_recon(username: str, timeout: int = 60) -> dict:
    """Gather public Instagram profile information.
    Collects: followers, following, posts count, bio, external links, tagged photos.

    username: Instagram username (without @)
    """
    if not _clone_tool("wlmzz/SilverInstaEye", _INSTA_DIR):
        # Try alternative Instagram OSINT tools
        _clone_tool("Greenwolf/social_mapper", _INSTA_DIR)

    script = next(
        (p for p in [
            _INSTA_DIR / "SilverInstaEye.py",
            _INSTA_DIR / "insta.py",
            _INSTA_DIR / "main.py",
        ] if p.exists()),
        None
    )

    # Try direct Instagram API (public endpoint, no auth needed for public profiles)
    try:
        url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; ARGOS/1.0)")
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            user = data.get("graphql", {}).get("user", data.get("data", {}).get("user", {}))
            if user:
                return {
                    "username":       username,
                    "full_name":      user.get("full_name", ""),
                    "bio":            user.get("biography", ""),
                    "followers":      user.get("edge_followed_by", {}).get("count", 0),
                    "following":      user.get("edge_follow", {}).get("count", 0),
                    "posts":          user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                    "is_private":     user.get("is_private", False),
                    "is_verified":    user.get("is_verified", False),
                    "external_url":   user.get("external_url", ""),
                    "source":         "Instagram public API",
                }
    except Exception:
        pass

    # Try the local script
    if script:
        try:
            r = subprocess.run(
                ["python3", str(script), "-u", username],
                capture_output=True, text=True, timeout=timeout,
                cwd=str(_INSTA_DIR)
            )
            return {
                "username": username,
                "tool":     script.name,
                "output":   (r.stdout + r.stderr)[-3000:],
                "source":   "SilverInstaEye",
            }
        except Exception as e:
            return {"error": str(e), "username": username}

    return {"error": "Instagram OSINT tool not available", "username": username}


def extract_urls_from_page(url: str, depth: int = 1,
                            timeout: int = 30) -> dict:
    """Extract all URLs from a web page.
    Useful for mapping attack surface, finding admin panels, hidden endpoints.

    url:   target webpage URL
    depth: number of links to follow (default: 1 = just this page)
    """
    if not _clone_tool("wlmzz/URLextractor", _URLEXTRACT_DIR):
        pass  # Use built-in urllib fallback

    # Try URLextractor script
    script = next(
        (p for p in [
            _URLEXTRACT_DIR / "URLextractor.py",
            _URLEXTRACT_DIR / "main.py",
        ] if p.exists()),
        None
    )

    if script:
        try:
            r = subprocess.run(
                ["python3", str(script), url],
                capture_output=True, text=True, timeout=timeout,
                cwd=str(_URLEXTRACT_DIR)
            )
            output = r.stdout + r.stderr
            urls = re.findall(r'https?://[^\s\'"<>\]]+', output)
            return {
                "source_url": url,
                "tool":       "URLextractor",
                "url_count":  len(urls),
                "urls":       urls[:100],
                "output":     output[-1000:],
            }
        except Exception:
            pass

    # Fallback: built-in urllib
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; ARGOS/1.0)")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read().decode(errors="replace")

        urls = list(set(re.findall(r'https?://[^\s\'"<>\]]+', content)))
        relative = list(set(re.findall(r'href=["\']([^"\'<>]+)', content)))

        return {
            "source_url":   url,
            "tool":         "urllib fallback",
            "url_count":    len(urls),
            "urls":         urls[:100],
            "relative_urls": relative[:50],
        }
    except Exception as e:
        return {"error": str(e), "source_url": url}



# ── sherlock-rs (Rust rewrite of Sherlock) ────────────────────────────────────

import subprocess as _subprocess
import shutil as _shutil
import re as _re


def _get_sherlock_rs_bin():
    import os
    for p in ["/usr/local/bin/sherlock-rs",
              os.path.expanduser("~/.cargo/bin/sherlock-rs"),
              os.path.expanduser("~/.cargo/bin/sherlock")]:
        if os.path.exists(p):
            return p
    return _shutil.which("sherlock-rs") or _shutil.which("sherlock")


def sherlock_rs_search(usernames: list, proxy: str = None, timeout: int = 120) -> dict:
    """
    Search usernames across 400+ social networks using sherlock-rs (Rust Sherlock).
    Faster and more accurate than the Python original, with structured output.

    Args:
        usernames: List of usernames to search (up to 5 at once)
        proxy: Optional proxy URL (e.g. socks5://127.0.0.1:9050)
        timeout: Total timeout in seconds

    Returns:
        Platforms where each username was found, with URLs
    """
    if not usernames or not isinstance(usernames, list):
        return {"error": "Pass a list of usernames, e.g. ['johndoe', 'jdoe']"}
    usernames = usernames[:5]

    bin_path = _get_sherlock_rs_bin()
    if not bin_path:
        if not _shutil.which("cargo"):
            return {"error": "sherlock-rs not installed and cargo not found",
                    "install": "curl https://sh.rustup.rs -sSf | sh && cargo install sherlock-rs",
                    "fallback": "userrecon_search() is available as alternative"}
        rc, out, err = (lambda r: (r.returncode, r.stdout, r.stderr))(
            _subprocess.run(
                ["cargo", "install", "sherlock-rs", "--locked"],
                capture_output=True, text=True, timeout=300,
            )
        )
        import os
        bin_path = os.path.expanduser("~/.cargo/bin/sherlock-rs")
        if not os.path.exists(bin_path):
            return {"error": f"Install failed: {err[:400]}",
                    "fallback": "userrecon_search() is available as alternative"}

    results = {}
    for username in usernames:
        cmd = [bin_path, username]
        if proxy:
            cmd += ["--proxy", proxy]
        try:
            r = _subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = r.stdout + r.stderr
            found = []
            for line in output.splitlines():
                if "[+]" in line or ("found" in line.lower() and "http" in line.lower()):
                    url_m = _re.search(r'https?://\S+', line)
                    if url_m:
                        found.append(url_m.group(0).rstrip("."))
            results[username] = {
                "found_count": len(found),
                "urls": found,
                "raw": output[:3000],
            }
        except _subprocess.TimeoutExpired:
            results[username] = {"error": f"Timed out after {timeout}s",
                                  "fallback": "Try userrecon_search()"}
        except Exception as e:
            results[username] = {"error": str(e)}

    return {
        "usernames": usernames,
        "results": results,
        "total_found": sum(r.get("found_count", 0) for r in results.values()),
    }

TOOLS = {
    "userrecon_search": {
        "fn": userrecon_search,
        "description": (
            "Search a username across 200+ social media and online platforms. "
            "Returns all URLs where the username exists."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {"type": "string",  "description": "Username/handle to search"},
                "timeout":  {"type": "integer", "description": "Max seconds (default: 120)"},
            },
            "required": ["username"]
        }
    },
    "instagram_recon": {
        "fn": instagram_recon,
        "description": (
            "Gather public Instagram profile information: followers, following, posts, bio, links. "
            "Works on public profiles only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {"type": "string",  "description": "Instagram username (without @)"},
                "timeout":  {"type": "integer", "description": "Max seconds (default: 60)"},
            },
            "required": ["username"]
        }
    },
    "sherlock_rs_search": {
        "fn": sherlock_rs_search,
        "description": (
            "Search 1-5 usernames across 400+ social networks using sherlock-rs (Rust). "
            "Faster than Python original. Returns all platform URLs where username exists."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "usernames": {"type": "array", "items": {"type": "string"},
                              "description": "List of usernames to search (max 5)"},
                "proxy":     {"type": "string", "description": "Optional SOCKS5/HTTP proxy URL"},
                "timeout":   {"type": "integer", "description": "Timeout in seconds (default: 120)"},
            },
            "required": ["usernames"]
        }
    },
    "extract_urls_from_page": {
        "fn": extract_urls_from_page,
        "description": (
            "Extract all URLs from a web page. "
            "Useful for attack surface mapping, finding admin panels, hidden endpoints."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url":     {"type": "string",  "description": "Target webpage URL"},
                "timeout": {"type": "integer", "description": "Max seconds (default: 30)"},
            },
            "required": ["url"]
        }
    },
}
