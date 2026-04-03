#!/usr/bin/env python3
"""
ARGOS Installer — Cross-Platform
Installs the ARGOS agent as a system service.

Usage:
    python install.py                      # Interactive
    python install.py --mode=standalone    # Non-interactive
    python install.py --uninstall          # Remove ARGOS

MIT License
"""

import os
import sys
import json
import shutil
import platform
import subprocess
import argparse
from pathlib import Path

VERSION = "0.1.0"
PLATFORM = platform.system().lower()  # linux / darwin / windows
HOME = Path.home()
ARGOS_DIR = HOME / ".argos"
VENV_DIR = ARGOS_DIR / "venv"
CONFIG_PATH = ARGOS_DIR / "config.json"
REPO_ROOT = Path(__file__).parent.parent.resolve()

BANNER = """
\033[36m  █████╗ ██████╗  ██████╗  ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗██╔════╝
 ███████║██████╔╝██║  ███╗██║   ██║███████╗
 ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
 ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝\033[0m
\033[90m Open Source AI Security Platform — v{version}
 Security is a right, not a privilege.\033[0m
""".format(version=VERSION)

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def ok(msg): print(f"  \033[32m✓\033[0m {msg}")
def info(msg): print(f"  \033[90m·\033[0m {msg}")
def warn(msg): print(f"  \033[33m!\033[0m {msg}")
def err(msg): print(f"  \033[31m✗\033[0m {msg}")
def section(title): print(f"\n\033[1m{title}\033[0m")

def run(cmd, check=True, capture=False):
    """Run a shell command."""
    return subprocess.run(
        cmd, shell=isinstance(cmd, str),
        check=check,
        capture_output=capture,
        text=True
    )

def run_ok(cmd) -> bool:
    """Run command, return True if successful."""
    try:
        subprocess.run(cmd, shell=isinstance(cmd, str), check=True,
                       capture_output=True, text=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def python_version_ok() -> bool:
    return sys.version_info >= (3, 10)

def pip_path() -> str:
    if VENV_DIR.exists():
        if PLATFORM == "windows":
            return str(VENV_DIR / "Scripts" / "pip")
        return str(VENV_DIR / "bin" / "pip")
    return "pip3"

def python_path() -> str:
    if VENV_DIR.exists():
        if PLATFORM == "windows":
            return str(VENV_DIR / "Scripts" / "python")
        return str(VENV_DIR / "bin" / "python")
    return sys.executable

# ─── CHECKS ──────────────────────────────────────────────────────────────────

def check_prerequisites():
    section("Checking prerequisites")

    if not python_version_ok():
        err(f"Python 3.10+ required (found {sys.version})")
        sys.exit(1)
    ok(f"Python {sys.version.split()[0]}")

    if PLATFORM == "linux":
        if os.geteuid() != 0:
            warn("Not running as root — firewall and port binding features may be limited")
            info("Re-run with sudo for full functionality")
        else:
            ok("Running as root")
    elif PLATFORM == "darwin":
        if os.geteuid() != 0:
            warn("Not running as root — firewall features may be limited")

    # Check pip
    if not run_ok([sys.executable, "-m", "pip", "--version"]):
        err("pip not found")
        sys.exit(1)
    ok("pip available")

# ─── VIRTUALENV ──────────────────────────────────────────────────────────────

def setup_virtualenv():
    section("Setting up virtual environment")
    ARGOS_DIR.mkdir(parents=True, exist_ok=True)

    if not VENV_DIR.exists():
        info(f"Creating venv at {VENV_DIR}")
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
        ok("Virtual environment created")
    else:
        ok("Virtual environment already exists")

def install_dependencies():
    section("Installing Python dependencies")
    req_file = REPO_ROOT / "requirements.txt"

    if req_file.exists():
        info(f"Installing from {req_file}")
        run([pip_path(), "install", "-q", "-r", str(req_file)])
        ok("Agent dependencies installed")
    else:
        info("No requirements.txt found — installing core deps")
        run([pip_path(), "install", "-q", "psutil", "requests", "watchdog"])
        ok("Core dependencies installed")

# ─── OLLAMA ───────────────────────────────────────────────────────────────────

def check_ollama():
    section("Checking Ollama (AI engine)")

    if run_ok(["ollama", "version"]):
        ok("Ollama is installed")
        return True
    else:
        warn("Ollama not found")
        info("Ollama is required for the AI engine.")
        info("Install it from: https://ollama.ai/")
        if PLATFORM == "linux":
            info("Quick install: curl -fsSL https://ollama.ai/install.sh | sh")
        elif PLATFORM == "darwin":
            info("Download: https://ollama.ai/download/mac")
        elif PLATFORM == "windows":
            info("Download: https://ollama.ai/download/windows")
        info("ARGOS will use rule-based fallback until Ollama is installed.")
        return False

def pull_model(model: str = "phi4:14b"):
    section(f"Pulling AI model: {model}")

    # Check if model already exists
    result = run(["ollama", "list"], capture=True, check=False)
    if result.returncode == 0 and model.split(":")[0] in result.stdout:
        ok(f"Model {model} already available")
        return

    info(f"Pulling {model} — this may take a while (model is ~10GB)...")
    info("You can monitor progress in a separate terminal: ollama pull " + model)

    try:
        # Run pull with live output
        proc = subprocess.Popen(
            ["ollama", "pull", model],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in proc.stdout:
            print(f"    {line.rstrip()}")
        proc.wait()
        if proc.returncode == 0:
            ok(f"Model {model} ready")
        else:
            warn(f"Model pull failed — ARGOS will use fallback engine")
    except FileNotFoundError:
        warn("Ollama not found — skipping model pull")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def create_config(mode: str, autonomy: str, server_url: str = "", token: str = ""):
    section("Creating configuration")
    ARGOS_DIR.mkdir(parents=True, exist_ok=True)

    config = {
        "mode": mode,
        "server_url": server_url,
        "api_token": token,
        "ai_model": "phi4:14b",
        "ollama_url": "http://localhost:11434",
        "scan_interval": 5,
        "autonomy_level": autonomy,
        "honeypot_enabled": True,
        "community_intel": False,
        "log_level": "INFO"
    }

    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    ok(f"Config written to {CONFIG_PATH}")
    ok(f"Mode: {mode} | Autonomy: {autonomy}")

# ─── SYSTEM SERVICE ───────────────────────────────────────────────────────────

def install_systemd():
    """Install ARGOS as a systemd service (Linux)."""
    service_content = f"""[Unit]
Description=ARGOS AI Security Agent
Documentation=https://github.com/argos-security/argos
After=network.target

[Service]
Type=simple
User=root
ExecStart={python_path()} {REPO_ROOT}/argos_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=argos

[Install]
WantedBy=multi-user.target
"""
    service_path = Path("/etc/systemd/system/argos.service")
    try:
        with open(service_path, "w") as f:
            f.write(service_content)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "argos"])
        ok(f"Systemd service installed: {service_path}")
        ok("Service enabled (start with: systemctl start argos)")
        return True
    except PermissionError:
        warn("Cannot write to /etc/systemd/system/ — not running as root")
        return False

def install_launchd():
    """Install ARGOS as a LaunchDaemon (macOS)."""
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.argos.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path()}</string>
        <string>{REPO_ROOT}/argos_agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{ARGOS_DIR}/logs/argos.log</string>
    <key>StandardErrorPath</key>
    <string>{ARGOS_DIR}/logs/argos-error.log</string>
</dict>
</plist>
"""
    (ARGOS_DIR / "logs").mkdir(parents=True, exist_ok=True)
    plist_path = Path("/Library/LaunchDaemons/io.argos.agent.plist")
    try:
        with open(plist_path, "w") as f:
            f.write(plist_content)
        run(["launchctl", "load", str(plist_path)])
        ok(f"LaunchDaemon installed: {plist_path}")
        return True
    except PermissionError:
        # Try user LaunchAgent as fallback
        user_plist = HOME / "Library" / "LaunchAgents" / "io.argos.agent.plist"
        user_plist.parent.mkdir(parents=True, exist_ok=True)
        with open(user_plist, "w") as f:
            f.write(plist_content)
        run_ok(["launchctl", "load", str(user_plist)])
        ok(f"LaunchAgent installed (user): {user_plist}")
        warn("Running as user agent — some features require root")
        return True

def install_windows_service():
    """Install ARGOS as a Windows Service using sc.exe."""
    try:
        run([
            "sc", "create", "ARGOS",
            "binPath=", f'"{sys.executable}" "{REPO_ROOT / "argos_agent.py"}"',
            "DisplayName=", "ARGOS AI Security Agent",
            "start=", "auto"
        ])
        run(["sc", "description", "ARGOS", "ARGOS Open Source AI Security Platform"])
        ok("Windows Service installed")
        ok("Start with: sc start ARGOS")
        return True
    except Exception as e:
        warn(f"Service installation failed: {e}")
        return False

def install_service():
    section("Installing system service")

    if PLATFORM == "linux":
        if shutil.which("systemctl"):
            return install_systemd()
        else:
            warn("systemctl not found — skipping service installation")
            info(f"Manual start: python3 {REPO_ROOT}/argos_agent.py")
    elif PLATFORM == "darwin":
        return install_launchd()
    elif PLATFORM == "windows":
        return install_windows_service()

    return False

# ─── UNINSTALL ────────────────────────────────────────────────────────────────

def uninstall():
    section("Uninstalling ARGOS")

    # Stop and remove service
    if PLATFORM == "linux":
        run_ok(["systemctl", "stop", "argos"])
        run_ok(["systemctl", "disable", "argos"])
        Path("/etc/systemd/system/argos.service").unlink(missing_ok=True)
        run_ok(["systemctl", "daemon-reload"])
        ok("Systemd service removed")
    elif PLATFORM == "darwin":
        plist = Path("/Library/LaunchDaemons/io.argos.agent.plist")
        user_plist = HOME / "Library" / "LaunchAgents" / "io.argos.agent.plist"
        for p in [plist, user_plist]:
            if p.exists():
                run_ok(["launchctl", "unload", str(p)])
                p.unlink()
        ok("LaunchDaemon removed")
    elif PLATFORM == "windows":
        run_ok(["sc", "stop", "ARGOS"])
        run_ok(["sc", "delete", "ARGOS"])
        ok("Windows Service removed")

    # Remove venv (optional — keep data)
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
        ok("Virtual environment removed")

    info(f"Config and data preserved at: {ARGOS_DIR}")
    info("To remove all data: rm -rf ~/.argos")
    ok("ARGOS uninstalled")

# ─── INTERACTIVE SETUP ────────────────────────────────────────────────────────

def ask(prompt: str, default: str, choices: list[str] | None = None) -> str:
    choices_str = f" [{'/'.join(choices)}]" if choices else ""
    default_str = f" (default: {default})"
    while True:
        answer = input(f"  {prompt}{choices_str}{default_str}: ").strip()
        if not answer:
            return default
        if choices and answer not in choices:
            print(f"  Please choose from: {', '.join(choices)}")
            continue
        return answer

def interactive_setup() -> dict:
    print("\n  Welcome to ARGOS setup. Press Enter to accept defaults.\n")

    mode = ask("Deployment mode", "standalone", ["standalone", "self-hosted", "cloud"])
    autonomy = ask("Autonomy level", "semi", ["full", "semi", "supervised"])

    server_url = ""
    token = ""
    if mode in ("self-hosted", "cloud"):
        server_url = ask("Server URL", "https://argos.yourdomain.com")
        token = ask("API token", "")

    return {"mode": mode, "autonomy": autonomy, "server_url": server_url, "token": token}

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="ARGOS Installer")
    parser.add_argument("--mode", choices=["standalone", "self-hosted", "cloud"],
                        help="Deployment mode (skip interactive setup)")
    parser.add_argument("--autonomy", choices=["full", "semi", "supervised"],
                        default="semi", help="Autonomy level")
    parser.add_argument("--server", default="", help="Server URL")
    parser.add_argument("--token", default="", help="API token")
    parser.add_argument("--no-service", action="store_true", help="Skip system service installation")
    parser.add_argument("--no-model", action="store_true", help="Skip Ollama model pull")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall ARGOS")
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
        return

    check_prerequisites()
    setup_virtualenv()
    install_dependencies()

    # Ollama check (non-blocking)
    ollama_available = check_ollama()
    if ollama_available and not args.no_model:
        pull_model("phi4:14b")
    elif not ollama_available:
        info("Skipping model pull — install Ollama first, then run: ollama pull phi4:14b")

    # Config
    if args.mode:
        create_config(args.mode, args.autonomy, args.server, args.token)
    else:
        setup = interactive_setup()
        create_config(**setup)

    # Service
    if not args.no_service:
        install_service()
    else:
        info("Skipping service installation (--no-service)")

    # Done
    section("Installation complete!")
    ok("ARGOS is installed and ready")
    print()
    info(f"Config:    {CONFIG_PATH}")
    info(f"Logs:      {ARGOS_DIR / 'logs'}/")
    info(f"Evidence:  {ARGOS_DIR / 'evidence'}/")
    info(f"Database:  {ARGOS_DIR / 'threats.db'}")
    print()
    print("  To start ARGOS manually:")
    print(f"    \033[36mpython3 {REPO_ROOT}/argos_agent.py\033[0m")
    print()
    print("  To start with debug output:")
    print(f"    \033[36mpython3 {REPO_ROOT}/argos_agent.py --debug\033[0m")
    print()
    if PLATFORM == "linux":
        print("  To start as system service:")
        print("    \033[36msystemctl start argos\033[0m")
    elif PLATFORM == "darwin":
        print("  Service starts automatically at login.")
    print()

if __name__ == "__main__":
    main()
