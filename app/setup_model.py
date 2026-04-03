#!/usr/bin/env python3
"""
ARGOS Model Setup
Imports a local GGUF model into Ollama so ARGOS can use it.

Usage:
    python setup_model.py                          # reads from ~/.argos/config.json
    python setup_model.py --path /path/to/model.gguf --name argos-cybersec
"""

import json
import sys
import subprocess
import argparse
from pathlib import Path

CONFIG_PATH = Path.home() / ".argos" / "config.json"

ARGOS_SYSTEM_PROMPT = """You are ARGOS, an autonomous cybersecurity AI analyst.
Analyze the threat event described and respond with a JSON object containing exactly these fields:
- severity_confirmed: boolean — does the data confirm the reported severity?
- action: string — one of: block_ip, deploy_honeypot, isolate_process, close_port, alert_human, monitor
- reasoning: string — brief explanation, max 2 sentences
- confidence: float 0.0-1.0 — your confidence in this assessment
- escalate_to_human: boolean — should a human review this?

Action selection guide:
- block_ip: confirmed attacker, brute force, repeat offender
- deploy_honeypot: port scan, gather attacker intelligence
- isolate_process: confirmed malware process
- close_port: vulnerable port being exploited
- alert_human: ambiguous, novel attack, low confidence
- monitor: low-risk anomaly, observation only

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def save_config(data: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)


def check_ollama() -> bool:
    try:
        r = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def start_ollama():
    """Start Ollama server if not running."""
    import requests
    try:
        requests.get("http://localhost:11434/api/tags", timeout=2)
        print("  ✓ Ollama already running")
        return True
    except Exception:
        pass

    print("  · Starting Ollama...")
    subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    import time
    for _ in range(15):
        time.sleep(1)
        try:
            requests.get("http://localhost:11434/api/tags", timeout=2)
            print("  ✓ Ollama started")
            return True
        except Exception:
            pass

    print("  ✗ Could not start Ollama")
    return False


def model_exists(name: str) -> bool:
    try:
        r = subprocess.run(["ollama", "list"], capture_output=True, text=True)
        return name in r.stdout
    except Exception:
        return False


def create_modelfile(gguf_path: str) -> str:
    return f"""FROM {gguf_path}

SYSTEM \"\"\"{ARGOS_SYSTEM_PROMPT}\"\"\"

PARAMETER temperature 0.1
PARAMETER num_ctx 4096
PARAMETER num_predict 512
"""


def import_model(gguf_path: str, model_name: str) -> bool:
    gguf = Path(gguf_path)
    if not gguf.exists():
        print(f"  ✗ GGUF file not found: {gguf_path}")
        return False

    size_gb = gguf.stat().st_size / 1e9
    print(f"  · Model: {gguf.name} ({size_gb:.1f} GB)")
    print(f"  · Importing as: {model_name}")

    modelfile_path = Path("/tmp/Modelfile-argos")
    modelfile_path.write_text(create_modelfile(gguf_path))

    print("  · Running: ollama create (this may take a minute)...")
    result = subprocess.run(
        ["ollama", "create", model_name, "-f", str(modelfile_path)],
        capture_output=False,   # mostra output live
        text=True
    )

    modelfile_path.unlink(missing_ok=True)
    return result.returncode == 0


def test_model(model_name: str) -> bool:
    import requests
    print(f"  · Testing model {model_name}...")
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model_name,
                "prompt": 'Threat: port_scan from 1.2.3.4\nRespond with JSON only.',
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 200}
            },
            timeout=60
        )
        if r.status_code == 200:
            response = r.json().get("response", "")
            print(f"  ✓ Model responded: {response[:120]}...")
            return True
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="ARGOS Model Setup — Import GGUF into Ollama")
    parser.add_argument("--path", help="Path to GGUF model file")
    parser.add_argument("--name", default="argos-cybersec", help="Ollama model name (default: argos-cybersec)")
    parser.add_argument("--test", action="store_true", help="Only test existing model, don't import")
    args = parser.parse_args()

    print("\n\033[36mARGOS Model Setup\033[0m\n")

    # Load config
    config = load_config()

    # Determine paths
    gguf_path = args.path or config.get("gguf_model_path", "")
    model_name = args.name or config.get("ai_model", "argos-cybersec")

    if not gguf_path and not args.test:
        print("Usage: python setup_model.py --path /path/to/model.gguf")
        print()
        print("Or set gguf_model_path in ~/.argos/config.json")
        print(f"\nCurrent config: {CONFIG_PATH}")
        if config:
            print(f"  ai_model: {config.get('ai_model', 'not set')}")
            print(f"  gguf_model_path: {config.get('gguf_model_path', 'not set')}")
        sys.exit(1)

    # Check Ollama
    print("Checking Ollama...")
    if not check_ollama():
        print("  ✗ Ollama not installed. Get it from: https://ollama.ai/")
        sys.exit(1)
    print("  ✓ Ollama installed")

    # Start Ollama
    print("\nStarting Ollama server...")
    if not start_ollama():
        sys.exit(1)

    if args.test:
        print(f"\nTesting model: {model_name}")
        test_model(model_name)
        return

    # Check if already imported
    if model_exists(model_name):
        print(f"\n  ✓ Model '{model_name}' already in Ollama")
        answer = input("  Re-import? [y/N]: ").strip().lower()
        if answer != "y":
            print("  Skipping import.")
        else:
            if not import_model(gguf_path, model_name):
                print("  ✗ Import failed")
                sys.exit(1)
    else:
        print(f"\nImporting model...")
        if not import_model(gguf_path, model_name):
            print("  ✗ Import failed")
            sys.exit(1)

    print(f"\n  ✓ Model '{model_name}' ready in Ollama")

    # Test
    print("\nRunning quick test...")
    test_model(model_name)

    # Update config
    config["ai_model"] = model_name
    config["gguf_model_path"] = gguf_path
    save_config(config)
    print(f"\n  ✓ Config updated: ai_model = {model_name}")

    print("\n\033[32mSetup complete!\033[0m")
    print(f"  Restart the server to activate: kill $(lsof -ti:8443) && python -m uvicorn server.server:app --port 8443")
    print()


if __name__ == "__main__":
    main()
