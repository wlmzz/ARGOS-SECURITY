"""
ARGOS Plugin: Atomic Red Team — MITRE ATT&CK Simulation
Execute atomic, focused tests for specific ATT&CK techniques to validate
security controls, detection capabilities, and incident response.

⚠️  AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY.
    Tests must run on systems you own or have explicit written permission.
    Each atomic test is designed to simulate specific attacker techniques.

Auto-installs to /opt/argos/tools/atomic-red-team/
Repo: https://github.com/redcanaryco/atomic-red-team (wlmzz/atomic-red-team)
"""
from __future__ import annotations
import os, subprocess, json, re, yaml
from pathlib import Path

MANIFEST = {
    "id":          "atomic_red_team",
    "name":        "Atomic Red Team (MITRE ATT&CK Simulation)",
    "description": "Execute MITRE ATT&CK atomic tests to validate detection controls. Authorized red team / security validation only.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

_ART_DIR   = Path("/opt/argos/tools/atomic-red-team")
_ATOMS_DIR = _ART_DIR / "atomics"
_TIMEOUT   = 120


def _ensure_art() -> bool:
    if _ATOMS_DIR.exists():
        return True
    _ART_DIR.parent.mkdir(parents=True, exist_ok=True)
    for repo in ["wlmzz/atomic-red-team", "redcanaryco/atomic-red-team"]:
        r = subprocess.run(
            ["git", "clone", "--depth=1", "-q",
             f"https://github.com/{repo}.git", str(_ART_DIR)],
            capture_output=True, timeout=180
        )
        if r.returncode == 0 and _ATOMS_DIR.exists():
            return True
    return False


def _load_technique(technique_id: str) -> dict | None:
    """Load YAML definition for an ATT&CK technique."""
    tid = technique_id.upper()
    for path in [
        _ATOMS_DIR / tid / f"{tid}.yaml",
        _ATOMS_DIR / tid / f"{tid}.yml",
    ]:
        if path.exists():
            try:
                return yaml.safe_load(path.read_text())
            except Exception:
                pass
    return None


def art_list_techniques(tactic: str = "", search: str = "") -> dict:
    """List available ATT&CK atomic test techniques.
    ⚠️  AUTHORIZED RED TEAM ONLY.

    tactic:  filter by ATT&CK tactic (e.g. 'execution', 'persistence', 'discovery')
    search:  search technique names/descriptions
    """
    if not _ensure_art():
        return {"error": "Failed to clone Atomic Red Team repo"}

    techniques = []
    for yaml_file in sorted(_ATOMS_DIR.rglob("T*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text())
            if not data:
                continue
            entry = {
                "id":          data.get("attack_technique", yaml_file.parent.name),
                "name":        data.get("display_name", ""),
                "tactic":      data.get("attack_tactic", ""),
                "test_count":  len(data.get("atomic_tests", [])),
            }
            if tactic and tactic.lower() not in entry["tactic"].lower():
                continue
            if search and search.lower() not in (entry["name"] + entry["id"]).lower():
                continue
            techniques.append(entry)
        except Exception:
            continue

    return {
        "source":          "Atomic Red Team",
        "technique_count": len(techniques),
        "tactic_filter":   tactic or "all",
        "search_filter":   search or "none",
        "techniques":      techniques[:50],
    }


def art_get_technique(technique_id: str) -> dict:
    """Get details and available tests for a specific ATT&CK technique.
    ⚠️  AUTHORIZED RED TEAM ONLY.

    technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1059.001')
    """
    if not _ensure_art():
        return {"error": "Failed to clone Atomic Red Team repo"}

    data = _load_technique(technique_id)
    if not data:
        return {"error": f"Technique {technique_id} not found", "hint": "Use art_list_techniques() to browse"}

    tests = []
    for i, test in enumerate(data.get("atomic_tests", []), 1):
        tests.append({
            "number":      i,
            "name":        test.get("name", ""),
            "description": test.get("description", "")[:200],
            "platform":    test.get("supported_platforms", []),
            "type":        test.get("executor", {}).get("name", ""),
        })

    return {
        "technique_id": technique_id.upper(),
        "name":         data.get("display_name", ""),
        "tactic":       data.get("attack_tactic", ""),
        "source":       "Atomic Red Team",
        "test_count":   len(tests),
        "tests":        tests,
        "note":         "AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY",
    }


def art_execute_test(technique_id: str, test_number: int = 1,
                      input_args: dict = None,
                      cleanup: bool = True,
                      timeout: int = _TIMEOUT) -> dict:
    """Execute an atomic red team test for a specific ATT&CK technique.
    ⚠️  AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY.
    ⚠️  This WILL execute commands on the local system. Only run on test/lab systems.

    technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1059.001')
    test_number:  which test to run (1-based, default: 1)
    input_args:   override default input arguments (dict)
    cleanup:      run cleanup commands after test (default: true)
    timeout:      max seconds for test execution (default: 120)
    """
    if not _ensure_art():
        return {"error": "Failed to clone Atomic Red Team repo"}

    data = _load_technique(technique_id)
    if not data:
        return {"error": f"Technique {technique_id} not found"}

    tests = data.get("atomic_tests", [])
    if test_number < 1 or test_number > len(tests):
        return {"error": f"Test #{test_number} not found. Available: 1-{len(tests)}"}

    test = tests[test_number - 1]
    executor = test.get("executor", {})
    executor_name = executor.get("name", "")
    platform = test.get("supported_platforms", [])

    # Build the command
    cmd_template = executor.get("command", "")
    cleanup_cmd  = executor.get("cleanup_command", "")

    # Substitute input arguments
    inputs = {k: v.get("default", "") for k, v in test.get("input_arguments", {}).items()}
    if input_args:
        inputs.update(input_args)
    for key, val in inputs.items():
        cmd_template = cmd_template.replace(f"#{{{key}}}", str(val))
        cleanup_cmd  = cleanup_cmd.replace(f"#{{{key}}}", str(val))

    # Execute
    if executor_name in ("sh", "bash"):
        shell_cmd = ["bash", "-c", cmd_template]
    elif executor_name in ("command_prompt", "cmd"):
        shell_cmd = ["cmd.exe", "/c", cmd_template]
    elif executor_name == "powershell":
        shell_cmd = ["powershell", "-Command", cmd_template]
    elif executor_name == "python":
        shell_cmd = ["python3", "-c", cmd_template]
    else:
        return {
            "error":          f"Executor '{executor_name}' not directly supported",
            "technique_id":   technique_id,
            "test_name":      test.get("name", ""),
            "manual_command": cmd_template,
            "note":           "Run the command above manually in an authorized test environment",
        }

    result = {
        "technique_id": technique_id.upper(),
        "test_number":  test_number,
        "test_name":    test.get("name", ""),
        "executor":     executor_name,
        "command":      cmd_template[:500],
        "platform":     platform,
        "note":         "AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY",
    }

    try:
        r = subprocess.run(
            shell_cmd, capture_output=True, text=True, timeout=timeout
        )
        result["returncode"] = r.returncode
        result["stdout"]     = r.stdout[-2000:]
        result["stderr"]     = r.stderr[-500:]
        result["success"]    = r.returncode == 0
    except subprocess.TimeoutExpired:
        result["error"] = f"Test timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)

    # Run cleanup
    if cleanup and cleanup_cmd:
        try:
            subprocess.run(
                ["bash", "-c", cleanup_cmd],
                capture_output=True, timeout=30
            )
            result["cleanup"] = "completed"
        except Exception:
            result["cleanup"] = "failed"

    return result


def art_simulate_tactic(tactic: str, max_tests: int = 3,
                          timeout: int = 60) -> dict:
    """Run multiple atomic tests for an entire ATT&CK tactic.
    ⚠️  AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY.
    ⚠️  Executes real commands on local system.

    tactic:     ATT&CK tactic name (e.g. 'discovery', 'persistence', 'execution')
    max_tests:  maximum tests to run (default: 3, safety limit)
    """
    if not _ensure_art():
        return {"error": "Failed to clone Atomic Red Team repo"}

    techniques = art_list_techniques(tactic=tactic)
    if "error" in techniques:
        return techniques

    results = []
    ran = 0
    for tech in techniques.get("techniques", [])[:max_tests * 3]:
        if ran >= max_tests:
            break
        tid = tech["id"]
        r = art_execute_test(tid, test_number=1, timeout=timeout)
        if "error" not in r or "not directly supported" in str(r.get("error", "")):
            results.append(r)
            ran += 1

    return {
        "tactic":       tactic,
        "source":       "Atomic Red Team",
        "tests_run":    len(results),
        "results":      results,
        "note":         "AUTHORIZED RED TEAM / SECURITY VALIDATION ONLY",
    }


TOOLS = {
    "art_list_techniques": {
        "fn": art_list_techniques,
        "description": (
            "List MITRE ATT&CK atomic test techniques. "
            "Filter by tactic (execution, persistence, discovery, etc.) or search by name. "
            "⚠️ AUTHORIZED RED TEAM ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tactic": {"type": "string", "description": "ATT&CK tactic filter (e.g. 'execution', 'persistence', 'discovery')"},
                "search": {"type": "string", "description": "Search in technique names/descriptions"},
            },
            "required": []
        }
    },
    "art_get_technique": {
        "fn": art_get_technique,
        "description": (
            "Get details and available tests for an ATT&CK technique (e.g. T1003, T1059.001). "
            "Shows test names, descriptions, platforms, and executor types. "
            "⚠️ AUTHORIZED RED TEAM ONLY."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "ATT&CK technique ID (e.g. 'T1003', 'T1059.001')"},
            },
            "required": ["technique_id"]
        }
    },
    "art_execute_test": {
        "fn": art_execute_test,
        "description": (
            "Execute an atomic red team test for a MITRE ATT&CK technique. "
            "Runs real commands on the local system to validate security controls. "
            "⚠️ AUTHORIZED RED TEAM ONLY — runs on local/test system only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string",  "description": "ATT&CK technique ID (e.g. 'T1003')"},
                "test_number":  {"type": "integer", "description": "Test number (1-based, default: 1)"},
                "input_args":   {"type": "object",  "description": "Override default input arguments"},
                "cleanup":      {"type": "boolean", "description": "Run cleanup after test (default: true)"},
                "timeout":      {"type": "integer", "description": "Max seconds (default: 120)"},
            },
            "required": ["technique_id"]
        }
    },
    "art_simulate_tactic": {
        "fn": art_simulate_tactic,
        "description": (
            "Run multiple atomic tests for an entire ATT&CK tactic to validate detection coverage. "
            "⚠️ AUTHORIZED RED TEAM ONLY — executes real commands on local system."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tactic":    {"type": "string",  "description": "ATT&CK tactic (execution, persistence, discovery, lateral_movement, etc.)"},
                "max_tests": {"type": "integer", "description": "Max tests to run (default: 3)"},
            },
            "required": ["tactic"]
        }
    },
}
