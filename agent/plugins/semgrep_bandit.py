"""
ARGOS Plugin: SAST Scanner (Semgrep + Bandit)
Static Application Security Testing via Semgrep and Bandit.
"""

import json
import subprocess
import shutil
from collections import defaultdict

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "semgrep-bandit",
    "name": "SAST Scanner (Semgrep + Bandit)",
    "description": (
        "Static Application Security Testing plugin. "
        "Runs Semgrep and Bandit to detect security vulnerabilities, "
        "code quality issues, and dangerous patterns in source code."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _tool_installed(name: str) -> bool:
    """Return True if *name* is on PATH."""
    return shutil.which(name) is not None


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run *cmd* with a 120-second timeout, capturing output."""
    return subprocess.run(
        cmd,
        timeout=120,
        capture_output=True,
        text=True,
    )


def _severity_flag(severity: str, mapping: dict[str, str]) -> list[str]:
    """Convert a severity string to a list of CLI flags using *mapping*."""
    key = severity.strip().lower()
    flag = mapping.get(key)
    if flag is None:
        return []
    return [flag]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def semgrep_scan(
    *,
    path: str,
    rules: str = "auto",
    severity: str = "WARNING",
    output_format: str = "json",
) -> dict:
    """
    Run Semgrep on *path* and return a structured findings report.

    Parameters
    ----------
    path:          File or directory to scan.
    rules:         Semgrep rule config (e.g. "auto", "p/python", "p/owasp-top-ten").
    severity:      Minimum severity to report: INFO | WARNING | ERROR.
    output_format: Currently only "json" is supported internally.
    """
    if not _tool_installed("semgrep"):
        return {
            "error": (
                "semgrep not installed. "
                "Install: pip install semgrep"
            )
        }

    cmd = [
        "semgrep",
        "scan",
        "--config", rules,
        "--severity", severity.upper(),
        "--json",
        path,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "semgrep scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run semgrep: {exc}"}

    # Semgrep exits with code 1 when findings are found, which is normal.
    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {"error": "semgrep produced no output.", "stderr": result.stderr}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Failed to parse semgrep JSON output: {exc}",
            "raw": raw_output[:2000],
        }

    raw_results = data.get("results", [])
    findings: list[dict] = []
    by_severity: dict[str, int] = defaultdict(int)

    for r in raw_results:
        sev = r.get("extra", {}).get("severity", "UNKNOWN").upper()
        finding = {
            "rule_id": r.get("check_id", "unknown"),
            "severity": sev,
            "message": r.get("extra", {}).get("message", ""),
            "path": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
        }
        findings.append(finding)
        by_severity[sev] += 1

    # Extract number of scanned files from stats block (if present).
    stats = data.get("stats", {})
    files_scanned: int = (
        stats.get("total_bytes", {}).get("num_files")
        or len({f["path"] for f in findings})
        or 0
    )

    # Fallback: count unique paths from findings when stats are absent.
    if files_scanned == 0 and findings:
        files_scanned = len({f["path"] for f in findings})

    return {
        "findings": findings,
        "total": len(findings),
        "by_severity": dict(by_severity),
        "files_scanned": files_scanned,
    }


def bandit_scan(
    *,
    path: str,
    severity: str = "medium",
    confidence: str = "medium",
    recursive: bool = True,
) -> dict:
    """
    Run Bandit on *path* and return a structured issues report.

    Parameters
    ----------
    path:       File or directory to scan.
    severity:   Minimum severity: low | medium | high.
    confidence: Minimum confidence: low | medium | high.
    recursive:  Whether to scan directories recursively.
    """
    if not _tool_installed("bandit"):
        return {
            "error": (
                "bandit not installed. "
                "Install: pip install bandit"
            )
        }

    severity_flags = {
        "low": "-l",
        "medium": "-ll",
        "high": "-lll",
    }
    confidence_flags = {
        "low": "-i",
        "medium": "-ii",
        "high": "-iii",
    }

    sev_flag = severity_flags.get(severity.strip().lower(), "-ll")
    conf_flag = confidence_flags.get(confidence.strip().lower(), "-ii")

    cmd = ["bandit"]
    if recursive:
        cmd.append("-r")
    cmd += [path, sev_flag, conf_flag, "-f", "json"]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "bandit scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run bandit: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {"error": "bandit produced no output.", "stderr": result.stderr}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Failed to parse bandit JSON output: {exc}",
            "raw": raw_output[:2000],
        }

    raw_issues = data.get("results", [])
    issues: list[dict] = []
    by_severity: dict[str, int] = defaultdict(int)
    by_confidence: dict[str, int] = defaultdict(int)

    for issue in raw_issues:
        sev = issue.get("issue_severity", "UNDEFINED").upper()
        conf = issue.get("issue_confidence", "UNDEFINED").upper()
        issues.append({
            "test_id": issue.get("test_id", ""),
            "test_name": issue.get("test_name", ""),
            "severity": sev,
            "confidence": conf,
            "message": issue.get("issue_text", ""),
            "path": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "code": issue.get("code", "").strip(),
            "cwe": issue.get("issue_cwe", {}).get("id") if isinstance(issue.get("issue_cwe"), dict) else None,
        })
        by_severity[sev] += 1
        by_confidence[conf] += 1

    metrics = data.get("metrics", {})

    return {
        "issues": issues,
        "total": len(issues),
        "by_severity": dict(by_severity),
        "by_confidence": dict(by_confidence),
        "metrics": metrics,
    }


def semgrep_list_rules(*, category: str = "all") -> dict:
    """
    List available Semgrep rule categories or attempt to fetch rule names.

    Parameters
    ----------
    category: Filter category — security | correctness | performance | all.
    """
    # Static well-known Semgrep registry rulesets grouped by category.
    _STATIC_RULES: dict[str, list[dict]] = {
        "security": [
            {"id": "p/owasp-top-ten",         "description": "OWASP Top 10 vulnerabilities"},
            {"id": "p/cwe-top-25",             "description": "CWE Top 25 dangerous software weaknesses"},
            {"id": "p/secrets",                "description": "Hardcoded secrets and credentials"},
            {"id": "p/sql-injection",          "description": "SQL injection patterns"},
            {"id": "p/xss",                    "description": "Cross-site scripting patterns"},
            {"id": "p/command-injection",      "description": "OS command injection"},
            {"id": "p/insecure-transport",     "description": "Insecure transport / HTTP usage"},
            {"id": "p/jwt",                    "description": "JWT misuse and vulnerabilities"},
            {"id": "p/python.flask.security",  "description": "Flask-specific security issues"},
            {"id": "p/django",                 "description": "Django security rules"},
            {"id": "p/nodejs.security",        "description": "Node.js security patterns"},
            {"id": "p/java.security",          "description": "Java security rules"},
            {"id": "p/golang.security",        "description": "Go security rules"},
        ],
        "correctness": [
            {"id": "p/python.correctness",     "description": "Python correctness rules"},
            {"id": "p/java.correctness",       "description": "Java correctness rules"},
            {"id": "p/typescript.correctness", "description": "TypeScript correctness rules"},
            {"id": "p/javascript.correctness", "description": "JavaScript correctness rules"},
        ],
        "performance": [
            {"id": "p/performance",            "description": "General performance anti-patterns"},
            {"id": "p/python.performance",     "description": "Python performance rules"},
        ],
    }

    all_rules = [rule for rules in _STATIC_RULES.values() for rule in rules]

    # Optionally attempt to enumerate installed / local rules via semgrep CLI.
    live_attempt: dict = {}
    if _tool_installed("semgrep"):
        try:
            result = _run(["semgrep", "--config", "auto", "--validate", "--json"])
            if result.returncode == 0 and result.stdout.strip():
                parsed = json.loads(result.stdout)
                live_rules = parsed.get("rules", [])
                if live_rules:
                    live_attempt = {
                        "live_rules_count": len(live_rules),
                        "note": "Retrieved from local semgrep validation run.",
                    }
        except Exception:
            pass  # Non-critical; fall back to static list.

    category_key = category.strip().lower()
    if category_key == "all":
        selected = all_rules
    else:
        selected = _STATIC_RULES.get(category_key, [])
        if not selected:
            return {
                "error": (
                    f"Unknown category '{category}'. "
                    "Valid values: security, correctness, performance, all."
                )
            }

    response: dict = {
        "category": category_key,
        "rules": selected,
        "total": len(selected),
    }
    if live_attempt:
        response["live_info"] = live_attempt

    return response


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "semgrep_scan": {
        "fn": semgrep_scan,
        "description": (
            "Run Semgrep static analysis on a file or directory and return "
            "a structured list of security findings with severity breakdown."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file or directory to scan.",
                },
                "rules": {
                    "type": "string",
                    "description": (
                        "Semgrep rule configuration. Examples: 'auto', 'p/python', "
                        "'p/owasp-top-ten', path to a local rule YAML file."
                    ),
                },
                "severity": {
                    "type": "string",
                    "enum": ["INFO", "WARNING", "ERROR"],
                    "description": "Minimum severity level to include in results.",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["json"],
                    "description": "Output format (currently only 'json' is supported).",
                },
            },
            "required": ["path"],
        },
    },
    "bandit_scan": {
        "fn": bandit_scan,
        "description": (
            "Run Bandit static analysis on Python code to detect common security "
            "issues. Returns issues grouped by severity and confidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the Python file or directory to scan.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Minimum issue severity to report.",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Minimum confidence level to report.",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Whether to scan directories recursively (default: true).",
                },
            },
            "required": ["path"],
        },
    },
    "semgrep_list_rules": {
        "fn": semgrep_list_rules,
        "description": (
            "List available Semgrep rule-sets by category. "
            "Returns well-known registry rule IDs grouped under security, "
            "correctness, or performance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["security", "correctness", "performance", "all"],
                    "description": "Rule category to list. Defaults to 'all'.",
                },
            },
            "required": [],
        },
    },
}
