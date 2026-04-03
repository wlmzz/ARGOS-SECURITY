"""
ARGOS Plugin — Google OSV-Scanner
Scans project dependencies and SBOMs for known vulnerabilities using
the OSV database (osv.dev) via the CLI tool or the OSV REST API.
Only stdlib + subprocess. Timeout = 120 s.
"""

import json
import os
import shutil
import subprocess
import urllib.request
import urllib.error
import ssl
from typing import Any

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "osv-scanner",
    "name": "OSV Scanner",
    "description": (
        "Google OSV-Scanner: scans project dependencies, lockfiles, and SBOMs "
        "for known vulnerabilities using the open OSV database (osv.dev). "
        "Supports npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems, and more."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_OSV_API = "https://api.osv.dev/v1/query"

_VALID_ECOSYSTEMS = {
    "PyPI", "npm", "Go", "Maven", "NuGet",
    "crates.io", "RubyGems", "Packagist",
    "Hex", "Pub", "Alpine", "Debian", "Ubuntu",
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _osv_available() -> bool:
    return shutil.which("osv-scanner") is not None


def _run_osv(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run osv-scanner with the given arguments; return (returncode, stdout, stderr)."""
    cmd = ["osv-scanner"] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "osv-scanner timed out after {} seconds.".format(timeout)
    except FileNotFoundError:
        return -1, "", "osv-scanner binary not found."


def _parse_osv_json(raw: str) -> dict[str, Any]:
    """
    Parse the JSON output produced by `osv-scanner --format json`.
    OSV-Scanner returns a top-level object with a 'results' array.
    """
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # The tool sometimes emits progress lines before the JSON block;
        # try to extract the last valid JSON object.
        for line in reversed(raw.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    pass
        return {"parse_error": str(exc), "raw_output": raw[:2000]}


def _normalize_osv_results(parsed: dict) -> tuple[list, int, dict, int]:
    """
    Extract (vuln_list, total, by_ecosystem, packages_scanned) from parsed OSV output.
    """
    results = parsed.get("results", [])
    vulns: list[dict] = []
    by_ecosystem: dict[str, int] = {}
    packages_scanned = 0

    for result_block in results:
        # Each result block has a 'packages' list
        packages = result_block.get("packages", [])
        packages_scanned += len(packages)
        for pkg_block in packages:
            pkg_info = pkg_block.get("package", {})
            ecosystem = pkg_info.get("ecosystem", "Unknown")
            pkg_vulns = pkg_block.get("vulnerabilities", [])

            for vuln in pkg_vulns:
                aliases = vuln.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")] or aliases[:1]
                severity_scores = []
                for sev in vuln.get("severity", []):
                    severity_scores.append({
                        "type": sev.get("type", ""),
                        "score": sev.get("score", ""),
                    })

                normalized = {
                    "id": vuln.get("id", ""),
                    "aliases": aliases,
                    "cve": cve_ids[0] if cve_ids else "",
                    "summary": vuln.get("summary", vuln.get("details", "")[:200]),
                    "details": vuln.get("details", ""),
                    "severity": severity_scores,
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                    "package": {
                        "name": pkg_info.get("name", ""),
                        "version": pkg_info.get("version", ""),
                        "ecosystem": ecosystem,
                    },
                    "fixed_versions": _extract_fixed_versions(vuln),
                    "references": [r.get("url", "") for r in vuln.get("references", [])][:5],
                }
                vulns.append(normalized)
                by_ecosystem[ecosystem] = by_ecosystem.get(ecosystem, 0) + 1

    return vulns, len(vulns), by_ecosystem, packages_scanned


def _extract_fixed_versions(vuln: dict) -> list[str]:
    """Extract fixed versions from OSV affected[] ranges."""
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fix = event.get("fixed", "")
                if fix and fix != "0":
                    fixed.append(fix)
    return list(dict.fromkeys(fixed))  # deduplicate


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def osv_scan_dir(path: str, recursive: bool = True) -> dict:
    """
    Scan a project directory for vulnerable dependencies.

    osv-scanner automatically discovers lockfiles (package-lock.json,
    requirements.txt, go.sum, Cargo.lock, yarn.lock, pom.xml, etc.).

    Parameters
    ----------
    path : str
        Absolute path to the project directory to scan.
    recursive : bool
        Recursively scan sub-directories (default True).
    """
    if not _osv_available():
        return {
            "error": (
                "osv-scanner not installed. "
                "Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest  "
                "OR download from https://github.com/google/osv-scanner/releases"
            )
        }

    if not os.path.isdir(path):
        return {"error": "Directory not found: {}".format(path)}

    args = ["--format", "json"]
    if recursive:
        args += ["--recursive"]
    args.append(path)

    rc, stdout, stderr = _run_osv(args, timeout=120)

    if rc == -1 and not stdout:
        return {"error": stderr or "osv-scanner failed with no output."}

    parsed = _parse_osv_json(stdout)
    if "parse_error" in parsed:
        return {
            "error": "Failed to parse osv-scanner output.",
            "details": parsed["parse_error"],
            "stderr": stderr,
        }

    vulns, total, by_ecosystem, packages_scanned = _normalize_osv_results(parsed)

    return {
        "path": path,
        "recursive": recursive,
        "vulnerabilities": vulns,
        "total": total,
        "by_ecosystem": by_ecosystem,
        "packages_scanned": packages_scanned,
        "scan_exit_code": rc,
        "stderr": stderr if rc not in (0, 1) else "",
    }


def osv_scan_lockfile(lockfile_path: str) -> dict:
    """
    Scan a single lockfile for vulnerable dependencies.

    Supported lockfiles: package-lock.json, yarn.lock, requirements.txt,
    go.sum, Cargo.lock, pom.xml, Gemfile.lock, composer.lock, and others.

    Parameters
    ----------
    lockfile_path : str
        Absolute path to the lockfile to analyse.
    """
    if not _osv_available():
        return {
            "error": (
                "osv-scanner not installed. "
                "Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest  "
                "OR download from https://github.com/google/osv-scanner/releases"
            )
        }

    if not os.path.isfile(lockfile_path):
        return {"error": "File not found: {}".format(lockfile_path)}

    args = ["--format", "json", "--lockfile", lockfile_path]
    rc, stdout, stderr = _run_osv(args, timeout=120)

    if rc == -1 and not stdout:
        return {"error": stderr or "osv-scanner failed with no output."}

    parsed = _parse_osv_json(stdout)
    if "parse_error" in parsed:
        return {
            "error": "Failed to parse osv-scanner output.",
            "details": parsed["parse_error"],
            "stderr": stderr,
        }

    vulns, total, by_ecosystem, packages_scanned = _normalize_osv_results(parsed)

    return {
        "lockfile": lockfile_path,
        "vulnerabilities": vulns,
        "total": total,
        "by_ecosystem": by_ecosystem,
        "packages_scanned": packages_scanned,
        "scan_exit_code": rc,
        "stderr": stderr if rc not in (0, 1) else "",
    }


def osv_scan_sbom(sbom_path: str) -> dict:
    """
    Scan a Software Bill of Materials (SBOM) for known vulnerabilities.

    Supports CycloneDX (JSON/XML) and SPDX formats, as produced by
    tools such as Trivy, Syft, or cdxgen.

    Parameters
    ----------
    sbom_path : str
        Absolute path to the SBOM file to analyse.
    """
    if not _osv_available():
        return {
            "error": (
                "osv-scanner not installed. "
                "Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest  "
                "OR download from https://github.com/google/osv-scanner/releases"
            )
        }

    if not os.path.isfile(sbom_path):
        return {"error": "SBOM file not found: {}".format(sbom_path)}

    args = ["--format", "json", "--sbom", sbom_path]
    rc, stdout, stderr = _run_osv(args, timeout=120)

    if rc == -1 and not stdout:
        return {"error": stderr or "osv-scanner failed with no output."}

    parsed = _parse_osv_json(stdout)
    if "parse_error" in parsed:
        return {
            "error": "Failed to parse osv-scanner output.",
            "details": parsed["parse_error"],
            "stderr": stderr,
        }

    vulns, total, by_ecosystem, packages_scanned = _normalize_osv_results(parsed)

    # Determine SBOM format from file extension / content
    sbom_format = "unknown"
    ext = os.path.splitext(sbom_path)[1].lower()
    if ext in (".json",):
        sbom_format = "CycloneDX/SPDX JSON"
    elif ext in (".xml",):
        sbom_format = "CycloneDX XML"
    elif ext in (".spdx", ".tv"):
        sbom_format = "SPDX Tag-Value"

    return {
        "sbom_path": sbom_path,
        "sbom_format": sbom_format,
        "vulnerabilities": vulns,
        "total": total,
        "by_ecosystem": by_ecosystem,
        "packages_scanned": packages_scanned,
        "scan_exit_code": rc,
        "stderr": stderr if rc not in (0, 1) else "",
    }


def osv_check_package(package: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Check a specific package@version against the OSV database via REST API.

    Does not require the osv-scanner CLI — uses the public OSV API directly.

    Parameters
    ----------
    package : str
        Package name (e.g. "requests", "lodash", "log4j").
    version : str
        Exact version string (e.g. "2.27.0", "4.17.15").
    ecosystem : str
        Package ecosystem: PyPI, npm, Go, Maven, NuGet, crates.io,
        RubyGems, Packagist (default PyPI).
    """
    if not package or not version:
        return {"error": "Both 'package' and 'version' are required."}

    if ecosystem not in _VALID_ECOSYSTEMS:
        return {
            "error": "Unknown ecosystem '{}'. Valid options: {}".format(
                ecosystem, ", ".join(sorted(_VALID_ECOSYSTEMS))
            )
        }

    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        _OSV_API,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return {"error": "OSV API HTTP {} — {}".format(exc.code, raw[:500])}
    except urllib.error.URLError as exc:
        return {"error": "Cannot reach OSV API — {}".format(exc.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    raw_vulns = body.get("vulns", [])

    normalized: list[dict] = []
    by_severity: dict[str, int] = {}

    for vuln in raw_vulns:
        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")] or aliases[:1]

        severity_scores: list[dict] = []
        severity_label = "Unknown"
        for sev in vuln.get("severity", []):
            score_str = sev.get("score", "")
            severity_scores.append({"type": sev.get("type", ""), "score": score_str})
            # Parse CVSS score to label
            if sev.get("type", "").startswith("CVSS") and score_str:
                try:
                    parts = dict(
                        part.split(":") for part in score_str.split("/") if ":" in part
                    )
                    base = float(parts.get("BaseScore", "0") or "0")
                except (ValueError, AttributeError):
                    # Newer CVSS strings have embedded numeric base score elsewhere
                    # Try reading from database_specific
                    base_alt = vuln.get("database_specific", {}).get("severity", "")
                    severity_label = base_alt or severity_label
                    base = 0.0

                if base >= 9.0:
                    severity_label = "CRITICAL"
                elif base >= 7.0:
                    severity_label = "HIGH"
                elif base >= 4.0:
                    severity_label = "MEDIUM"
                elif base > 0:
                    severity_label = "LOW"

        # Fall back to database_specific.severity if CVSS parsing failed
        if severity_label == "Unknown":
            severity_label = (
                vuln.get("database_specific", {}).get("severity", "Unknown").upper()
            )

        by_severity[severity_label] = by_severity.get(severity_label, 0) + 1

        normalized.append({
            "id": vuln.get("id", ""),
            "aliases": aliases,
            "cve": cve_ids[0] if cve_ids else "",
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", "")[:500],
            "severity": severity_scores,
            "severity_label": severity_label,
            "published": vuln.get("published", ""),
            "modified": vuln.get("modified", ""),
            "fixed_versions": _extract_fixed_versions(vuln),
            "references": [r.get("url", "") for r in vuln.get("references", [])][:5],
        })

    # Sort by severity
    _SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    normalized.sort(
        key=lambda v: _SEV_ORDER.index(v["severity_label"])
        if v["severity_label"] in _SEV_ORDER else 99
    )

    return {
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerable": len(normalized) > 0,
        "vulnerabilities": normalized,
        "total": len(normalized),
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------
TOOLS = {
    "osv_scan_dir": {
        "fn": osv_scan_dir,
        "description": (
            "Scan a project directory for vulnerable dependencies using osv-scanner. "
            "Automatically discovers all lockfiles (package-lock.json, requirements.txt, "
            "go.sum, Cargo.lock, etc.) and returns CVEs grouped by ecosystem."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to scan.",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Recursively scan sub-directories (default true).",
                    "default": True,
                },
            },
            "required": ["path"],
        },
    },
    "osv_scan_lockfile": {
        "fn": osv_scan_lockfile,
        "description": (
            "Scan a single lockfile for vulnerable dependencies. "
            "Supports package-lock.json, yarn.lock, requirements.txt, go.sum, "
            "Cargo.lock, pom.xml, Gemfile.lock, composer.lock, and others."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "lockfile_path": {
                    "type": "string",
                    "description": "Absolute path to the lockfile to scan.",
                },
            },
            "required": ["lockfile_path"],
        },
    },
    "osv_scan_sbom": {
        "fn": osv_scan_sbom,
        "description": (
            "Scan a Software Bill of Materials (SBOM) for known vulnerabilities. "
            "Accepts CycloneDX (JSON/XML) and SPDX formats produced by Trivy, Syft, or cdxgen."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sbom_path": {
                    "type": "string",
                    "description": "Absolute path to the SBOM file (CycloneDX or SPDX).",
                },
            },
            "required": ["sbom_path"],
        },
    },
    "osv_check_package": {
        "fn": osv_check_package,
        "description": (
            "Check a specific package version for known CVEs using the OSV REST API "
            "(no CLI required). Returns vulnerabilities sorted by severity."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name (e.g. 'requests', 'lodash', 'log4j-core').",
                },
                "version": {
                    "type": "string",
                    "description": "Exact version string (e.g. '2.27.0', '4.17.15', '2.14.1').",
                },
                "ecosystem": {
                    "type": "string",
                    "description": (
                        "Package ecosystem: PyPI, npm, Go, Maven, NuGet, "
                        "crates.io, RubyGems, Packagist (default PyPI)."
                    ),
                    "default": "PyPI",
                    "enum": [
                        "PyPI", "npm", "Go", "Maven", "NuGet",
                        "crates.io", "RubyGems", "Packagist",
                        "Hex", "Pub", "Alpine", "Debian", "Ubuntu",
                    ],
                },
            },
            "required": ["package", "version"],
        },
    },
}
