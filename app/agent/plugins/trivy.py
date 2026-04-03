"""
ARGOS Plugin: Trivy Security Scanner
Container image, filesystem, repository, SBOM and IaC misconfiguration scanning
via the Trivy CLI (https://github.com/aquasecurity/trivy).
"""

import json
import subprocess
import shutil
from collections import defaultdict

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = {
    "id": "trivy-scanner",
    "name": "Trivy Security Scanner",
    "description": (
        "Comprehensive security scanning plugin powered by Trivy. "
        "Supports container image scanning, filesystem/dependency auditing, "
        "remote git repository scanning, SBOM generation (CycloneDX / SPDX), "
        "and Infrastructure-as-Code misconfiguration detection."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _tool_installed(name: str) -> bool:
    """Return True if *name* is available on PATH."""
    return shutil.which(name) is not None


def _trivy_not_installed() -> dict:
    return {
        "error": (
            "trivy not installed. "
            "Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
    }


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run *cmd* with a 120-second timeout, capturing stdout and stderr."""
    return subprocess.run(
        cmd,
        timeout=120,
        capture_output=True,
        text=True,
    )


def _parse_trivy_json(raw: str, source_label: str) -> dict:
    """
    Parse Trivy JSON output into a normalised dict.

    Trivy's JSON schema groups results by target (e.g. image layer, package file).
    This function flattens all vulnerability entries across every target.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Failed to parse Trivy JSON output: {exc}",
            "raw": raw[:2000],
        }

    results = data.get("Results", []) if isinstance(data, dict) else []

    vulnerabilities: list[dict] = []
    by_severity: dict[str, int] = defaultdict(int)

    for target_block in results:
        for vuln in target_block.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            entry = {
                "vuln_id": vuln.get("VulnerabilityID", ""),
                "pkg_name": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": sev,
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "references": vuln.get("References", [])[:5],  # cap to 5 URLs
                "target": target_block.get("Target", ""),
                "type": target_block.get("Type", ""),
            }
            vulnerabilities.append(entry)
            by_severity[sev] += 1

    return {
        "source": source_label,
        "vulnerabilities": vulnerabilities,
        "total": len(vulnerabilities),
        "by_severity": dict(by_severity),
    }


def _parse_trivy_misconfig_json(raw: str, path: str) -> dict:
    """Parse Trivy config/IaC scan output into a normalised dict."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Failed to parse Trivy config JSON output: {exc}",
            "raw": raw[:2000],
        }

    results = data.get("Results", []) if isinstance(data, dict) else []

    misconfigurations: list[dict] = []
    by_severity: dict[str, int] = defaultdict(int)

    for target_block in results:
        for mc in target_block.get("Misconfigurations") or []:
            sev = mc.get("Severity", "UNKNOWN").upper()
            misconfigurations.append({
                "id": mc.get("ID", ""),
                "avd_id": mc.get("AVDID", ""),
                "title": mc.get("Title", ""),
                "description": mc.get("Description", ""),
                "severity": sev,
                "resolution": mc.get("Resolution", ""),
                "status": mc.get("Status", ""),
                "target": target_block.get("Target", ""),
                "type": target_block.get("Type", ""),
                "references": mc.get("References", [])[:5],
            })
            by_severity[sev] += 1

    return {
        "path": path,
        "misconfigurations": misconfigurations,
        "total": len(misconfigurations),
        "by_severity": dict(by_severity),
    }


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def trivy_image(
    *,
    image: str,
    severity: str = "CRITICAL,HIGH",
    format: str = "json",
) -> dict:
    """
    Scan a container image for known vulnerabilities.

    Parameters
    ----------
    image:    Image reference, e.g. 'nginx:latest' or 'myrepo/myimage:1.0'.
    severity: Comma-separated severity levels to include, e.g. 'CRITICAL,HIGH'.
    format:   Output format; only 'json' is supported for structured results.
    """
    if not _tool_installed("trivy"):
        return _trivy_not_installed()

    cmd = [
        "trivy", "image",
        "--severity", severity.upper(),
        "--format", "json",
        image,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "trivy image scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run trivy image: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {
            "error": "trivy image produced no output.",
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    parsed = _parse_trivy_json(raw_output, source_label=image)
    parsed["image"] = image
    return parsed


def trivy_fs(
    *,
    path: str,
    severity: str = "CRITICAL,HIGH",
) -> dict:
    """
    Scan a local filesystem path for vulnerabilities in dependency manifests
    (requirements.txt, package.json, go.mod, Gemfile, Cargo.toml, pom.xml, etc.).

    Parameters
    ----------
    path:     Absolute or relative path to the directory or file to scan.
    severity: Comma-separated severity levels to include.
    """
    if not _tool_installed("trivy"):
        return _trivy_not_installed()

    cmd = [
        "trivy", "fs",
        "--severity", severity.upper(),
        "--format", "json",
        path,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "trivy fs scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run trivy fs: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {
            "error": "trivy fs produced no output.",
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    parsed = _parse_trivy_json(raw_output, source_label=path)
    parsed["path"] = path
    return parsed


def trivy_repo(
    *,
    url: str,
    severity: str = "CRITICAL,HIGH",
) -> dict:
    """
    Scan a remote git repository for vulnerabilities.

    Parameters
    ----------
    url:      URL of the git repository, e.g. 'https://github.com/org/repo'.
    severity: Comma-separated severity levels to include.
    """
    if not _tool_installed("trivy"):
        return _trivy_not_installed()

    cmd = [
        "trivy", "repo",
        "--severity", severity.upper(),
        "--format", "json",
        url,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "trivy repo scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run trivy repo: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {
            "error": "trivy repo produced no output.",
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    parsed = _parse_trivy_json(raw_output, source_label=url)
    parsed["url"] = url
    return parsed


def trivy_sbom(
    *,
    path: str,
    format: str = "cyclonedx",
) -> dict:
    """
    Generate a Software Bill of Materials (SBOM) for an image, directory, or file.

    Parameters
    ----------
    path:   Image reference or filesystem path to generate SBOM for.
    format: SBOM format — 'cyclonedx' | 'spdx' | 'spdx-json'.
    """
    if not _tool_installed("trivy"):
        return _trivy_not_installed()

    valid_formats = {"cyclonedx", "spdx", "spdx-json"}
    fmt = format.strip().lower()
    if fmt not in valid_formats:
        return {
            "error": (
                f"Unsupported SBOM format '{format}'. "
                f"Valid values: {', '.join(sorted(valid_formats))}."
            )
        }

    cmd = [
        "trivy", "sbom",
        "--format", fmt,
        path,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "trivy sbom generation timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run trivy sbom: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {
            "error": "trivy sbom produced no output.",
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    # spdx-json and cyclonedx produce JSON output; plain spdx produces text.
    if fmt in {"cyclonedx", "spdx-json"}:
        try:
            sbom_data = json.loads(raw_output)
            return {
                "path": path,
                "format": fmt,
                "sbom": sbom_data,
            }
        except json.JSONDecodeError:
            # Non-fatal: return raw text if JSON parsing fails.
            pass

    return {
        "path": path,
        "format": fmt,
        "sbom_raw": raw_output,
    }


def trivy_config(*, path: str) -> dict:
    """
    Scan Infrastructure-as-Code files for misconfigurations.

    Supports Terraform (.tf), Kubernetes YAML manifests, Dockerfiles,
    Helm charts, CloudFormation templates, and more.

    Parameters
    ----------
    path: Absolute or relative path to the IaC file or directory to scan.
    """
    if not _tool_installed("trivy"):
        return _trivy_not_installed()

    cmd = [
        "trivy", "config",
        "--format", "json",
        path,
    ]

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"error": "trivy config scan timed out after 120 seconds."}
    except Exception as exc:
        return {"error": f"Failed to run trivy config: {exc}"}

    raw_output = result.stdout or result.stderr
    if not raw_output.strip():
        return {
            "error": "trivy config produced no output.",
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    return _parse_trivy_misconfig_json(raw_output, path=path)


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "trivy_image": {
        "fn": trivy_image,
        "description": (
            "Scan a container image for known CVE vulnerabilities using Trivy. "
            "Returns a structured list of findings grouped by severity."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "image": {
                    "type": "string",
                    "description": (
                        "Container image reference to scan. "
                        "Examples: 'nginx:latest', 'python:3.11-slim', 'myorg/myapp:v2.0'."
                    ),
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Comma-separated list of severity levels to include. "
                        "Options: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN. "
                        "Default: 'CRITICAL,HIGH'."
                    ),
                },
                "format": {
                    "type": "string",
                    "enum": ["json"],
                    "description": "Output format. Only 'json' is supported for structured results.",
                },
            },
            "required": ["image"],
        },
    },
    "trivy_fs": {
        "fn": trivy_fs,
        "description": (
            "Scan a local filesystem directory or file for vulnerabilities in "
            "dependency manifests (requirements.txt, package.json, go.mod, Gemfile, etc.)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the directory or file to scan.",
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Comma-separated severity levels to include. "
                        "Default: 'CRITICAL,HIGH'."
                    ),
                },
            },
            "required": ["path"],
        },
    },
    "trivy_repo": {
        "fn": trivy_repo,
        "description": (
            "Scan a remote git repository for known vulnerabilities in its dependencies."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": (
                        "URL of the git repository to scan. "
                        "Example: 'https://github.com/org/repo'."
                    ),
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Comma-separated severity levels to include. "
                        "Default: 'CRITICAL,HIGH'."
                    ),
                },
            },
            "required": ["url"],
        },
    },
    "trivy_sbom": {
        "fn": trivy_sbom,
        "description": (
            "Generate a Software Bill of Materials (SBOM) for a container image "
            "or filesystem path using Trivy. Supports CycloneDX and SPDX formats."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Image reference or filesystem path to generate SBOM for. "
                        "Example: 'nginx:latest' or '/app/src'."
                    ),
                },
                "format": {
                    "type": "string",
                    "enum": ["cyclonedx", "spdx", "spdx-json"],
                    "description": "SBOM output format. Default: 'cyclonedx'.",
                },
            },
            "required": ["path"],
        },
    },
    "trivy_config": {
        "fn": trivy_config,
        "description": (
            "Scan Infrastructure-as-Code files for misconfigurations using Trivy. "
            "Supports Terraform, Kubernetes YAML, Dockerfiles, Helm charts, and CloudFormation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute or relative path to the IaC file or directory to scan."
                    ),
                },
            },
            "required": ["path"],
        },
    },
}
