"""
ARGOS Plugin: cloud-security
Cloud security assessment via ScoutSuite and Prowler.
Requires: scout (pip install scoutsuite), prowler (pip install prowler), aws CLI
"""

import json
import os
import glob
import subprocess
import shutil
from typing import Any

# ---------------------------------------------------------------------------
# MANIFEST
# ---------------------------------------------------------------------------
MANIFEST = {
    "id": "cloud-security",
    "name": "Cloud Security Assessment",
    "description": (
        "Cloud security assessment for AWS, Azure, GCP and more. "
        "Uses ScoutSuite and Prowler to surface misconfigurations, compliance gaps, "
        "and IAM weaknesses across your cloud environment."
    ),
    "version": "1.0.0",
    "author": "ARGOS",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _which(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list, env: dict = None, timeout: int = 120) -> subprocess.CompletedProcess:
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=effective_env,
    )


def _aws_cmd(args: list, profile: str = "default", timeout: int = 30) -> dict:
    """Run an AWS CLI command and return parsed JSON output."""
    if not _which("aws"):
        return {"__error__": "aws CLI not installed. Install: https://aws.amazon.com/cli/"}
    cmd = ["aws"] + args + ["--profile", profile, "--output", "json"]
    try:
        result = _run(cmd, timeout=timeout)
        if result.returncode != 0:
            return {"__error__": result.stderr.strip()[:500]}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"__error__": f"aws command timed out: {' '.join(args)}"}
    except json.JSONDecodeError:
        return {"__error__": "Could not parse aws CLI output as JSON."}


def _parse_severity(severity_str: str) -> str:
    return severity_str.lower() if severity_str else "informational"


# ---------------------------------------------------------------------------
# Severity bucket counters
# ---------------------------------------------------------------------------

def _empty_severity_buckets() -> dict:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}


def _bump_severity(buckets: dict, severity: str) -> None:
    key = _parse_severity(severity)
    if key in buckets:
        buckets[key] += 1
    else:
        buckets["informational"] += 1


# ---------------------------------------------------------------------------
# ScoutSuite report parser
# ---------------------------------------------------------------------------

def _parse_scoutsuite_report(report_dir: str, provider: str) -> tuple:
    """
    Returns (findings, by_severity, services_scanned).
    ScoutSuite writes a JSON report as scoutsuite_results_{provider}.js
    (a JavaScript file wrapping a JSON object).
    """
    findings: list = []
    by_severity = _empty_severity_buckets()
    services_scanned: list = []

    # ScoutSuite report can be .js (wrapped) or .json
    candidates = (
        glob.glob(os.path.join(report_dir, "scoutsuite_results*.js"))
        + glob.glob(os.path.join(report_dir, "scoutsuite_results*.json"))
        + glob.glob(os.path.join(report_dir, "*.json"))
    )

    if not candidates:
        return findings, by_severity, services_scanned

    report_path = candidates[0]
    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            content = fh.read()

        # Strip JS wrapper: `scoutsuite_results = {...};`
        if content.strip().startswith("scoutsuite_results"):
            idx = content.index("{")
            content = content[idx:]
            if content.endswith(";"):
                content = content[:-1]

        data = json.loads(content)
    except (OSError, json.JSONDecodeError, ValueError):
        return findings, by_severity, services_scanned

    services = data.get("services", {})
    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            continue
        services_scanned.append(service_name)
        findings_dict = service_data.get("findings", {})
        for finding_id, finding in findings_dict.items():
            if not isinstance(finding, dict):
                continue
            flagged = finding.get("flagged_items", 0)
            if flagged == 0:
                continue
            level = finding.get("level", "informational")
            description = finding.get("description", finding_id)
            findings.append({
                "id": finding_id,
                "service": service_name,
                "severity": level,
                "description": description,
                "flagged_items": flagged,
            })
            _bump_severity(by_severity, level)

    return findings, by_severity, services_scanned


# ---------------------------------------------------------------------------
# Prowler report parser
# ---------------------------------------------------------------------------

def _parse_prowler_report(output_dir: str) -> tuple:
    """
    Returns (checks_run, passed, failed, findings, compliance).
    Prowler -M json writes one JSON object per line (JSONL).
    """
    checks_run = 0
    passed = 0
    failed = 0
    findings: list = []
    compliance: dict = {}

    json_files = (
        glob.glob(os.path.join(output_dir, "*.json"))
        + glob.glob(os.path.join(output_dir, "**", "*.json"), recursive=True)
    )

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Handle list-wrapped format (some Prowler versions)
                    if isinstance(entry, list):
                        entries = entry
                    else:
                        entries = [entry]

                    for item in entries:
                        if not isinstance(item, dict):
                            continue
                        checks_run += 1
                        status = item.get("Status", item.get("status", "")).upper()
                        if status == "PASS":
                            passed += 1
                        else:
                            failed += 1
                            findings.append({
                                "check_id": item.get("CheckID", item.get("check_id", "unknown")),
                                "service": item.get("ServiceName", item.get("service", "unknown")),
                                "severity": item.get("Severity", item.get("severity", "unknown")).lower(),
                                "status": status,
                                "description": item.get("CheckTitle", item.get("description", ""))[:300],
                                "resource": item.get("ResourceArn", item.get("resource_arn", ""))[:200],
                                "region": item.get("Region", item.get("region", "")),
                            })
                        # Compliance frameworks
                        for comp_key in ("Compliance", "compliance"):
                            comp_data = item.get(comp_key, {})
                            if isinstance(comp_data, dict):
                                for framework, controls in comp_data.items():
                                    if framework not in compliance:
                                        compliance[framework] = {"passed": 0, "failed": 0}
                                    if status == "PASS":
                                        compliance[framework]["passed"] += 1
                                    else:
                                        compliance[framework]["failed"] += 1
        except OSError:
            pass

    return checks_run, passed, failed, findings, compliance


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def scoutsuite_scan(
    provider: str = "aws",
    profile: str = "default",
    regions: str = "",
    services: str = "",
) -> dict:
    """Run a ScoutSuite scan against a cloud provider."""
    if not _which("scout"):
        return {
            "error": "ScoutSuite not installed. Install: pip install scoutsuite"
        }

    valid_providers = {"aws", "azure", "gcp", "aliyun", "oci"}
    if provider not in valid_providers:
        return {"error": f"Invalid provider '{provider}'. Valid options: {sorted(valid_providers)}"}

    report_dir = "/tmp/scoutsuite_report"
    os.makedirs(report_dir, exist_ok=True)

    cmd = [
        "scout", provider,
        "--report-dir", report_dir,
        "--no-browser",
    ]

    if provider == "aws":
        cmd += ["--profile", profile]

    if regions.strip():
        cmd += ["--regions", regions.strip()]

    if services.strip():
        cmd += ["--services", services.strip()]

    try:
        result = _run(cmd, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "ScoutSuite scan timed out after 120 seconds."}
    except FileNotFoundError:
        return {"error": "ScoutSuite not installed. Install: pip install scoutsuite"}

    findings, by_severity, services_scanned = _parse_scoutsuite_report(report_dir, provider)

    return {
        "provider": provider,
        "profile": profile,
        "regions": regions or "all",
        "services_requested": services or "all",
        "findings": findings,
        "by_severity": by_severity,
        "services_scanned": services_scanned,
        "total_findings": len(findings),
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-800:] if result.stdout else "",
        "stderr_tail": result.stderr[-400:] if result.stderr else "",
    }


def prowler_scan(
    provider: str = "aws",
    checks: str = "",
    compliance: str = "",
    profile: str = "default",
    output_dir: str = "/tmp/prowler_out",
) -> dict:
    """Run a Prowler scan and return structured findings."""
    if not _which("prowler"):
        return {
            "error": "Prowler not installed. Install: pip install prowler"
        }

    valid_providers = {"aws", "azure", "gcp", "kubernetes"}
    if provider not in valid_providers:
        return {"error": f"Invalid provider '{provider}'. Valid: {sorted(valid_providers)}"}

    valid_compliance = {
        "cis_aws_benchmark_3.0", "gdpr", "hipaa",
        "pci_dss_3.2.1", "soc2", "nist_800_53",
    }
    if compliance and compliance not in valid_compliance:
        return {
            "error": f"Invalid compliance framework '{compliance}'. Valid: {sorted(valid_compliance)}"
        }

    os.makedirs(output_dir, exist_ok=True)

    cmd = ["prowler", provider, "-M", "json", "-o", output_dir]

    if provider == "aws":
        cmd += ["--profile", profile]

    if checks.strip():
        cmd += ["-c", checks.strip()]

    if compliance.strip():
        cmd += ["--compliance", compliance.strip()]

    try:
        result = _run(cmd, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "Prowler scan timed out after 120 seconds."}
    except FileNotFoundError:
        return {"error": "Prowler not installed. Install: pip install prowler"}

    checks_run, passed_count, failed_count, findings, compliance_data = _parse_prowler_report(output_dir)

    return {
        "provider": provider,
        "profile": profile,
        "checks_requested": checks or "all",
        "compliance_framework": compliance or "none",
        "checks_run": checks_run,
        "passed": passed_count,
        "failed": failed_count,
        "findings": findings,
        "compliance": compliance_data,
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-800:] if result.stdout else "",
        "stderr_tail": result.stderr[-400:] if result.stderr else "",
    }


def prowler_list_checks(
    provider: str = "aws",
    service: str = "",
) -> dict:
    """List available Prowler checks, optionally filtered by service."""
    if not _which("prowler"):
        return {
            "error": "Prowler not installed. Install: pip install prowler"
        }

    cmd = ["prowler", provider, "--list-checks"]

    try:
        result = _run(cmd, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "prowler --list-checks timed out after 60 seconds."}
    except FileNotFoundError:
        return {"error": "Prowler not installed. Install: pip install prowler"}

    checks = _parse_prowler_list_checks(result.stdout, service)

    return {
        "provider": provider,
        "service_filter": service or "all",
        "checks": checks,
        "total": len(checks),
    }


def _parse_prowler_list_checks(output: str, service_filter: str = "") -> list:
    """Parse `prowler --list-checks` output into structured records."""
    checks = []
    service_filter_lower = service_filter.lower()

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("="):
            continue

        # Prowler typically outputs: check_id [severity] description
        # or just check_id per line; handle both
        parts = line.split(None, 2)
        if not parts:
            continue

        check_id = parts[0]
        # Infer service from check_id prefix (e.g. iam_root_mfa -> iam)
        service = check_id.split("_")[0] if "_" in check_id else "unknown"

        if service_filter_lower and service_filter_lower not in service.lower():
            continue

        severity = "medium"
        description = ""
        if len(parts) >= 2 and parts[1].startswith("["):
            # Format: check_id [SEVERITY] description
            sev_candidate = parts[1].strip("[]").lower()
            if sev_candidate in ("critical", "high", "medium", "low", "informational"):
                severity = sev_candidate
            description = parts[2] if len(parts) > 2 else ""
        elif len(parts) >= 2:
            description = " ".join(parts[1:])

        checks.append({
            "id": check_id,
            "service": service,
            "severity": severity,
            "description": description[:200],
        })

    return checks


def cloud_quick_audit(
    provider: str = "aws",
    profile: str = "default",
) -> dict:
    """
    Fast cloud security audit using AWS CLI or Prowler subset.
    Checks: MFA on root, public S3 buckets, overly permissive IAM, open security groups.
    """
    critical_issues: list = []
    quick_wins: list = []
    estimated_risk = "LOW"

    if provider != "aws":
        # For non-AWS: delegate to prowler with a small check set
        if not _which("prowler"):
            return {
                "error": (
                    f"Quick audit for '{provider}' requires Prowler. "
                    "Install: pip install prowler"
                )
            }
        return _prowler_quick_audit(provider, profile, critical_issues, quick_wins)

    # ----- AWS-specific quick checks via AWS CLI -----

    # 1. Root MFA
    account_summary = _aws_cmd(["iam", "get-account-summary"], profile=profile)
    if "__error__" not in account_summary:
        summary_map = account_summary.get("SummaryMap", {})
        if summary_map.get("AccountMFAEnabled", 0) == 0:
            critical_issues.append({
                "check": "root_mfa_disabled",
                "severity": "critical",
                "description": "MFA is NOT enabled on the root account.",
                "remediation": "Enable MFA for root: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            })
        else:
            quick_wins.append("Root MFA is enabled.")

        # Root access keys
        if summary_map.get("AccountAccessKeysPresent", 0) > 0:
            critical_issues.append({
                "check": "root_access_keys_present",
                "severity": "critical",
                "description": "Root account has active access keys.",
                "remediation": "Delete root access keys immediately.",
            })

    # 2. Public S3 buckets (account-level public access block)
    s3_public_block = _aws_cmd(
        ["s3control", "get-public-access-block", "--account-id",
         _get_account_id(profile)],
        profile=profile,
    )
    if "__error__" not in s3_public_block:
        cfg = s3_public_block.get("PublicAccessBlockConfiguration", {})
        if not all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("RestrictPublicBuckets", False),
        ]):
            critical_issues.append({
                "check": "s3_account_public_access_not_fully_blocked",
                "severity": "high",
                "description": "S3 account-level public access block is not fully enabled.",
                "remediation": "Enable all four S3 Block Public Access settings at the account level.",
            })
        else:
            quick_wins.append("S3 account-level public access block is fully enabled.")
    else:
        # Fallback: list buckets and check individual policies
        _check_s3_buckets(profile, critical_issues, quick_wins)

    # 3. IAM users without MFA
    users_response = _aws_cmd(["iam", "list-users"], profile=profile)
    if "__error__" not in users_response:
        users = users_response.get("Users", [])
        users_no_mfa = []
        for user in users:
            username = user.get("UserName", "")
            mfa_resp = _aws_cmd(
                ["iam", "list-mfa-devices", "--user-name", username],
                profile=profile,
            )
            if "__error__" not in mfa_resp:
                if len(mfa_resp.get("MFADevices", [])) == 0:
                    users_no_mfa.append(username)
        if users_no_mfa:
            critical_issues.append({
                "check": "iam_users_without_mfa",
                "severity": "high",
                "description": f"{len(users_no_mfa)} IAM user(s) have no MFA device.",
                "affected_users": users_no_mfa[:20],
                "remediation": "Enforce MFA for all IAM users via an IAM policy condition.",
            })
        else:
            quick_wins.append("All IAM users have MFA enabled.")

    # 4. Security groups with 0.0.0.0/0 ingress on dangerous ports
    ec2_sgs = _aws_cmd(["ec2", "describe-security-groups"], profile=profile, timeout=45)
    if "__error__" not in ec2_sgs:
        dangerous_ports = {22, 3389, 1433, 3306, 5432, 27017, 6379, 9200}
        open_sgs = []
        for sg in ec2_sgs.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                port_range = set(range(from_port, to_port + 1)) if from_port and to_port else set()
                is_dangerous_port = bool(port_range & dangerous_ports) or (from_port == -1)
                open_to_world = any(
                    r.get("CidrIp") in ("0.0.0.0/0", "::/0")
                    for r in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", [])
                )
                if open_to_world and is_dangerous_port:
                    open_sgs.append({
                        "sg_id": sg.get("GroupId"),
                        "sg_name": sg.get("GroupName"),
                        "from_port": from_port,
                        "to_port": to_port,
                    })
        if open_sgs:
            critical_issues.append({
                "check": "ec2_security_group_open_to_world",
                "severity": "critical",
                "description": f"{len(open_sgs)} security group(s) allow world access on sensitive ports.",
                "affected_groups": open_sgs[:10],
                "remediation": "Restrict ingress rules to known IP ranges or VPN CIDRs.",
            })
        else:
            quick_wins.append("No security groups expose dangerous ports (22/3389/DB) to 0.0.0.0/0.")

    # Compute overall risk
    critical_count = sum(1 for i in critical_issues if i.get("severity") == "critical")
    high_count = sum(1 for i in critical_issues if i.get("severity") == "high")
    if critical_count >= 2 or (critical_count >= 1 and high_count >= 1):
        estimated_risk = "HIGH"
    elif critical_count >= 1 or high_count >= 2:
        estimated_risk = "MEDIUM"
    else:
        estimated_risk = "LOW"

    return {
        "provider": provider,
        "profile": profile,
        "critical_issues": critical_issues,
        "quick_wins": quick_wins,
        "estimated_risk": estimated_risk,
        "total_issues_found": len(critical_issues),
    }


def _get_account_id(profile: str) -> str:
    resp = _aws_cmd(["sts", "get-caller-identity"], profile=profile)
    return resp.get("Account", "unknown")


def _check_s3_buckets(profile: str, critical_issues: list, quick_wins: list) -> None:
    """Fallback: check individual S3 bucket ACLs for public access."""
    buckets_resp = _aws_cmd(["s3api", "list-buckets"], profile=profile)
    if "__error__" in buckets_resp:
        return
    public_buckets = []
    for bucket in (buckets_resp.get("Buckets") or [])[:50]:  # cap at 50
        name = bucket.get("Name", "")
        acl_resp = _aws_cmd(["s3api", "get-bucket-acl", "--bucket", name], profile=profile)
        if "__error__" in acl_resp:
            continue
        for grant in acl_resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                public_buckets.append(name)
                break
    if public_buckets:
        critical_issues.append({
            "check": "s3_bucket_publicly_accessible",
            "severity": "critical",
            "description": f"{len(public_buckets)} S3 bucket(s) are publicly accessible via ACL.",
            "affected_buckets": public_buckets[:10],
            "remediation": "Set bucket ACL to private and enable block public access.",
        })
    else:
        quick_wins.append("No S3 buckets with public ACL grants found (sampled).")


def _prowler_quick_audit(
    provider: str,
    profile: str,
    critical_issues: list,
    quick_wins: list,
) -> dict:
    """Delegate quick audit to Prowler for non-AWS providers."""
    critical_checks = "iam,s3,ec2" if provider == "aws" else ""
    prowler_result = prowler_scan(
        provider=provider,
        profile=profile,
        checks=critical_checks,
        output_dir="/tmp/prowler_quick",
    )
    if "error" in prowler_result:
        return prowler_result

    for finding in prowler_result.get("findings", []):
        if finding.get("severity") in ("critical", "high"):
            critical_issues.append({
                "check": finding.get("check_id"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
                "resource": finding.get("resource"),
            })

    estimated_risk = "HIGH" if len(critical_issues) >= 3 else ("MEDIUM" if critical_issues else "LOW")
    return {
        "provider": provider,
        "profile": profile,
        "critical_issues": critical_issues,
        "quick_wins": quick_wins,
        "estimated_risk": estimated_risk,
        "total_issues_found": len(critical_issues),
    }


def iam_analyzer(
    provider: str = "aws",
    profile: str = "default",
) -> dict:
    """
    Deep IAM analysis: users without MFA, old access keys, admin users, unused roles.
    Uses AWS CLI if available, falls back to Prowler.
    """
    if not _which("aws") and not _which("prowler"):
        return {
            "error": (
                "Neither 'aws' CLI nor 'prowler' is installed. "
                "Install one: pip install prowler  OR  https://aws.amazon.com/cli/"
            )
        }

    users_without_mfa: list = []
    old_access_keys: list = []   # keys older than 90 days
    admin_users: list = []
    unused_roles: list = []

    if _which("aws"):
        _iam_via_aws_cli(profile, users_without_mfa, old_access_keys, admin_users, unused_roles)
    else:
        # Prowler fallback
        return _iam_via_prowler(provider, profile)

    return {
        "provider": provider,
        "profile": profile,
        "users_without_mfa": users_without_mfa,
        "old_access_keys": old_access_keys,
        "admin_users": admin_users,
        "unused_roles": unused_roles,
        "summary": {
            "users_without_mfa_count": len(users_without_mfa),
            "old_access_keys_count": len(old_access_keys),
            "admin_users_count": len(admin_users),
            "unused_roles_count": len(unused_roles),
        },
    }


def _iam_via_aws_cli(
    profile: str,
    users_without_mfa: list,
    old_access_keys: list,
    admin_users: list,
    unused_roles: list,
) -> None:
    """Populate IAM lists using AWS CLI calls."""
    import datetime

    # 1. Generate credential report (contains MFA status, key ages)
    _aws_cmd(["iam", "generate-credential-report"], profile=profile, timeout=30)
    import time as _time
    _time.sleep(2)  # allow report to generate
    cred_report_resp = _aws_cmd(
        ["iam", "get-credential-report"], profile=profile, timeout=30
    )

    if "__error__" not in cred_report_resp:
        import base64, csv, io
        content = cred_report_resp.get("Content", "")
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            reader = csv.DictReader(io.StringIO(decoded))
            now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            for row in reader:
                username = row.get("user", "")
                if username == "<root_account>":
                    continue

                # MFA check
                mfa_active = row.get("mfa_active", "false").lower() == "true"
                if not mfa_active:
                    users_without_mfa.append(username)

                # Access key age
                for key_num in ("1", "2"):
                    key_active = row.get(f"access_key_{key_num}_active", "false").lower() == "true"
                    last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                    if key_active and last_rotated not in ("N/A", "no_information", ""):
                        try:
                            rotated_dt = datetime.datetime.fromisoformat(
                                last_rotated.replace("Z", "+00:00")
                            )
                            age_days = (now - rotated_dt).days
                            if age_days > 90:
                                old_access_keys.append({
                                    "username": username,
                                    "key_number": int(key_num),
                                    "age_days": age_days,
                                    "last_rotated": last_rotated,
                                })
                        except ValueError:
                            pass
        except Exception:  # noqa: BLE001
            pass

    # 2. Admin users (attached AdministratorAccess policy)
    users_resp = _aws_cmd(["iam", "list-users"], profile=profile)
    if "__error__" not in users_resp:
        for user in users_resp.get("Users", [])[:100]:
            username = user.get("UserName", "")
            attached = _aws_cmd(
                ["iam", "list-attached-user-policies", "--user-name", username],
                profile=profile,
            )
            if "__error__" in attached:
                continue
            for policy in attached.get("AttachedPolicies", []):
                if policy.get("PolicyName") == "AdministratorAccess":
                    admin_users.append(username)
                    break

    # 3. Unused roles (no last used date or unused > 90 days)
    roles_resp = _aws_cmd(["iam", "list-roles"], profile=profile)
    if "__error__" not in roles_resp:
        import datetime
        now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        for role in roles_resp.get("Roles", [])[:100]:
            role_name = role.get("RoleName", "")
            role_detail = _aws_cmd(
                ["iam", "get-role", "--role-name", role_name], profile=profile
            )
            if "__error__" in role_detail:
                continue
            role_info = role_detail.get("Role", {})
            last_used = role_info.get("RoleLastUsed", {})
            last_used_date = last_used.get("LastUsedDate")
            if last_used_date is None:
                unused_roles.append({"role_name": role_name, "last_used": "never"})
            else:
                try:
                    lu_dt = datetime.datetime.fromisoformat(
                        last_used_date.replace("Z", "+00:00")
                    )
                    age_days = (now - lu_dt).days
                    if age_days > 90:
                        unused_roles.append({
                            "role_name": role_name,
                            "last_used": last_used_date,
                            "days_since_used": age_days,
                        })
                except ValueError:
                    pass


def _iam_via_prowler(provider: str, profile: str) -> dict:
    """Run Prowler IAM checks as fallback."""
    result = prowler_scan(
        provider=provider,
        checks="iam",
        profile=profile,
        output_dir="/tmp/prowler_iam",
    )
    if "error" in result:
        return result

    users_without_mfa: list = []
    old_access_keys: list = []
    admin_users: list = []
    unused_roles: list = []

    for finding in result.get("findings", []):
        check_id = finding.get("check_id", "")
        desc = finding.get("description", "")
        resource = finding.get("resource", "")
        if "mfa" in check_id.lower():
            users_without_mfa.append({"resource": resource, "description": desc})
        elif "key" in check_id.lower() and "rotat" in check_id.lower():
            old_access_keys.append({"resource": resource, "description": desc})
        elif "admin" in check_id.lower() or "administrator" in desc.lower():
            admin_users.append({"resource": resource, "description": desc})
        elif "unused" in check_id.lower() or "unused" in desc.lower():
            unused_roles.append({"resource": resource, "description": desc})

    return {
        "provider": provider,
        "profile": profile,
        "users_without_mfa": users_without_mfa,
        "old_access_keys": old_access_keys,
        "admin_users": admin_users,
        "unused_roles": unused_roles,
        "summary": {
            "users_without_mfa_count": len(users_without_mfa),
            "old_access_keys_count": len(old_access_keys),
            "admin_users_count": len(admin_users),
            "unused_roles_count": len(unused_roles),
        },
    }


# ---------------------------------------------------------------------------
# TOOLS registry
# ---------------------------------------------------------------------------

TOOLS = {
    "scoutsuite_scan": {
        "fn": scoutsuite_scan,
        "description": (
            "Run a ScoutSuite multi-cloud security audit (AWS, Azure, GCP, Aliyun, OCI). "
            "Returns findings grouped by severity and service."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Cloud provider: aws, azure, gcp, aliyun, oci.",
                    "default": "aws",
                    "enum": ["aws", "azure", "gcp", "aliyun", "oci"],
                },
                "profile": {
                    "type": "string",
                    "description": "AWS/Azure/GCP credential profile name.",
                    "default": "default",
                },
                "regions": {
                    "type": "string",
                    "description": "Comma-separated regions to scan (empty = all).",
                    "default": "",
                },
                "services": {
                    "type": "string",
                    "description": "Comma-separated services to scan, e.g. 'ec2,s3,iam' (empty = all).",
                    "default": "",
                },
            },
            "required": [],
        },
    },
    "prowler_scan": {
        "fn": prowler_scan,
        "description": (
            "Run a Prowler cloud security scan. Supports compliance frameworks: "
            "cis_aws_benchmark_3.0, gdpr, hipaa, pci_dss_3.2.1, soc2, nist_800_53."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Cloud provider: aws, azure, gcp, kubernetes.",
                    "default": "aws",
                    "enum": ["aws", "azure", "gcp", "kubernetes"],
                },
                "checks": {
                    "type": "string",
                    "description": "Comma-separated check IDs to run (empty = all).",
                    "default": "",
                },
                "compliance": {
                    "type": "string",
                    "description": "Compliance framework, e.g. cis_aws_benchmark_3.0, gdpr, hipaa.",
                    "default": "",
                },
                "profile": {
                    "type": "string",
                    "description": "AWS credential profile name.",
                    "default": "default",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write Prowler JSON output.",
                    "default": "/tmp/prowler_out",
                },
            },
            "required": [],
        },
    },
    "prowler_list_checks": {
        "fn": prowler_list_checks,
        "description": (
            "List all available Prowler checks for a provider, optionally filtered by service "
            "(iam, ec2, s3, rds, etc.)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Cloud provider: aws, azure, gcp, kubernetes.",
                    "default": "aws",
                    "enum": ["aws", "azure", "gcp", "kubernetes"],
                },
                "service": {
                    "type": "string",
                    "description": "Filter checks by service name prefix (e.g. 'iam', 'ec2', 's3').",
                    "default": "",
                },
            },
            "required": [],
        },
    },
    "cloud_quick_audit": {
        "fn": cloud_quick_audit,
        "description": (
            "Fast cloud security audit without waiting for a full scan. "
            "Checks root MFA, public S3 buckets, IAM users without MFA, and open security groups. "
            "Returns critical issues, quick wins, and an overall risk rating."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Cloud provider (aws recommended; others use Prowler).",
                    "default": "aws",
                },
                "profile": {
                    "type": "string",
                    "description": "AWS credential profile name.",
                    "default": "default",
                },
            },
            "required": [],
        },
    },
    "iam_analyzer": {
        "fn": iam_analyzer,
        "description": (
            "Deep IAM analysis: finds users without MFA, access keys older than 90 days, "
            "users with AdministratorAccess, and roles unused for 90+ days. "
            "Uses AWS CLI (credential report) when available, falls back to Prowler."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Cloud provider.",
                    "default": "aws",
                },
                "profile": {
                    "type": "string",
                    "description": "AWS credential profile name.",
                    "default": "default",
                },
            },
            "required": [],
        },
    },
}
