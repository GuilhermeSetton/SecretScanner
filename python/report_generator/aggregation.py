from collections import defaultdict
from typing import Any, Dict, List

from .models import Finding, ScanReport

REMEDIATION_MAP = {
    "internal.aws-access-key-id": "Rotate the exposed AWS Access Key ID and migrate authentication to IAM Roles for Service Accounts (IRSA) or AWS Secrets Manager.",
    "internal.aws-secret-access-key": "Revoke the exposed AWS Secret Access Key immediately and inject credentials via External Secrets Operator or Kubernetes Secrets.",
    "internal.google-api-key": "Restrict Google API Key scopes in GCP IAM and mount the key securely via Secret or Workload Identity Federation.",
    "internal.ssh-private-key": "Revoke and regenerate the compromised private key immediately; manage SSH credentials with cert-manager or Vault.",
    "internal.jwt-token": "Invalidate the active token session and avoid hardcoding long-lived authorization tokens directly in manifest files.",
    "internal.sensitive-env-var": "Refactor hardcoded container environment variables to reference Kubernetes Secrets using secretKeyRef or valueFrom.",
    "internal.shannon-entropy": "Inspect the high-entropy string. If it represents a secret or API token, migrate it into a managed secret store.",
}

DEFAULT_REMEDIATION = "Remove the hardcoded secret and migrate to a secure secrets manager (External Secrets, HashiCorp Vault, or SealedSecrets)."


def get_remediation(rule_id: str) -> str:
    return REMEDIATION_MAP.get(rule_id, DEFAULT_REMEDIATION)


def aggregate_report(report: ScanReport) -> Dict[str, Any]:
    severity_counts = {
        "critical": report.summary.critical,
        "high": report.summary.high,
        "medium": report.summary.medium,
        "low": report.summary.low,
    }

    # Group by Rule ID
    rule_groups: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "severity": "",
        "description": "",
        "remediation": "",
    })

    for f in report.findings:
        entry = rule_groups[f.rule_id]
        entry["count"] += 1
        entry["severity"] = f.severity
        entry["description"] = f.description
        entry["remediation"] = get_remediation(f.rule_id)

    # Group by File
    files_map: Dict[str, List[Finding]] = defaultdict(list)
    for f in report.findings:
        files_map[f.file].append(f)

    # Group by Resource
    resource_map: Dict[str, List[Finding]] = defaultdict(list)
    for f in report.findings:
        res_key = f"{f.kind or 'Resource'}/{f.resource or 'Unnamed'}"
        resource_map[res_key].append(f)

    # Status classification
    if report.summary.errors > 0:
        overall_status = "ERROR"
    elif report.summary.findings > 0:
        overall_status = "FAILED"
    else:
        overall_status = "PASSED"

    return {
        "schema_version": report.schema_version,
        "status": overall_status,
        "summary": {
            "files_scanned": report.summary.files_scanned,
            "findings": report.summary.findings,
            "errors": report.summary.errors,
            "critical": report.summary.critical,
            "high": report.summary.high,
            "medium": report.summary.medium,
            "low": report.summary.low,
            "duration_ms": report.summary.duration_ms,
            "scanner_version": report.summary.scanner_version,
            "severity_distribution": severity_counts,
        },
        "rule_distribution": dict(rule_groups),
        "affected_files_count": len(files_map),
        "affected_files": sorted(files_map.keys()),
        "findings": [
            {
                "rule_id": f.rule_id,
                "description": f.description,
                "severity": f.severity,
                "confidence": f.confidence,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "field_path": f.field_path,
                "resource": f.resource,
                "kind": f.kind,
                "match": f.match,
                "remediation": get_remediation(f.rule_id),
            }
            for f in report.findings
        ],
        "errors": [
            {
                "file": e.file,
                "message": e.message,
            }
            for e in report.errors
        ],
    }
