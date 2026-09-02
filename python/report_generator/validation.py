import json
import os
import re
from typing import Any, Dict, List

from .models import Finding, ScanError, ScanReport, ScanSummary

MAX_INPUT_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
ALLOWED_CONFIDENCES = {"critical", "high", "medium", "low"}
SCHEMA_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")
CURRENT_SCHEMA_VERSION = "1.0"


ALLOWED_ROOT_KEYS = {"schema_version", "summary", "findings", "errors"}
ALLOWED_SUMMARY_KEYS = {
    "files_scanned", "findings", "errors", "critical", "high", "medium", "low", "duration_ms", "scanner_version"
}
ALLOWED_FINDING_KEYS = {
    "rule_id", "description", "severity", "confidence", "file", "line", "column", "field_path", "match", "resource", "kind"
}
ALLOWED_ERROR_KEYS = {"file", "message"}


class ValidationError(Exception):
    """Raised when scan JSON payload fails schema or structural validation."""
    pass


def load_and_validate_file(file_path: str) -> ScanReport:
    if not os.path.exists(file_path):
        raise ValidationError(f"Input file does not exist: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size > MAX_INPUT_FILE_SIZE_BYTES:
        raise ValidationError(
            f"Input file size ({file_size} bytes) exceeds maximum allowable limit of {MAX_INPUT_FILE_SIZE_BYTES} bytes"
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Failed to parse input file as valid JSON: {e}")
    except Exception as e:
        raise ValidationError(f"Failed to read input file: {e}")

    return validate_scan_report(raw_data)


def validate_scan_report(data: Any) -> ScanReport:
    if not isinstance(data, dict):
        raise ValidationError(f"Root JSON element must be an object, got {type(data).__name__}")

    # Enforce strict root keys (additionalProperties: false)
    root_keys = set(data.keys())
    missing_root_keys = ALLOWED_ROOT_KEYS - root_keys
    if missing_root_keys:
        raise ValidationError(f"Missing required top-level key(s): {', '.join(sorted(missing_root_keys))}")
    unexpected_root_keys = root_keys - ALLOWED_ROOT_KEYS
    if unexpected_root_keys:
        raise ValidationError(f"Unexpected additional top-level key(s): {', '.join(sorted(unexpected_root_keys))}")

    # Validate schema_version
    schema_ver = data["schema_version"]
    if not isinstance(schema_ver, str) or not SCHEMA_VERSION_PATTERN.match(schema_ver):
        raise ValidationError(f"Invalid schema_version '{schema_ver}', expected string format like '1.0'")
    if schema_ver != CURRENT_SCHEMA_VERSION:
        raise ValidationError(
            f"Unsupported schema_version '{schema_ver}', supported version is '{CURRENT_SCHEMA_VERSION}'"
        )

    # Validate summary
    summary_data = data["summary"]
    if not isinstance(summary_data, dict):
        raise ValidationError("summary must be an object")

    summary_keys = set(summary_data.keys())
    missing_summary_keys = ALLOWED_SUMMARY_KEYS - summary_keys
    if missing_summary_keys:
        raise ValidationError(f"Missing required summary key(s): {', '.join(sorted(missing_summary_keys))}")
    unexpected_summary_keys = summary_keys - ALLOWED_SUMMARY_KEYS
    if unexpected_summary_keys:
        raise ValidationError(f"Unexpected additional summary key(s): {', '.join(sorted(unexpected_summary_keys))}")

    int_fields = ["files_scanned", "findings", "errors", "critical", "high", "medium", "low", "duration_ms"]
    for field_name in int_fields:
        val = summary_data[field_name]
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValidationError(f"summary.{field_name} must be a non-negative integer, got {val!r}")

    scanner_version = summary_data["scanner_version"]
    if not isinstance(scanner_version, str):
        raise ValidationError(f"summary.scanner_version must be a string, got {type(scanner_version).__name__}")

    summary = ScanSummary(
        files_scanned=summary_data["files_scanned"],
        findings=summary_data["findings"],
        errors=summary_data["errors"],
        critical=summary_data["critical"],
        high=summary_data["high"],
        medium=summary_data["medium"],
        low=summary_data["low"],
        duration_ms=summary_data["duration_ms"],
        scanner_version=scanner_version,
    )

    # Validate findings list
    findings_data = data["findings"]
    if not isinstance(findings_data, list):
        raise ValidationError(f"findings must be a list, got {type(findings_data).__name__}")

    validated_findings: List[Finding] = []
    required_finding_keys = {
        "rule_id", "description", "severity", "confidence", "file", "line", "column", "field_path", "match"
    }

    for idx, item in enumerate(findings_data):
        if not isinstance(item, dict):
            raise ValidationError(f"Finding at index {idx} must be an object")

        item_keys = set(item.keys())
        missing_finding_keys = required_finding_keys - item_keys
        if missing_finding_keys:
            raise ValidationError(f"Finding at index {idx} missing key(s): {', '.join(sorted(missing_finding_keys))}")
        unexpected_finding_keys = item_keys - ALLOWED_FINDING_KEYS
        if unexpected_finding_keys:
            raise ValidationError(f"Finding at index {idx} has unexpected key(s): {', '.join(sorted(unexpected_finding_keys))}")

        severity = item["severity"].lower() if isinstance(item["severity"], str) else None
        if severity not in ALLOWED_SEVERITIES:
            raise ValidationError(f"Finding at index {idx} has invalid severity '{item.get('severity')}'")

        confidence = item["confidence"].lower() if isinstance(item["confidence"], str) else None
        if confidence not in ALLOWED_CONFIDENCES:
            raise ValidationError(f"Finding at index {idx} has invalid confidence '{item.get('confidence')}'")

        line = item["line"]
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValidationError(f"Finding at index {idx} line must be integer >= 1, got {line!r}")

        column = item["column"]
        if not isinstance(column, int) or isinstance(column, bool) or column < 1:
            raise ValidationError(f"Finding at index {idx} column must be integer >= 1, got {column!r}")

        for str_key in ["rule_id", "description", "file", "field_path", "match"]:
            if not isinstance(item[str_key], str):
                raise ValidationError(f"Finding at index {idx} field '{str_key}' must be a string")

        resource = item.get("resource")
        if resource is not None and not isinstance(resource, str):
            raise ValidationError(f"Finding at index {idx} field 'resource' must be string if present")

        kind = item.get("kind")
        if kind is not None and not isinstance(kind, str):
            raise ValidationError(f"Finding at index {idx} field 'kind' must be string if present")

        validated_findings.append(Finding(
            rule_id=item["rule_id"],
            description=item["description"],
            severity=severity,
            confidence=confidence,
            file=item["file"],
            line=line,
            column=column,
            field_path=item["field_path"],
            match=item["match"],
            resource=resource,
            kind=kind,
        ))

    # Validate errors list
    errors_data = data["errors"]
    if not isinstance(errors_data, list):
        raise ValidationError(f"errors must be a list, got {type(errors_data).__name__}")

    validated_errors: List[ScanError] = []
    for idx, item in enumerate(errors_data):
        if not isinstance(item, dict):
            raise ValidationError(f"Error at index {idx} must be an object")

        err_keys = set(item.keys())
        missing_err_keys = ALLOWED_ERROR_KEYS - err_keys
        if missing_err_keys:
            raise ValidationError(f"Error at index {idx} missing key(s): {', '.join(sorted(missing_err_keys))}")
        unexpected_err_keys = err_keys - ALLOWED_ERROR_KEYS
        if unexpected_err_keys:
            raise ValidationError(f"Error at index {idx} has unexpected key(s): {', '.join(sorted(unexpected_err_keys))}")

        if not isinstance(item["file"], str) or not isinstance(item["message"], str):
            raise ValidationError(f"Error at index {idx} 'file' and 'message' must be strings")

        validated_errors.append(ScanError(
            file=item["file"],
            message=item["message"],
        ))

    # Strict consistency verification between summary metrics and actual items
    if summary.findings != len(validated_findings):
        raise ValidationError(
            f"Summary findings count ({summary.findings}) does not match actual findings count ({len(validated_findings)})"
        )

    if summary.errors != len(validated_errors):
        raise ValidationError(
            f"Summary errors count ({summary.errors}) does not match actual errors count ({len(validated_errors)})"
        )

    actual_severity_counts = {
        "critical": sum(1 for f in validated_findings if f.severity == "critical"),
        "high": sum(1 for f in validated_findings if f.severity == "high"),
        "medium": sum(1 for f in validated_findings if f.severity == "medium"),
        "low": sum(1 for f in validated_findings if f.severity == "low"),
    }

    if summary.critical != actual_severity_counts["critical"]:
        raise ValidationError(
            f"Summary critical count ({summary.critical}) does not match actual critical findings ({actual_severity_counts['critical']})"
        )
    if summary.high != actual_severity_counts["high"]:
        raise ValidationError(
            f"Summary high count ({summary.high}) does not match actual high findings ({actual_severity_counts['high']})"
        )
    if summary.medium != actual_severity_counts["medium"]:
        raise ValidationError(
            f"Summary medium count ({summary.medium}) does not match actual medium findings ({actual_severity_counts['medium']})"
        )
    if summary.low != actual_severity_counts["low"]:
        raise ValidationError(
            f"Summary low count ({summary.low}) does not match actual low findings ({actual_severity_counts['low']})"
        )

    return ScanReport(
        schema_version=schema_ver,
        summary=summary,
        findings=validated_findings,
        errors=validated_errors,
    )
