import json
import os
import pytest

from report_generator.validation import (
    ValidationError,
    load_and_validate_file,
    validate_scan_report,
)


def valid_sample_payload():
    return {
        "schema_version": "1.0",
        "summary": {
            "files_scanned": 2,
            "findings": 1,
            "errors": 0,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "duration_ms": 12,
            "scanner_version": "1.0.0",
        },
        "findings": [
            {
                "rule_id": "internal.aws-access-key-id",
                "description": "AWS Access Key ID exposed",
                "severity": "critical",
                "confidence": "high",
                "file": "deployment.yaml",
                "line": 15,
                "column": 10,
                "field_path": "spec.template.spec.containers[0].env[0].value",
                "resource": "auth-svc",
                "kind": "Deployment",
                "match": "AKIA************MPLE",
            }
        ],
        "errors": [],
    }


def test_validate_valid_payload():
    payload = valid_sample_payload()
    report = validate_scan_report(payload)
    assert report.schema_version == "1.0"
    assert report.summary.findings == 1
    assert report.summary.critical == 1
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "internal.aws-access-key-id"


def test_reject_non_dict_root():
    with pytest.raises(ValidationError, match="Root JSON element must be an object"):
        validate_scan_report(["not", "a", "dict"])


def test_reject_missing_top_level_keys():
    payload = valid_sample_payload()
    del payload["schema_version"]
    with pytest.raises(ValidationError, match="Missing required top-level key"):
        validate_scan_report(payload)


def test_reject_invalid_schema_version():
    payload = valid_sample_payload()
    payload["schema_version"] = "invalid-version"
    with pytest.raises(ValidationError, match="Invalid schema_version"):
        validate_scan_report(payload)


def test_reject_missing_summary_keys():
    payload = valid_sample_payload()
    del payload["summary"]["critical"]
    with pytest.raises(ValidationError, match="Missing required summary key"):
        validate_scan_report(payload)


def test_reject_negative_summary_metrics():
    payload = valid_sample_payload()
    payload["summary"]["files_scanned"] = -1
    with pytest.raises(ValidationError, match="must be a non-negative integer"):
        validate_scan_report(payload)


def test_reject_invalid_severity_in_finding():
    payload = valid_sample_payload()
    payload["findings"][0]["severity"] = "ultra-critical"
    with pytest.raises(ValidationError, match="invalid severity"):
        validate_scan_report(payload)


def test_reject_invalid_line_number():
    payload = valid_sample_payload()
    payload["findings"][0]["line"] = 0
    with pytest.raises(ValidationError, match="line must be integer >= 1"):
        validate_scan_report(payload)


def test_reject_unexpected_root_keys():
    payload = valid_sample_payload()
    payload["unknown_root_prop"] = "disallowed"
    with pytest.raises(ValidationError, match="Unexpected additional top-level key"):
        validate_scan_report(payload)


def test_reject_unexpected_finding_keys():
    payload = valid_sample_payload()
    payload["findings"][0]["unsupported_extra_key"] = "disallowed"
    with pytest.raises(ValidationError, match="has unexpected key"):
        validate_scan_report(payload)


def test_reject_derived_findings_count_mismatch():
    payload = valid_sample_payload()
    payload["summary"]["findings"] = 99
    with pytest.raises(ValidationError, match="Summary findings count .* does not match actual findings count"):
        validate_scan_report(payload)


def test_reject_derived_severity_count_mismatch():
    payload = valid_sample_payload()
    payload["summary"]["critical"] = 0  # Actual finding is critical
    payload["summary"]["high"] = 1
    with pytest.raises(ValidationError, match="Summary critical count .* does not match actual critical findings"):
        validate_scan_report(payload)


def test_reject_derived_errors_count_mismatch():
    payload = valid_sample_payload()
    payload["summary"]["errors"] = 5
    with pytest.raises(ValidationError, match="Summary errors count .* does not match actual errors count"):
        validate_scan_report(payload)


def test_load_non_existent_file():
    with pytest.raises(ValidationError, match="Input file does not exist"):
        load_and_validate_file("does_not_exist_12345.json")


def test_load_invalid_json(tmp_path):
    broken_file = tmp_path / "broken.json"
    broken_file.write_text("{broken json syntax:", encoding="utf-8")
    with pytest.raises(ValidationError, match="Failed to parse input file as valid JSON"):
        load_and_validate_file(str(broken_file))
