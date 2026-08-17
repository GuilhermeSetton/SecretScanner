from report_generator.aggregation import aggregate_report
from report_generator.models import Finding, ScanError, ScanReport, ScanSummary


def build_test_report():
    summary = ScanSummary(
        files_scanned=3,
        findings=2,
        errors=1,
        critical=1,
        high=1,
        medium=0,
        low=0,
        duration_ms=25,
        scanner_version="1.0.0",
    )
    findings = [
        Finding(
            rule_id="internal.aws-access-key-id",
            description="AWS Access Key ID exposed",
            severity="critical",
            confidence="high",
            file="deploy.yaml",
            line=10,
            column=15,
            field_path="spec.template.spec.containers[0].env[0].value",
            match="AKIA************MPLE",
            resource="app-deploy",
            kind="Deployment",
        ),
        Finding(
            rule_id="internal.sensitive-env-var",
            description="Sensitive env variable",
            severity="high",
            confidence="high",
            file="deploy.yaml",
            line=14,
            column=15,
            field_path="spec.template.spec.containers[0].env[1].value",
            match="Secr*********2345",
            resource="app-deploy",
            kind="Deployment",
        ),
    ]
    errors = [
        ScanError(
            file="broken.yaml",
            message="invalid syntax",
        )
    ]
    return ScanReport(
        schema_version="1.0",
        summary=summary,
        findings=findings,
        errors=errors,
    )


def test_aggregate_report_metrics():
    report = build_test_report()
    agg = aggregate_report(report)

    assert agg["schema_version"] == "1.0"
    assert agg["status"] == "ERROR"  # Because errors > 0
    assert agg["summary"]["critical"] == 1
    assert agg["summary"]["high"] == 1
    assert agg["summary"]["medium"] == 0
    assert agg["summary"]["low"] == 0
    assert agg["affected_files_count"] == 1
    assert agg["affected_files"] == ["deploy.yaml"]


def test_aggregate_rule_distribution_and_remediation():
    report = build_test_report()
    agg = aggregate_report(report)

    rule_dist = agg["rule_distribution"]
    assert "internal.aws-access-key-id" in rule_dist
    assert rule_dist["internal.aws-access-key-id"]["count"] == 1
    assert "IAM Roles for Service Accounts" in rule_dist["internal.aws-access-key-id"]["remediation"]

    assert "internal.sensitive-env-var" in rule_dist
    assert "secretKeyRef" in rule_dist["internal.sensitive-env-var"]["remediation"]


def test_status_passed_on_clean_scan():
    clean_summary = ScanSummary(
        files_scanned=1,
        findings=0,
        errors=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        duration_ms=5,
        scanner_version="1.0.0",
    )
    report = ScanReport(schema_version="1.0", summary=clean_summary, findings=[], errors=[])
    agg = aggregate_report(report)
    assert agg["status"] == "PASSED"
