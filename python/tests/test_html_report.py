import json
from report_generator.cli import run_cli
from report_generator.html_report import generate_html_report
from report_generator.models import Finding, ScanError, ScanReport, ScanSummary


def test_generate_html_report_content():
    summary = ScanSummary(
        files_scanned=2,
        findings=1,
        errors=0,
        critical=1,
        high=0,
        medium=0,
        low=0,
        duration_ms=10,
        scanner_version="1.0.0",
    )
    findings = [
        Finding(
            rule_id="internal.aws-access-key-id",
            description="AWS Access Key ID exposed",
            severity="critical",
            confidence="high",
            file="deploy.yaml",
            line=12,
            column=15,
            field_path="spec.template.spec.containers[0].env[0].value",
            match="AKIA************MPLE",
            resource="payment-processor",
            kind="Deployment",
        )
    ]
    report = ScanReport(schema_version="1.0", summary=summary, findings=findings, errors=[])
    html = generate_html_report(report)

    assert "<!DOCTYPE html>" in html
    assert "SecretScanner-K8s Report" in html
    assert "payment-processor" in html
    assert "AKIA************MPLE" in html
    assert "FINDINGS DETECTED" in html
    assert "v1.0" in html


def test_html_report_xss_escaping():
    summary = ScanSummary(
        files_scanned=1,
        findings=1,
        errors=1,
        critical=1,
        high=0,
        medium=0,
        low=0,
        duration_ms=10,
        scanner_version="1.0.0",
    )
    malicious_finding = Finding(
        rule_id="internal.test-xss",
        description="<script>alert('xss-desc')</script>",
        severity="critical",
        confidence="high",
        file="<img src=x onerror=alert('xss-file')>",
        line=1,
        column=1,
        field_path="<svg onload=alert('xss-path')>",
        match="<b>raw_secret</b>",
        resource="<script>alert('xss-res')</script>",
        kind="<iframe src='malicious.html'></iframe>",
    )
    malicious_error = ScanError(
        file="<script>alert('xss-err-file')</script>",
        message="<script>alert('xss-err-msg')</script>",
    )
    report = ScanReport(
        schema_version="1.0",
        summary=summary,
        findings=[malicious_finding],
        errors=[malicious_error],
    )

    html = generate_html_report(report)

    # The report ships one inline script of its own (progressive enhancement),
    # so "no <script> anywhere" is no longer the property to assert. What must
    # hold is that the data contributes no markup: exactly one script tag, the
    # template's, and every injected payload rendered as text.
    assert html.count("<script") == 1
    assert "<script>alert(" not in html
    assert "<img src=x" not in html
    assert "<svg onload=" not in html
    assert "<iframe" not in html
    assert "<b>raw_secret</b>" not in html

    # Ensure escaped HTML entities ARE present
    assert "&lt;script&gt;alert(&#39;xss-desc&#39;)&lt;/script&gt;" in html or "&lt;script&gt;" in html
    assert "&lt;img src=x" in html


def test_cli_html_generation(tmp_path):
    sample_json = {
        "schema_version": "1.0",
        "summary": {
            "files_scanned": 1,
            "findings": 0,
            "errors": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "duration_ms": 2,
            "scanner_version": "1.0.0",
        },
        "findings": [],
        "errors": [],
    }
    input_file = tmp_path / "scan.json"
    output_html = tmp_path / "report.html"
    input_file.write_text(json.dumps(sample_json), encoding="utf-8")

    code = run_cli(["--input", str(input_file), "--output", str(output_html), "--format", "html"])
    assert code == 0
    assert output_html.exists()
    content = output_html.read_text(encoding="utf-8")
    assert "PASSED" in content


def test_cli_json_summary_generation(tmp_path):
    sample_json = {
        "schema_version": "1.0",
        "summary": {
            "files_scanned": 1,
            "findings": 0,
            "errors": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "duration_ms": 2,
            "scanner_version": "1.0.0",
        },
        "findings": [],
        "errors": [],
    }
    input_file = tmp_path / "scan.json"
    output_json = tmp_path / "summary.json"
    input_file.write_text(json.dumps(sample_json), encoding="utf-8")

    code = run_cli(["--input", str(input_file), "--output", str(output_json), "--format", "json"])
    assert code == 0
    assert output_json.exists()
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert data["status"] == "PASSED"
    assert data["schema_version"] == "1.0"
