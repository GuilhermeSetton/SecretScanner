// internal/report/report_test.go
package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/secretscanner/secretscanner-k8s/internal/detectors"
	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

func TestJSONFormatterRejectsUnsupportedSchemaVersion(t *testing.T) {
	formatter := &JSONFormatter{}
	report := &scanner.ScanReport{SchemaVersion: "2.0"}

	if err := formatter.Format(&bytes.Buffer{}, report); err == nil {
		t.Fatal("expected unsupported schema version to be rejected")
	}
}

func TestJSONSchemaVersionMatchesScanner(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test file")
	}

	schemaPath := filepath.Join(filepath.Dir(filename), "..", "..", "docs", "schema", "scan-result-v1.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	var document struct {
		Properties struct {
			SchemaVersion struct {
				Const string `json:"const"`
			} `json:"schema_version"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if document.Properties.SchemaVersion.Const != scanner.CurrentSchemaVersion {
		t.Fatalf("schema version = %q, scanner version = %q", document.Properties.SchemaVersion.Const, scanner.CurrentSchemaVersion)
	}
}

func sampleReport() *scanner.ScanReport {
	return &scanner.ScanReport{
		Summary: scanner.ScanSummary{
			FilesScanned: 2,
			Findings:     2,
			Errors:       1,
		},
		Findings: []detectors.Finding{
			{
				RuleID:      "internal.aws-access-key-id",
				Description: "AWS Access Key ID exposed",
				Severity:    rules.SeverityCritical,
				Confidence:  rules.ConfidenceHigh,
				File:        "deploy.yaml",
				Line:        14,
				Column:      10,
				FieldPath:   "spec.template.spec.containers[0].env[0].value",
				Resource:    "auth-deployment",
				Kind:        "Deployment",
				Match:       "AKIA************MPLE",
			},
			{
				RuleID:      "internal.google-api-key",
				Description: "Google API Key exposed",
				Severity:    rules.SeverityCritical,
				Confidence:  rules.ConfidenceHigh,
				File:        "secret.yaml",
				Line:        8,
				Column:      5,
				FieldPath:   "stringData.google_api_key",
				Resource:    "cloud-secret",
				Kind:        "Secret",
				Match:       "AIza************345",
			},
		},
		Errors: []scanner.ScanError{
			{
				File:    "broken.yaml",
				Message: "invalid YAML syntax in document 1: syntax error",
			},
		},
	}
}

func TestTextFormatter(t *testing.T) {
	rep := sampleReport()
	formatter := &TextFormatter{}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, rep); err != nil {
		t.Fatalf("TextFormatter failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "RULE ID") {
		t.Errorf("expected table header in text output, got:\n%s", out)
	}
	if !strings.Contains(out, "internal.aws-access-key-id") {
		t.Errorf("expected rule id in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Scan summary: 2 files scanned | 2 findings detected | 1 errors") {
		t.Errorf("expected summary line in output, got:\n%s", out)
	}
}

func TestJSONFormatter(t *testing.T) {
	rep := sampleReport()
	formatter := &JSONFormatter{}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, rep); err != nil {
		t.Fatalf("JSONFormatter failed: %v", err)
	}

	var parsed JSONReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if parsed.Summary.FilesScanned != 2 || parsed.Summary.Findings != 2 || parsed.Summary.Errors != 1 {
		t.Errorf("unexpected summary in parsed JSON: %+v", parsed.Summary)
	}

	if len(parsed.Findings) != 2 {
		t.Errorf("expected 2 findings in JSON, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Match != "AKIA************MPLE" {
		t.Errorf("expected masked match in JSON, got %s", parsed.Findings[0].Match)
	}
}

func TestSARIFFormatter(t *testing.T) {
	rep := sampleReport()
	formatter := &SARIFFormatter{}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, rep); err != nil {
		t.Fatalf("SARIFFormatter failed: %v", err)
	}

	var sarifDoc SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &sarifDoc); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	if sarifDoc.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifDoc.Version)
	}

	if len(sarifDoc.Runs) != 1 {
		t.Fatalf("expected 1 run in SARIF, got %d", len(sarifDoc.Runs))
	}

	run := sarifDoc.Runs[0]
	if run.Tool.Driver.Name != "SecretScanner-K8s" {
		t.Errorf("expected tool driver name 'SecretScanner-K8s', got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results in SARIF, got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "internal.aws-access-key-id" {
		t.Errorf("expected result ruleId 'internal.aws-access-key-id', got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level 'error' for critical severity, got %s", res.Level)
	}
	if len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.Region.StartLine != 14 {
		t.Errorf("unexpected location in SARIF: %+v", res.Locations)
	}
	if res.PartialFingerprints["primaryLocationLineHash"] == "" {
		t.Errorf("expected non-empty primaryLocationLineHash fingerprint")
	}
}

func TestAntiLeakInAllFormatters(t *testing.T) {
	rawCredentials := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AIza" + "SyD-1234567890abcdefghijklmnopqrst",
		"SuperSecretPassword123",
	}

	rep := sampleReport()
	formatters := []struct {
		name string
		fmt  Formatter
	}{
		{"Text", &TextFormatter{}},
		{"JSON", &JSONFormatter{}},
		{"SARIF", &SARIFFormatter{}},
	}

	for _, f := range formatters {
		t.Run(f.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := f.fmt.Format(&buf, rep); err != nil {
				t.Fatalf("formatter %s failed: %v", f.name, err)
			}

			outputStr := buf.String()
			for _, rawSecret := range rawCredentials {
				if strings.Contains(outputStr, rawSecret) {
					t.Fatalf("SECURITY VIOLATION: raw credential %q leaked in %s formatter output:\n%s", rawSecret, f.name, outputStr)
				}
			}
		})
	}
}

func TestJSONFormatter_SchemaCompatibility(t *testing.T) {
	rep := sampleReport()
	rep.Summary.Critical = 2
	rep.Summary.High = 0
	rep.Summary.Medium = 0
	rep.Summary.Low = 0
	rep.Summary.DurationMs = 15
	rep.Summary.ScannerVersion = "1.0.0"

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	if err := formatter.Format(&buf, rep); err != nil {
		t.Fatalf("JSONFormatter failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON into generic map: %v", err)
	}

	// 1. Verify schema_version
	if ver, ok := parsed["schema_version"].(string); !ok || ver != "1.0" {
		t.Errorf("expected schema_version '1.0', got %v", parsed["schema_version"])
	}

	// 2. Verify summary object and required fields
	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary object in JSON")
	}

	requiredSummaryKeys := []string{
		"files_scanned", "findings", "errors", "critical", "high", "medium", "low", "duration_ms", "scanner_version",
	}
	for _, key := range requiredSummaryKeys {
		if _, exists := summary[key]; !exists {
			t.Errorf("missing required summary key %q in JSON output", key)
		}
	}

	// 3. Verify findings array structure
	findings, ok := parsed["findings"].([]interface{})
	if !ok || len(findings) != 2 {
		t.Fatalf("expected 2 findings in array, got %v", parsed["findings"])
	}

	f1, ok := findings[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected finding to be a map")
	}
	requiredFindingKeys := []string{
		"rule_id", "description", "severity", "confidence", "file", "line", "column", "field_path", "match",
	}
	for _, key := range requiredFindingKeys {
		if _, exists := f1[key]; !exists {
			t.Errorf("missing required finding key %q in JSON output", key)
		}
	}

	// 4. Verify errors array structure
	errorsList, ok := parsed["errors"].([]interface{})
	if !ok || len(errorsList) != 1 {
		t.Fatalf("expected 1 error in array, got %v", parsed["errors"])
	}
	e1, ok := errorsList[0].(map[string]interface{})
	if !ok || e1["file"] == nil || e1["message"] == nil {
		t.Errorf("invalid error object structure: %v", errorsList[0])
	}
}

func TestJSONReport_ContractStability(t *testing.T) {
	// Verify that empty findings and errors serialize as empty arrays [] rather than null
	emptyReport := &scanner.ScanReport{
		SchemaVersion: "1.0",
		Summary: scanner.ScanSummary{
			FilesScanned:   1,
			Findings:       0,
			Errors:         0,
			ScannerVersion: "1.0.0",
		},
		Findings: nil,
		Errors:   nil,
	}

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	if err := formatter.Format(&buf, emptyReport); err != nil {
		t.Fatalf("failed to format empty report: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf("expected findings to be formatted as empty array [], got:\n%s", out)
	}
	if !strings.Contains(out, `"errors": []`) {
		t.Errorf("expected errors to be formatted as empty array [], got:\n%s", out)
	}
}
