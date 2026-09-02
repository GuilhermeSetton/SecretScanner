// internal/scanner/scanner_test.go
package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanner_EndToEndScan(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Valid Deployment with hardcoded env credentials
	deployYAML := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-deployment
spec:
  template:
    spec:
      containers:
      - name: auth-svc
        image: auth-svc:1.0.0
        env:
        - name: DATABASE_PASSWORD
          value: "SuperSecretDbPassword123"
        - name: AWS_ACCESS_KEY_ID
          value: "AKIAIOSFODNN7EXAMPLE"
`
	// 2. Secret with base64 encoded data
	rawAWSSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	encodedAWSSecret := base64.StdEncoding.EncodeToString([]byte(rawAWSSecret))
	googleAPIKey := "AIza" + "12345678901234567890123456789012345"
	secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: cloud-secrets
type: Opaque
data:
  aws_secret_access_key: "%s"
stringData:
  google_api_key: "%s"
`, encodedAWSSecret, googleAPIKey)

	// 3. Clean service manifest (no secrets)
	cleanYAML := `
apiVersion: v1
kind: Service
metadata:
  name: web-service
spec:
  ports:
  - port: 80
    targetPort: 8080
`

	// 4. Invalid YAML file (recoverable error)
	invalidYAML := `
apiVersion: v1
kind: Broken
metadata:
  name: [broken syntax
`

	if err := os.WriteFile(filepath.Join(tempDir, "deploy.yaml"), []byte(deployYAML), 0600); err != nil {
		t.Fatalf("failed to write deploy.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "secret.yaml"), []byte(secretYAML), 0600); err != nil {
		t.Fatalf("failed to write secret.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "service.yaml"), []byte(cleanYAML), 0600); err != nil {
		t.Fatalf("failed to write service.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "invalid.yaml"), []byte(invalidYAML), 0600); err != nil {
		t.Fatalf("failed to write invalid.yaml: %v", err)
	}

	opts := ScannerOptions{
		TargetDir:        tempDir,
		Workers:          4,
		EntropyThreshold: 4.5,
	}
	scn := NewScanner(opts)

	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed with fatal error: %v", err)
	}

	if report.Summary.FilesScanned != 4 {
		t.Errorf("expected 4 files scanned, got %d", report.Summary.FilesScanned)
	}

	if report.Summary.Errors != 1 {
		t.Errorf("expected 1 recoverable error for invalid.yaml, got %d", report.Summary.Errors)
	}

	// We expect findings:
	// - deploy.yaml: DATABASE_PASSWORD (internal.sensitive-env-var)
	// - deploy.yaml: AKIAIOSFODNN7EXAMPLE (internal.aws-access-key-id)
	// - secret.yaml: aws_secret_access_key in data (internal.aws-secret-access-key)
	// - secret.yaml: google_api_key in stringData (internal.google-api-key)
	if report.Summary.Findings != 4 {
		t.Errorf("expected 4 findings, got %d", report.Summary.Findings)
		for _, f := range report.Findings {
			t.Logf("Found: %s in %s (%s)", f.RuleID, f.File, f.FieldPath)
		}
	}

	// Verify that all findings have masked matches
	for _, f := range report.Findings {
		if f.Match == "SuperSecretDbPassword123" || f.Match == "AKIAIOSFODNN7EXAMPLE" || f.Match == rawAWSSecret {
			t.Errorf("Finding for %s leaked raw secret in Match field: %s", f.RuleID, f.Match)
		}
	}
}

func TestScanner_DeterministicOrdering(t *testing.T) {
	tempDir := t.TempDir()

	googleAPIKey := "AIza" + "12345678901234567890123456789012345"
	for i := 0; i < 5; i++ {
		content := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: secret-%d
stringData:
  key: "%s"
`, i, googleAPIKey)
		if err := os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("file_%d.yaml", i)), []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
	}

	opts := ScannerOptions{
		TargetDir: tempDir,
		Workers:   8,
	}
	scn := NewScanner(opts)

	// Run multiple times and assert identical finding order
	report1, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("first scan failed: %v", err)
	}

	report2, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	if len(report1.Findings) != len(report2.Findings) {
		t.Fatalf("mismatched findings count between runs: %d vs %d", len(report1.Findings), len(report2.Findings))
	}

	for idx := range report1.Findings {
		f1 := report1.Findings[idx]
		f2 := report2.Findings[idx]
		if f1.File != f2.File || f1.Line != f2.Line || f1.Column != f2.Column || f1.RuleID != f2.RuleID {
			t.Errorf("non-deterministic ordering at index %d: %+v vs %+v", idx, f1, f2)
		}
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	// Create 20 files
	for i := 0; i < 20; i++ {
		content := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
		_ = os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("cm_%d.yaml", i)), []byte(content), 0600)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	opts := ScannerOptions{
		TargetDir: tempDir,
		Workers:   4,
	}
	scn := NewScanner(opts)

	_, err := scn.Scan(ctx)
	if err == nil {
		t.Errorf("expected context cancellation error, got nil")
	}
}

func TestScanner_BinarySecretIgnored(t *testing.T) {
	tempDir := t.TempDir()

	// Binary payload containing null byte
	binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}
	encodedBinary := base64.StdEncoding.EncodeToString(binaryData)

	secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: cert-secret
data:
  tls.crt: "%s"
`, encodedBinary)

	if err := os.WriteFile(filepath.Join(tempDir, "cert.yaml"), []byte(secretYAML), 0600); err != nil {
		t.Fatalf("failed to write cert.yaml: %v", err)
	}

	scn := NewScanner(ScannerOptions{TargetDir: tempDir})
	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for binary payload, got %d", len(report.Findings))
	}
	if len(report.Errors) != 0 {
		t.Errorf("expected 0 errors for binary payload, got %d", len(report.Errors))
	}
}

func TestScanner_WorkerBounds(t *testing.T) {
	if ClampWorkers(0) != MinWorkers {
		t.Errorf("expected min workers 1, got %d", ClampWorkers(0))
	}
	if ClampWorkers(200) != MaxWorkers {
		t.Errorf("expected max workers 128, got %d", ClampWorkers(200))
	}
}

func TestScanner_FileSizeLimit(t *testing.T) {
	tempDir := t.TempDir()

	// Create file exceeding 100 bytes limit
	bigContent := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + string(make([]byte, 200))
	if err := os.WriteFile(filepath.Join(tempDir, "big.yaml"), []byte(bigContent), 0600); err != nil {
		t.Fatalf("failed to write big file: %v", err)
	}

	scn := NewScanner(ScannerOptions{
		TargetDir:   tempDir,
		MaxFileSize: 100,
	})

	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Errors) != 1 {
		t.Errorf("expected 1 file size error, got %d", len(report.Errors))
	}
}

func TestScanner_MultiDocumentYAML(t *testing.T) {
	tempDir := t.TempDir()

	googleAPIKey1 := "AIza" + "12345678901234567890123456789012345"
	googleAPIKey2 := "AIza" + "98765432109876543210987654321098765"

	multiDocYAML := fmt.Sprintf(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  google_api_key: "%s"
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
data:
  aws_secret_access_key: "d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ=="
stringData:
  custom_token: "%s"
`, googleAPIKey1, googleAPIKey2)
	filePath := filepath.Join(tempDir, "multidoc.yaml")
	if err := os.WriteFile(filePath, []byte(multiDocYAML), 0600); err != nil {
		t.Fatalf("failed to write multidoc.yaml: %v", err)
	}

	scn := NewScanner(ScannerOptions{TargetDir: tempDir})
	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %d: %+v", len(report.Errors), report.Errors)
	}

	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings across multi-document YAML, got %d", len(report.Findings))
	}

	// Finding 1: ConfigMap data.google_api_key
	f1 := report.Findings[0]
	if f1.Kind != "ConfigMap" {
		t.Errorf("finding 1: expected Kind 'ConfigMap', got %s", f1.Kind)
	}
	if f1.Resource != "app-config" {
		t.Errorf("finding 1: expected Resource 'app-config', got %s", f1.Resource)
	}
	if f1.FieldPath != "data.google_api_key" {
		t.Errorf("finding 1: expected FieldPath 'data.google_api_key', got %s", f1.FieldPath)
	}
	if f1.Line != 7 {
		t.Errorf("finding 1: expected Line 7, got %d", f1.Line)
	}
	if f1.Column <= 0 {
		t.Errorf("finding 1: expected positive Column, got %d", f1.Column)
	}

	// Finding 2: Secret data.aws_secret_access_key
	f2 := report.Findings[1]
	if f2.Kind != "Secret" {
		t.Errorf("finding 2: expected Kind 'Secret', got %s", f2.Kind)
	}
	if f2.Resource != "app-secret" {
		t.Errorf("finding 2: expected Resource 'app-secret', got %s", f2.Resource)
	}
	if f2.FieldPath != "data.aws_secret_access_key" {
		t.Errorf("finding 2: expected FieldPath 'data.aws_secret_access_key', got %s", f2.FieldPath)
	}
	if f2.Line != 14 {
		t.Errorf("finding 2: expected Line 14, got %d", f2.Line)
	}

	// Finding 3: Secret stringData.custom_token
	f3 := report.Findings[2]
	if f3.Kind != "Secret" {
		t.Errorf("finding 3: expected Kind 'Secret', got %s", f3.Kind)
	}
	if f3.Resource != "app-secret" {
		t.Errorf("finding 3: expected Resource 'app-secret', got %s", f3.Resource)
	}
	if f3.FieldPath != "stringData.custom_token" {
		t.Errorf("finding 3: expected FieldPath 'stringData.custom_token', got %s", f3.FieldPath)
	}
	if f3.Line != 16 {
		t.Errorf("finding 3: expected Line 16, got %d", f3.Line)
	}
}

func TestScanner_SecretDataComprehensive(t *testing.T) {
	tempDir := t.TempDir()

	rawSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	encodedBase64 := base64.StdEncoding.EncodeToString([]byte(rawSecret))
	googleAPIKey := "AIza" + "12345678901234567890123456789012345"

	secretContent := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: test-secret-data
data:
  aws_secret_access_key: "%s"
  invalid_b64: "!!!not_valid_base64$$$"
  binary_null_byte: "AAAA/w=="
stringData:
  direct_str: "%s"
`, encodedBase64, googleAPIKey)

	if err := os.WriteFile(filepath.Join(tempDir, "secret.yaml"), []byte(secretContent), 0600); err != nil {
		t.Fatalf("failed to write secret.yaml: %v", err)
	}

	scn := NewScanner(ScannerOptions{TargetDir: tempDir})
	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// 1. Raw Base64 string must NOT appear in findings or matches
	for _, f := range report.Findings {
		if strings.Contains(f.Match, encodedBase64) {
			t.Errorf("raw Base64 string %s leaked in finding Match: %s", encodedBase64, f.Match)
		}
	}

	// 2. Raw decoded value must NOT appear in findings (only masked)
	for _, f := range report.Findings {
		if f.Match == rawSecret {
			t.Errorf("raw decoded secret %s leaked unmasked in finding Match", rawSecret)
		}
	}

	// 3. Binary payload containing null byte is ignored (no finding)
	for _, f := range report.Findings {
		if f.FieldPath == "data.binary_null_byte" {
			t.Errorf("expected binary null byte payload to be ignored, but generated finding: %+v", f)
		}
	}

	// 4. Invalid base64 generates sanitized error WITHOUT leaking the invalid payload
	if len(report.Errors) != 1 {
		t.Fatalf("expected exactly 1 error for invalid base64, got %d: %+v", len(report.Errors), report.Errors)
	}
	errMsg := report.Errors[0].Message
	if !strings.Contains(errMsg, "failed to decode Secret.data.invalid_b64: invalid base64 encoding") {
		t.Errorf("unexpected error message: %s", errMsg)
	}
	if strings.Contains(errMsg, "!!!not_valid_base64$$$") {
		t.Errorf("sanitized error leaked invalid base64 payload: %s", errMsg)
	}

	// 5. stringData is analyzed directly
	foundStringData := false
	for _, f := range report.Findings {
		if f.FieldPath == "stringData.direct_str" {
			foundStringData = true
			if f.Line != 10 {
				t.Errorf("expected stringData finding on line 10, got %d", f.Line)
			}
			if f.RuleID != "internal.google-api-key" {
				t.Errorf("expected rule 'internal.google-api-key', got %s", f.RuleID)
			}
		}
	}
	if !foundStringData {
		t.Errorf("expected finding for stringData.direct_str")
	}

	// 6. Location points to original scalar
	foundValidB64 := false
	for _, f := range report.Findings {
		if f.FieldPath == "data.aws_secret_access_key" {
			foundValidB64 = true
			if f.Line != 6 {
				t.Errorf("expected data.aws_secret_access_key on line 6, got %d", f.Line)
			}
		}
	}
	if !foundValidB64 {
		t.Errorf("expected finding for data.aws_secret_access_key")
	}
}

func TestScanner_DeduplicationHierarchy(t *testing.T) {
	tempDir := t.TempDir()

	// An env var AWS_SECRET_ACCESS_KEY with a valid high-entropy 40-char secret:
	// Isolated detectors would trigger:
	// 1. RegexDetector -> internal.aws-secret-access-key (Specific Pattern Rule)
	// 2. K8sEnvDetector -> internal.sensitive-env-var (Sensitive Env Var)
	// 3. EntropyDetector -> internal.shannon-entropy (Entropy)
	// Expected Result: Deduplication hierarchy keeps ONLY internal.aws-secret-access-key.
	manifestYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: dedup-test
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        - name: DATABASE_PASSWORD
          value: "x9#K2$mP91!vL8@qZ3*wT7&bY5(cN0_uJ4"
`
	if err := os.WriteFile(filepath.Join(tempDir, "dedup.yaml"), []byte(manifestYAML), 0600); err != nil {
		t.Fatalf("failed to write dedup.yaml: %v", err)
	}

	scn := NewScanner(ScannerOptions{
		TargetDir:        tempDir,
		EntropyThreshold: 4.0,
	})
	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %d: %+v", len(report.Errors), report.Errors)
	}

	// We expect exactly 2 findings:
	// 1. AWS_SECRET_ACCESS_KEY -> internal.aws-secret-access-key (suppressed sensitive-env-var and entropy)
	// 2. DATABASE_PASSWORD -> internal.sensitive-env-var (suppressed redundant entropy)
	if len(report.Findings) != 2 {
		t.Fatalf("expected exactly 2 deduplicated findings, got %d: %+v", len(report.Findings), report.Findings)
	}

	var awsRuleFound, envRuleFound, entropyFound bool
	for _, f := range report.Findings {
		if f.FieldPath == "spec.template.spec.containers[0].env[0].value" {
			if f.RuleID == "internal.aws-secret-access-key" {
				awsRuleFound = true
			} else {
				t.Errorf("unexpected rule for AWS_SECRET_ACCESS_KEY: %s", f.RuleID)
			}
		}
		if f.FieldPath == "spec.template.spec.containers[0].env[1].value" {
			if f.RuleID == "internal.sensitive-env-var" {
				envRuleFound = true
			} else {
				t.Errorf("unexpected rule for DATABASE_PASSWORD: %s", f.RuleID)
			}
		}
		if f.RuleID == "internal.shannon-entropy" {
			entropyFound = true
		}
	}

	if !awsRuleFound {
		t.Errorf("expected specific rule internal.aws-secret-access-key to prevail")
	}
	if !envRuleFound {
		t.Errorf("expected heuristic rule internal.sensitive-env-var to prevail over entropy")
	}
	if entropyFound {
		t.Errorf("redundant internal.shannon-entropy finding was not properly suppressed")
	}
}

func TestScanner_ScanDocuments_InMemory(t *testing.T) {
	scn := NewScanner(ScannerOptions{})

	googleAPIKey := "AIza" + "12345678901234567890123456789012345"
	yamlContent := []byte(fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: in-memory-deploy
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: GOOGLE_API_KEY
          value: "%s"
`, googleAPIKey))

	report, err := scn.ScanDocuments(context.Background(), "admission-review-object.yaml", yamlContent)
	if err != nil {
		t.Fatalf("ScanDocuments failed: %v", err)
	}

	if report.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("expected schema version %s, got %s", CurrentSchemaVersion, report.SchemaVersion)
	}

	if report.Summary.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned in summary, got %d", report.Summary.FilesScanned)
	}

	if report.Summary.Critical != 1 {
		t.Errorf("expected 1 critical finding in summary, got %d", report.Summary.Critical)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.RuleID != "internal.google-api-key" {
		t.Errorf("expected rule 'internal.google-api-key', got %s", f.RuleID)
	}
	if f.Resource != "in-memory-deploy" {
		t.Errorf("expected resource 'in-memory-deploy', got %s", f.Resource)
	}
	if f.Kind != "Deployment" {
		t.Errorf("expected kind 'Deployment', got %s", f.Kind)
	}
}

func TestScanner_VulnerableFixtureTemplate(t *testing.T) {
	tempDir := t.TempDir()

	tmplPath := filepath.Join("..", "..", "testdata", "vulnerable", "secret.yaml.tmpl")
	tmplBytes, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Fatalf("failed to read secret.yaml.tmpl: %v", err)
	}

	googleAPIKey := "AIza" + "12345678901234567890123456789012345"
	rendered := strings.ReplaceAll(string(tmplBytes), "__GOOGLE_API_KEY__", googleAPIKey)

	renderedPath := filepath.Join(tempDir, "secret.yaml")
	if err := os.WriteFile(renderedPath, []byte(rendered), 0600); err != nil {
		t.Fatalf("failed to write rendered secret.yaml: %v", err)
	}

	scn := NewScanner(ScannerOptions{TargetDir: tempDir})
	report, err := scn.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %d: %+v", len(report.Errors), report.Errors)
	}

	var foundGoogle, foundAWS bool
	for _, f := range report.Findings {
		if f.RuleID == "internal.google-api-key" {
			foundGoogle = true
			if f.FieldPath != "stringData.google_api_key" {
				t.Errorf("expected FieldPath 'stringData.google_api_key', got %s", f.FieldPath)
			}
			if f.Match == googleAPIKey {
				t.Errorf("finding leaked raw unmasked Google API Key: %s", f.Match)
			}
		}
		if f.RuleID == "internal.aws-secret-access-key" {
			foundAWS = true
		}
	}

	if !foundGoogle {
		t.Errorf("expected finding for internal.google-api-key in rendered fixture")
	}
	if !foundAWS {
		t.Errorf("expected finding for internal.aws-secret-access-key in rendered fixture")
	}
}

func TestScanner_EntropyAllowlistOption(t *testing.T) {
	tempDir := t.TempDir()

	manifest := `
apiVersion: v1
kind: Secret
metadata:
  name: allowlist-demo
stringData:
  db_password: "Zx9Kq2LmVn4PrTuWy7BcDf1GhJk3MnQs5TvXz8AbCe6DgHi0JlNo"
`
	if err := os.WriteFile(filepath.Join(tempDir, "secret.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	baseline := NewScanner(ScannerOptions{TargetDir: tempDir})
	baseReport, err := baseline.Scan(context.Background())
	if err != nil {
		t.Fatalf("baseline scan failed: %v", err)
	}
	if len(baseReport.Findings) == 0 {
		t.Fatal("expected the value to be reported without an allowlist")
	}

	allowlisted := NewScanner(ScannerOptions{
		TargetDir:        tempDir,
		EntropyAllowlist: []string{`^Zx9Kq2`},
	})
	allowReport, err := allowlisted.Scan(context.Background())
	if err != nil {
		t.Fatalf("allowlisted scan failed: %v", err)
	}
	if len(allowReport.Findings) != 0 {
		t.Errorf("expected the allowlist to suppress the finding, got %d", len(allowReport.Findings))
	}
}
