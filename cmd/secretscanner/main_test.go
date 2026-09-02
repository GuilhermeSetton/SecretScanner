// cmd/secretscanner/main_test.go
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretscanner/secretscanner-k8s/internal/report"
)

func TestCLI_ExitCodes(t *testing.T) {
	tempDir := t.TempDir()

	cleanDir := filepath.Join(tempDir, "clean")
	vulnerableDir := filepath.Join(tempDir, "vulnerable")
	invalidDir := filepath.Join(tempDir, "invalid")

	_ = os.MkdirAll(cleanDir, 0755)
	_ = os.MkdirAll(vulnerableDir, 0755)
	_ = os.MkdirAll(invalidDir, 0755)

	// Clean manifest
	cleanYAML := `
apiVersion: v1
kind: Service
metadata:
  name: web-service
spec:
  ports:
  - port: 80
`
	_ = os.WriteFile(filepath.Join(cleanDir, "svc.yaml"), []byte(cleanYAML), 0600)

	// Vulnerable manifest
	vulnYAML := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-deploy
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: DATABASE_PASSWORD
          value: "SecretDbPass12345"
`
	_ = os.WriteFile(filepath.Join(vulnerableDir, "deploy.yaml"), []byte(vulnYAML), 0600)

	// Invalid YAML syntax manifest
	invalidYAML := `
apiVersion: v1
kind: Broken
metadata:
  name: [invalid syntax
`
	_ = os.WriteFile(filepath.Join(invalidDir, "broken.yaml"), []byte(invalidYAML), 0600)

	tests := []struct {
		name         string
		args         []string
		expectedCode int
	}{
		{
			name:         "Clean scan returns 0",
			args:         []string{"-dir", cleanDir, "-format", "text"},
			expectedCode: 0,
		},
		{
			name:         "Findings scan returns 1",
			args:         []string{"-dir", vulnerableDir, "-format", "json"},
			expectedCode: 1,
		},
		{
			name:         "Scan with syntax error returns 2",
			args:         []string{"-dir", invalidDir, "-format", "text"},
			expectedCode: 2,
		},
		{
			name:         "Invalid format flag returns 2",
			args:         []string{"-dir", cleanDir, "-format", "invalid_format"},
			expectedCode: 2,
		},
		{
			name:         "Non-existent directory returns 2",
			args:         []string{"-dir", filepath.Join(tempDir, "does_not_exist")},
			expectedCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdoutBuf, stderrBuf bytes.Buffer
			code := runWithIO(tt.args, &stdoutBuf, &stderrBuf)
			if code != tt.expectedCode {
				t.Errorf("run(%v) = %d, expected exit code %d (stderr: %s)", tt.args, code, tt.expectedCode, stderrBuf.String())
			}
		})
	}
}

func TestCLI_CustomRulesFlag(t *testing.T) {
	tempDir := t.TempDir()

	manifestDir := filepath.Join(tempDir, "manifests")
	_ = os.MkdirAll(manifestDir, 0755)

	manifestYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  token: "custom_corp_tok_1234567890abcdef"
`
	_ = os.WriteFile(filepath.Join(manifestDir, "cm.yaml"), []byte(manifestYAML), 0600)

	rulesFile := filepath.Join(tempDir, "rules.yaml")
	rulesYAML := `
rules:
  - id: "custom.corp-token"
    description: "Corporate Token"
    severity: "high"
    confidence: "high"
    pattern: "custom_corp_tok_[0-9a-f]{16}"
`
	_ = os.WriteFile(rulesFile, []byte(rulesYAML), 0600)

	var stdoutBuf, stderrBuf bytes.Buffer
	code := runWithIO([]string{"-dir", manifestDir, "-rules", rulesFile, "-format", "sarif"}, &stdoutBuf, &stderrBuf)
	if code != 1 {
		t.Errorf("expected exit code 1 when custom rule matches, got %d", code)
	}

	// Invalid rules file should return 2
	badRulesFile := filepath.Join(tempDir, "bad-rules.yaml")
	_ = os.WriteFile(badRulesFile, []byte("rules: [{id: 'internal.bad'}]"), 0600)
	var badStdoutBuf, badStderrBuf bytes.Buffer
	badCode := runWithIO([]string{"-dir", manifestDir, "-rules", badRulesFile}, &badStdoutBuf, &badStderrBuf)
	if badCode != 2 {
		t.Errorf("expected exit code 2 on invalid custom rules, got %d", badCode)
	}
}

func TestCLI_StreamsAndVerboseIsolation(t *testing.T) {
	tempDir := t.TempDir()

	vulnYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-deploy
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: AWS_SECRET_ACCESS_KEY
          value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	_ = os.WriteFile(filepath.Join(tempDir, "deploy.yaml"), []byte(vulnYAML), 0600)

	// Test 1: JSON format with -verbose flag
	t.Run("JSON format with verbose flag preserves clean stdout", func(t *testing.T) {
		var stdoutBuf, stderrBuf bytes.Buffer
		code := runWithIO([]string{"-dir", tempDir, "-format", "json", "-verbose"}, &stdoutBuf, &stderrBuf)

		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}

		stderrStr := stderrBuf.String()
		if !strings.Contains(stderrStr, "Starting scan") {
			t.Errorf("expected verbose log in stderr, got: %s", stderrStr)
		}

		stdoutStr := stdoutBuf.String()
		if strings.Contains(stdoutStr, "Starting scan") {
			t.Errorf("stderr verbose log contaminated stdout:\n%s", stdoutStr)
		}

		// Ensure stdout is 100% valid JSON without contamination
		var jsonRep report.JSONReport
		if err := json.Unmarshal(stdoutBuf.Bytes(), &jsonRep); err != nil {
			t.Fatalf("stdout failed to parse as valid JSON: %v\nOutput was:\n%s", err, stdoutStr)
		}

		if jsonRep.Summary.Findings != 1 {
			t.Errorf("expected 1 finding in parsed JSON, got %d", jsonRep.Summary.Findings)
		}
	})

	// Test 2: SARIF format with -verbose flag
	t.Run("SARIF format with verbose flag preserves clean stdout", func(t *testing.T) {
		var stdoutBuf, stderrBuf bytes.Buffer
		code := runWithIO([]string{"-dir", tempDir, "-format", "sarif", "-verbose"}, &stdoutBuf, &stderrBuf)

		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}

		stderrStr := stderrBuf.String()
		if !strings.Contains(stderrStr, "Starting scan") {
			t.Errorf("expected verbose log in stderr, got: %s", stderrStr)
		}

		stdoutStr := stdoutBuf.String()
		if strings.Contains(stdoutStr, "Starting scan") {
			t.Errorf("stderr verbose log contaminated stdout:\n%s", stdoutStr)
		}

		var sarifRep report.SARIFReport
		if err := json.Unmarshal(stdoutBuf.Bytes(), &sarifRep); err != nil {
			t.Fatalf("stdout failed to parse as valid SARIF JSON: %v\nOutput was:\n%s", err, stdoutStr)
		}

		if len(sarifRep.Runs) != 1 || len(sarifRep.Runs[0].Results) != 1 {
			t.Errorf("expected 1 result in SARIF run, got %+v", sarifRep.Runs)
		}
	})
}

func TestCLI_ValidJSONWithFileErrors(t *testing.T) {
	tempDir := t.TempDir()

	brokenYAML := `apiVersion: v1
kind: Broken
metadata:
  name: [broken syntax
`
	_ = os.WriteFile(filepath.Join(tempDir, "broken.yaml"), []byte(brokenYAML), 0600)

	var stdoutBuf, stderrBuf bytes.Buffer
	code := runWithIO([]string{"-dir", tempDir, "-format", "json"}, &stdoutBuf, &stderrBuf)

	// Exit code 2 because scan was incomplete due to file syntax error
	if code != 2 {
		t.Errorf("expected exit code 2 on syntax error, got %d", code)
	}

	stderrStr := stderrBuf.String()
	if !strings.Contains(stderrStr, "Warning in") {
		t.Errorf("expected warning in stderr, got: %s", stderrStr)
	}

	stdoutStr := stdoutBuf.String()
	var jsonRep report.JSONReport
	if err := json.Unmarshal(stdoutBuf.Bytes(), &jsonRep); err != nil {
		t.Fatalf("stdout must remain valid JSON even when file errors occur: %v\nStdout: %s", err, stdoutStr)
	}

	if jsonRep.Summary.Errors != 1 {
		t.Errorf("expected summary.errors == 1 in JSON, got %d", jsonRep.Summary.Errors)
	}
	if len(jsonRep.Errors) != 1 {
		t.Errorf("expected 1 error entry in JSON errors list, got %d", len(jsonRep.Errors))
	}
}

func TestCLI_EntropyAllowFlag(t *testing.T) {
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

	findingsFor := func(t *testing.T, args []string) float64 {
		t.Helper()
		var stdout, stderr bytes.Buffer
		runWithIO(args, &stdout, &stderr)

		var parsed map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON report: %v (stderr: %s)", err, stderr.String())
		}
		summary, ok := parsed["summary"].(map[string]any)
		if !ok {
			t.Fatal("report has no summary object")
		}
		count, ok := summary["findings"].(float64)
		if !ok {
			t.Fatal("summary has no findings count")
		}
		return count
	}

	baseArgs := []string{"-dir", tempDir, "-format", "json"}
	if got := findingsFor(t, baseArgs); got == 0 {
		t.Fatal("expected the value to be reported without -entropy-allow")
	}

	allowArgs := append(append([]string{}, baseArgs...), "-entropy-allow", `^Zx9Kq2`)
	if got := findingsFor(t, allowArgs); got != 0 {
		t.Errorf("expected -entropy-allow to suppress the finding, got %v", got)
	}

	// An unusable pattern is a configuration error, not a silently ignored flag.
	var stdout, stderr bytes.Buffer
	code := runWithIO([]string{"-dir", tempDir, "-entropy-allow", "["}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for an invalid pattern, got %d", code)
	}
	if !strings.Contains(stderr.String(), "entropy-allow") {
		t.Errorf("expected the error message to name the flag, got %q", stderr.String())
	}
}
