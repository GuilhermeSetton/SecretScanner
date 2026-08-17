// pkg/rules/rule_test.go
package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCustomRules_Valid(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "custom-rules.yaml")

	validYAML := `
rules:
  - id: "custom.internal-webhook"
    description: "Internal webhook URL"
    severity: "high"
    confidence: "high"
    pattern: "https://hooks\\.internal\\.corp/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9A-Za-z]{24}"
    secret_type: "internal-webhook"
  - id: "custom.internal-token"
    description: "Internal company auth token"
    severity: "critical"
    confidence: "medium"
    pattern: "corp_[0-9a-f]{32}"
`
	if err := os.WriteFile(rulesFile, []byte(validYAML), 0600); err != nil {
		t.Fatalf("failed to write test rules file: %v", err)
	}

	loadedRules, err := LoadCustomRules(rulesFile)
	if err != nil {
		t.Fatalf("expected valid rules to load, got error: %v", err)
	}

	if len(loadedRules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(loadedRules))
	}

	if loadedRules[0].ID != "custom.internal-webhook" {
		t.Errorf("expected id 'custom.internal-webhook', got %s", loadedRules[0].ID)
	}
	if loadedRules[0].Severity != SeverityHigh {
		t.Errorf("expected severity 'high', got %s", loadedRules[0].Severity)
	}
	if loadedRules[0].Confidence != ConfidenceHigh {
		t.Errorf("expected confidence 'high', got %s", loadedRules[0].Confidence)
	}
	if !loadedRules[0].Pattern.MatchString("https://hooks.internal.corp/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx") {
		t.Errorf("expected internal webhook pattern to match valid URL")
	}
}

func TestLoadCustomRules_ReservedInternalPrefix(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "invalid-prefix.yaml")

	invalidYAML := `
rules:
  - id: "internal.overridden-rule"
    description: "Attempt to override internal rule"
    severity: "critical"
    confidence: "high"
    pattern: "foo[0-9]+"
`
	if err := os.WriteFile(rulesFile, []byte(invalidYAML), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := LoadCustomRules(rulesFile)
	if err == nil {
		t.Fatalf("expected error when using reserved 'internal.' prefix, got nil")
	}
	if !strings.Contains(err.Error(), "reserved prefix") {
		t.Errorf("expected error to mention reserved prefix, got %v", err)
	}
}

func TestLoadCustomRules_DuplicateID(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "dup-id.yaml")

	dupYAML := `
rules:
  - id: "custom.token"
    description: "First token rule"
    severity: "high"
    confidence: "high"
    pattern: "token1_[0-9]+"
  - id: "custom.token"
    description: "Second token rule with duplicate id"
    severity: "low"
    confidence: "low"
    pattern: "token2_[0-9]+"
`
	if err := os.WriteFile(rulesFile, []byte(dupYAML), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := LoadCustomRules(rulesFile)
	if err == nil {
		t.Fatalf("expected error on duplicate rule id, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate rule id") {
		t.Errorf("expected error about duplicate rule id, got %v", err)
	}
}

func TestLoadCustomRules_InvalidRegex(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "invalid-regex.yaml")

	invalidRegexYAML := `
rules:
  - id: "custom.bad-regex"
    description: "Broken regex"
    severity: "medium"
    confidence: "low"
    pattern: "([a-z"
`
	if err := os.WriteFile(rulesFile, []byte(invalidRegexYAML), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := LoadCustomRules(rulesFile)
	if err == nil {
		t.Fatalf("expected error on invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "invalid regex pattern") {
		t.Errorf("expected error about invalid regex pattern, got %v", err)
	}
}

func TestLoadCustomRules_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "empty.yaml")

	if err := os.WriteFile(rulesFile, []byte("   \n"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := LoadCustomRules(rulesFile)
	if err == nil {
		t.Fatalf("expected error on empty rules file, got nil")
	}
}
