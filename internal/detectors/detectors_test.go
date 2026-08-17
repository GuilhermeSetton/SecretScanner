// internal/detectors/detectors_test.go
package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"Short 4 chars", "pass", "********"},
		{"Exact 8 chars", "12345678", "********"},
		{"AKIA 20 chars", "AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"40 chars secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJal********************************EKEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskSecret(tt.input)
			if got != tt.expected {
				t.Errorf("MaskSecret(%q) = %q, expected %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRegexDetector_AWSAccessKey(t *testing.T) {
	detector := NewRegexDetector(nil)
	scanCtx := ScanContext{
		File:      "deploy.yaml",
		FieldPath: "spec.template.spec.containers[0].env[0].value",
		Line:      10,
		Column:    15,
		KeyName:   "AWS_ACCESS_KEY_ID",
	}

	// Positive
	matches := detector.Detect("AKIAIOSFODNN7EXAMPLE", scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for AWS Access Key ID, got %d", len(matches))
	}
	if matches[0].RuleID != "internal.aws-access-key-id" {
		t.Errorf("expected rule id 'internal.aws-access-key-id', got %s", matches[0].RuleID)
	}

	finding := NewFinding(matches[0], scanCtx)
	if finding.Match == "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("finding.Match must be masked, got raw value")
	}
	if finding.Match != "AKIA************MPLE" {
		t.Errorf("expected masked match 'AKIA************MPLE', got %s", finding.Match)
	}

	// Negative (invalid prefix)
	negMatches := detector.Detect("BKIAIOSFODNN7EXAMPLE", scanCtx)
	if len(negMatches) != 0 {
		t.Errorf("expected 0 matches for invalid key, got %d", len(negMatches))
	}
}

func TestRegexDetector_AWSSecretKey_ContextAware(t *testing.T) {
	detector := NewRegexDetector(nil)

	valid40CharSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	positiveTests := []struct {
		name      string
		keyName   string
		fieldPath string
		nearby    []string
	}{
		{
			name:      "Uppercase AWS_SECRET_ACCESS_KEY",
			keyName:   "AWS_SECRET_ACCESS_KEY",
			fieldPath: "spec.template.spec.containers[0].env[1].value",
		},
		{
			name:      "Lowercase aws_secret_key",
			keyName:   "aws_secret_key",
			fieldPath: "data.aws_secret_key",
		},
		{
			name:      "secret_access_key in fieldpath",
			keyName:   "secret",
			fieldPath: "data.secret_access_key",
		},
		{
			name:      "aws_key in key name",
			keyName:   "aws_key",
			fieldPath: "spec.template.spec.containers[0].env[0].value",
		},
		{
			name:      "NearbyKey AWS_ACCESS_KEY_ID in same resource",
			keyName:   "secret_value",
			fieldPath: "spec.template.spec.containers[0].env[1].value",
			nearby:    []string{"AWS_ACCESS_KEY_ID"},
		},
	}

	for _, tt := range positiveTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ScanContext{
				File:       "deploy.yaml",
				FieldPath:  tt.fieldPath,
				KeyName:    tt.keyName,
				NearbyKeys: tt.nearby,
			}
			matches := detector.Detect(valid40CharSecret, ctx)
			if len(matches) != 1 {
				t.Fatalf("expected 1 match with AWS context for %s, got %d", tt.name, len(matches))
			}
			if matches[0].RuleID != "internal.aws-secret-access-key" {
				t.Errorf("expected rule id 'internal.aws-secret-access-key', got %s", matches[0].RuleID)
			}
		})
	}

	negativeTests := []struct {
		name      string
		keyName   string
		fieldPath string
		nearby    []string
		value     string
	}{
		{
			name:      "Commit SHA without AWS context",
			keyName:   "GIT_COMMIT_SHA",
			fieldPath: "spec.template.spec.containers[0].env[0].value",
			value:     "abcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:      "Container image name",
			keyName:   "image",
			fieldPath: "spec.template.spec.containers[0].image",
			value:     valid40CharSecret,
		},
		{
			name:      "Repetitive dummy string (isSuspiciousSecretKey rejection)",
			keyName:   "AWS_SECRET_ACCESS_KEY",
			fieldPath: "spec.template.spec.containers[0].env[1].value",
			value:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:      "Distant unrelated key in non-AWS context",
			keyName:   "APP_CHECKSUM",
			fieldPath: "data.checksum",
			nearby:    []string{"DATABASE_HOST", "PORT"},
			value:     valid40CharSecret,
		},
	}

	for _, tt := range negativeTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ScanContext{
				File:       "deploy.yaml",
				FieldPath:  tt.fieldPath,
				KeyName:    tt.keyName,
				NearbyKeys: tt.nearby,
			}
			matches := detector.Detect(tt.value, ctx)
			if len(matches) != 0 {
				t.Errorf("expected 0 matches for negative scenario %s, got %d", tt.name, len(matches))
			}
		})
	}
}

func TestRegexDetector_GoogleAPIKey(t *testing.T) {
	detector := NewRegexDetector(nil)
	scanCtx := ScanContext{
		File:    "config.yaml",
		KeyName: "GOOGLE_API_KEY",
	}

	validKey := "AIza" + "12345678901234567890123456789012345" // AIza + 35 chars = 39 total
	matches := detector.Detect(validKey, scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for Google API Key, got %d", len(matches))
	}
	if matches[0].RuleID != "internal.google-api-key" {
		t.Errorf("expected rule id 'internal.google-api-key', got %s", matches[0].RuleID)
	}
}

func TestRegexDetector_SSHPrivateKey(t *testing.T) {
	detector := NewRegexDetector(nil)
	scanCtx := ScanContext{
		File:    "secret.yaml",
		KeyName: "id_rsa",
	}

	privKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
	matches := detector.Detect(privKey, scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for Private Key, got %d", len(matches))
	}
	if matches[0].RuleID != "internal.ssh-private-key" {
		t.Errorf("expected rule id 'internal.ssh-private-key', got %s", matches[0].RuleID)
	}
}

func TestRegexDetector_CustomRules(t *testing.T) {
	customRule := rules.Rule{
		ID:          "custom.internal-token",
		Description: "Internal company token",
		Severity:    rules.SeverityHigh,
		Confidence:  rules.ConfidenceHigh,
		Pattern:     regexp.MustCompile(`corp_tok_[0-9a-f]{16}`),
		SecretType:  "corp-token",
	}
	detector := NewRegexDetector([]rules.Rule{customRule})
	scanCtx := ScanContext{File: "manifest.yaml"}

	matches := detector.Detect("token: corp_tok_0123456789abcdef", scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 custom rule match, got %d", len(matches))
	}
	if matches[0].RuleID != "custom.internal-token" {
		t.Errorf("expected rule id 'custom.internal-token', got %s", matches[0].RuleID)
	}
}

func TestJWTDetector(t *testing.T) {
	detector := NewJWTDetector()
	scanCtx := ScanContext{File: "auth.yaml"}

	// Valid JWT (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234567890","name":"John Doe"})
	headerJSON := `{"alg":"HS256","typ":"JWT"}`
	payloadJSON := `{"sub":"1234567890","name":"John Doe"}`
	validJWT := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payloadJSON)) + "." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	matches := detector.Detect("Bearer "+validJWT, scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for valid JWT, got %d", len(matches))
	}
	if matches[0].RuleID != "internal.jwt-token" {
		t.Errorf("expected rule id 'internal.jwt-token', got %s", matches[0].RuleID)
	}

	// Invalid JWT (not valid JSON payload)
	invalidJWT := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not a json payload")) + "." +
		"signature"
	invalidMatches := detector.Detect(invalidJWT, scanCtx)
	if len(invalidMatches) != 0 {
		t.Errorf("expected 0 matches for invalid JWT payload, got %d", len(invalidMatches))
	}
}

func TestEntropyDetector(t *testing.T) {
	detector := NewEntropyDetector(4.5)

	// Sensitive context + high entropy (32 distinct characters)
	sensCtx := ScanContext{
		File:    "secret.yaml",
		KeyName: "db_password",
	}
	highEntropySecret := "x9#K2$mP91!vL8@qZ3*wT7&bY5(cN0_uJ4" // 35 chars, high diversity
	matches := detector.Detect(highEntropySecret, sensCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for high entropy in sensitive context, got %d", len(matches))
	}

	// Non-sensitive context -> suppressed
	nonSensCtx := ScanContext{
		File:    "service.yaml",
		KeyName: "app_name",
	}
	noMatches := detector.Detect(highEntropySecret, nonSensCtx)
	if len(noMatches) != 0 {
		t.Errorf("expected 0 matches for high entropy in non-sensitive context, got %d", len(noMatches))
	}

	// UUID suppression in sensitive context
	uuidVal := "c56a4180-65aa-42ec-a945-5fd21dec0538"
	uuidMatches := detector.Detect(uuidVal, sensCtx)
	if len(uuidMatches) != 0 {
		t.Errorf("expected UUID to be suppressed from entropy detection, got %d matches", len(uuidMatches))
	}

	// Pure numeric suppression
	numVal := "12345678901234567890"
	numMatches := detector.Detect(numVal, sensCtx)
	if len(numMatches) != 0 {
		t.Errorf("expected numeric string to be suppressed, got %d matches", len(numMatches))
	}
}

func TestK8sEnvDetector(t *testing.T) {
	detector := NewK8sEnvDetector()

	// Sensitive env name with hardcoded value
	scanCtx := ScanContext{
		File:      "deploy.yaml",
		FieldPath: "spec.template.spec.containers[0].env[0].value",
		KeyName:   "DATABASE_PASSWORD",
	}
	matches := detector.Detect("mySuperSecret123", scanCtx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for sensitive env var, got %d", len(matches))
	}
	if matches[0].RuleID != "internal.sensitive-env-var" {
		t.Errorf("expected rule id 'internal.sensitive-env-var', got %s", matches[0].RuleID)
	}

	// Variable reference template $(DB_PASS) -> must be skipped
	refMatches := detector.Detect("$(EXTERNAL_PASS)", scanCtx)
	if len(refMatches) != 0 {
		t.Errorf("expected $(VAR) reference to be skipped, got %d matches", len(refMatches))
	}
}

func TestFindingZeroLeak(t *testing.T) {
	rawSecret := "AKIAIOSFODNN7EXAMPLE"
	match := Match{
		RuleID:      "internal.aws-access-key-id",
		Description: "AWS Key",
		Severity:    rules.SeverityCritical,
		Confidence:  rules.ConfidenceHigh,
		Value:       rawSecret,
	}
	scanCtx := ScanContext{File: "test.yaml", Line: 5, Column: 10}
	finding := NewFinding(match, scanCtx)

	if strings.Contains(finding.Match, "IOSFODNN7") {
		t.Fatalf("Finding.Match leaked middle characters: %s", finding.Match)
	}
}
