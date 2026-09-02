// internal/detectors/entropy_allowlist_test.go
package detectors

import (
	"strings"
	"testing"
)

const testEntropyThreshold = 4.5

func sensitiveEntropyContext() ScanContext {
	return ScanContext{
		File:      "secret.yaml",
		FieldPath: "data.credentials",
		KeyName:   "db_password",
	}
}

// Each suppressed case must be dense enough to fire without the allowlist,
// otherwise the test would pass for the wrong reason.
func assertWouldFireWithoutAllowlist(t *testing.T, name, value string) {
	t.Helper()
	for _, token := range extractTokens(value) {
		if len(token.text) < 16 {
			continue
		}
		if shouldSuppressEntropy(token.text) {
			continue
		}
		if CalculateShannonEntropy(token.text) >= testEntropyThreshold {
			return
		}
	}
	t.Fatalf("%s: no token reaches the entropy threshold, the case does not exercise the allowlist", name)
}

func TestEntropyDetector_SuppressesNonSecretShapes(t *testing.T) {
	detector := NewEntropyDetector(testEntropyThreshold)
	ctx := sensitiveEntropyContext()

	cases := []struct {
		name  string
		value string
	}{
		{
			name:  "ssh public key with algorithm prefix",
			value: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA8LMbbBHkzsLiOoBoDbTxRbAM4jTvOl8vHRPZ9OZzDsGrEGKrxWFOB3vGrMhkyJ4mE3EiOQ8bTvKxpDlWZfEQ deploy@ci",
		},
		{
			name:  "bare ssh public key blob",
			value: "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA8LMbbBHkzsLiOoBoDbTxRbAM4jTvOl8vHRPZ9OZzDsGrEGKrxWFOB3vGrMhkyJ4mE3EiOQ8bTvKxpDlWZfEQ",
		},
		{
			name: "PEM certificate block",
			value: "-----BEGIN CERTIFICATE-----\n" +
				"MIIDdzCCAl+gAwIBAgIEbGV0c0VuY3J5cHQwDQYJKoZIhvcNAQELBQAwTTELMAkG\n" +
				"A1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxJjAkBgNVBAMTHUxldCdz\n" +
				"-----END CERTIFICATE-----",
		},
		{
			name:  "base64-encoded certificate",
			value: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURkekNDQWwrZ0F3SUJBZ0lFYkdWMGMwVnU=",
		},
		{
			name:  "AWS Secrets Manager ARN",
			value: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
		},
		{
			name:  "GCP Secret Manager resource name",
			value: "projects/847362519204/secrets/payments-db-password/versions/17",
		},
		{
			name:  "token endpoint URL without credentials",
			value: "https://sts.googleapis.com/v1/token?audience=projects/123456789/locations/global",
		},
		{
			name:  "data URI payload",
			value: "data:application/octet-stream;base64,5+7nYV7zXzDkm0guFcrnUAcgHhJhew/tp+Fkd5b/AivqjtAqgqF1kw8jN803lMUiCABtaxrwwMvWJWWK",
		},
		{
			name:  "bcrypt password hash",
			value: "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		},
		{
			name:  "argon2id password hash",
			value: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertWouldFireWithoutAllowlist(t, tc.name, tc.value)

			matches := detector.Detect(tc.value, ctx)
			if len(matches) != 0 {
				t.Errorf("expected 0 entropy matches, got %d (first rule %q)", len(matches), matches[0].RuleID)
			}
		})
	}
}

func TestEntropyDetector_KeepsRealSecrets(t *testing.T) {
	detector := NewEntropyDetector(testEntropyThreshold)
	ctx := sensitiveEntropyContext()

	cases := []struct {
		name  string
		value string
	}{
		{
			name:  "random symbol-rich password",
			value: "x9#K2$mP91!vL8@qZ3*wT7&bY5(cN0_uJ4",
		},
		{
			name:  "random base62 token",
			value: "Zx9Kq2LmVn4PrTuWy7BcDf1GhJk3MnQs5TvXz8AbCe6DgHi0JlNo",
		},
		{
			name:  "URL embedding credentials in userinfo",
			value: "https://admin:S3cr3tP4ssw0rdXyz9@db.internal.example.com:5432/app",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.value, ctx)
			if len(matches) == 0 {
				t.Error("expected the entropy detector to report this value")
			}
		})
	}
}

// A bundle that mixes a public certificate with private key material must not
// be allowlisted just because the certificate comes first.
func TestEntropyDetector_PrivateKeyInBundleIsNotAllowlisted(t *testing.T) {
	detector := NewEntropyDetector(testEntropyThreshold)

	bundle := "-----BEGIN CERTIFICATE-----\n" +
		"MIIDdzCCAl+gAwIBAgIEbGV0c0VuY3J5cHQwDQYJKoZIhvcNAQELBQAwTTELMAkG\n" +
		"-----END CERTIFICATE-----\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA3Zx9Kq2LmVn4PrTuWy7BcDf1GhJk3MnQs5TvXz8AbCe6DgHi\n" +
		"-----END RSA PRIVATE KEY-----"

	if len(detector.Detect(bundle, sensitiveEntropyContext())) == 0 {
		t.Error("expected private key material in a certificate bundle to still be reported")
	}
}

func TestEntropyDetector_TemplateExpressionSuppressed(t *testing.T) {
	// A lower threshold is used because unresolved templates are not dense
	// enough to fire at the default 4.5 -- the suppression exists for users
	// who tune the threshold down.
	const loweredThreshold = 3.5
	detector := NewEntropyDetector(loweredThreshold)
	ctx := sensitiveEntropyContext()

	templated := "{{ .Values.postgresql.auth.existingSecretPasswordKey }}"
	if matches := detector.Detect(templated, ctx); len(matches) != 0 {
		t.Errorf("expected templated value to be suppressed, got %d matches", len(matches))
	}

	// Same shape without the template markers still fires at this threshold,
	// so the suppression above is what made the difference.
	resolved := strings.TrimSuffix(strings.TrimPrefix(templated, "{{ "), " }}")
	if matches := detector.Detect(resolved, ctx); len(matches) == 0 {
		t.Error("expected the resolved value to fire at the lowered threshold")
	}
}

func TestEntropyDetector_UserAllowlist(t *testing.T) {
	ctx := sensitiveEntropyContext()
	value := "Zx9Kq2LmVn4PrTuWy7BcDf1GhJk3MnQs5TvXz8AbCe6DgHi0JlNo"

	plain := NewEntropyDetector(testEntropyThreshold)
	if len(plain.Detect(value, ctx)) == 0 {
		t.Fatal("expected the value to fire without an allowlist")
	}

	allowlisted := NewEntropyDetectorWithAllowlist(testEntropyThreshold, []string{`^Zx9Kq2`})
	if matches := allowlisted.Detect(value, ctx); len(matches) != 0 {
		t.Errorf("expected the allowlist pattern to suppress the match, got %d", len(matches))
	}

	// Invalid patterns are dropped instead of panicking, and do not affect the rest.
	tolerant := NewEntropyDetectorWithAllowlist(testEntropyThreshold, []string{"[", "", `^Zx9Kq2`})
	if matches := tolerant.Detect(value, ctx); len(matches) != 0 {
		t.Errorf("expected valid patterns to still apply alongside invalid ones, got %d", len(matches))
	}
}
