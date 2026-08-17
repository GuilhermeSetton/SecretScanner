// internal/detectors/k8s_env.go
package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

var (
	sensitiveEnvNameRegex = regexp.MustCompile(`(?i)(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH_TOKEN|DB_PASS|DATABASE_PASSWORD|ADMIN_PASS)`)
	k8sVariableRefRegex   = regexp.MustCompile(`^\$\([A-Za-z0-9_.-]+\)$`)
)

// K8sEnvDetector detects hardcoded sensitive credentials in Kubernetes environment variables.
type K8sEnvDetector struct{}

// NewK8sEnvDetector creates a detector for sensitive env values.
func NewK8sEnvDetector() *K8sEnvDetector {
	return &K8sEnvDetector{}
}

func (d *K8sEnvDetector) Detect(value string, scanContext ScanContext) []Match {
	var matches []Match

	// Only evaluate within container environment variable fields
	if !strings.Contains(scanContext.FieldPath, ".env[") && !strings.HasPrefix(scanContext.FieldPath, "env[") {
		return matches
	}

	trimmedVal := strings.TrimSpace(value)
	if trimmedVal == "" {
		return matches
	}

	// Skip standard Kubernetes variable references like $(POD_NAME) or $(DB_HOST)
	if k8sVariableRefRegex.MatchString(trimmedVal) {
		return matches
	}

	// Check if the variable name matches a sensitive credential keyword
	if sensitiveEnvNameRegex.MatchString(scanContext.KeyName) {
		matches = append(matches, Match{
			RuleID:      "internal.sensitive-env-var",
			Description: "Hardcoded sensitive credential in environment variable",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			Value:       trimmedVal,
			Offset:      0,
		})
	}

	return matches
}
