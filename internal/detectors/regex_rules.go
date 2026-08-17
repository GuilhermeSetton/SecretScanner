// internal/detectors/regex_rules.go
package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

var (
	awsAccessKeyRegex = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	awsSecretKeyRegex = regexp.MustCompile(`\b([0-9a-zA-Z/+]{40})\b`)
	awsContextRegex   = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|secret_access_key|aws_secret|aws_key)`)
	googleAPIKeyRegex = regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`)
	privateKeyRegex   = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)
)

// RegexDetector evaluates pre-compiled internal regex patterns and user-provided custom rules.
type RegexDetector struct {
	customRules []rules.Rule
}

// NewRegexDetector creates a new detector with optional custom rules.
func NewRegexDetector(customRules []rules.Rule) *RegexDetector {
	return &RegexDetector{
		customRules: customRules,
	}
}

func (d *RegexDetector) Detect(value string, scanContext ScanContext) []Match {
	var matches []Match

	// 1. AWS Access Key ID
	for _, loc := range awsAccessKeyRegex.FindAllStringIndex(value, -1) {
		matchedStr := value[loc[0]:loc[1]]
		matches = append(matches, Match{
			RuleID:      "internal.aws-access-key-id",
			Description: "AWS Access Key ID exposed",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			Value:       matchedStr,
			Offset:      loc[0],
		})
	}

	// 2. AWS Secret Access Key (strictly context-aware)
	hasAWSContext := isAWSContext(scanContext)
	if hasAWSContext {
		for _, loc := range awsSecretKeyRegex.FindAllStringIndex(value, -1) {
			matchedStr := value[loc[0]:loc[1]]
			// Ignore pure repetitive characters or padded zeros
			if isSuspiciousSecretKey(matchedStr) {
				matches = append(matches, Match{
					RuleID:      "internal.aws-secret-access-key",
					Description: "AWS Secret Access Key exposed in sensitive context",
					Severity:    rules.SeverityCritical,
					Confidence:  rules.ConfidenceHigh,
					Value:       matchedStr,
					Offset:      loc[0],
				})
			}
		}
	}

	// 3. Google API Key
	for _, loc := range googleAPIKeyRegex.FindAllStringIndex(value, -1) {
		matchedStr := value[loc[0]:loc[1]]
		matches = append(matches, Match{
			RuleID:      "internal.google-api-key",
			Description: "Google API Key exposed",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			Value:       matchedStr,
			Offset:      loc[0],
		})
	}

	// 4. Private Keys (SSH, RSA, PGP, etc.)
	if privateKeyRegex.MatchString(value) {
		loc := privateKeyRegex.FindStringIndex(value)
		matchedStr := value[loc[0]:loc[1]]
		matches = append(matches, Match{
			RuleID:      "internal.ssh-private-key",
			Description: "Private Key block exposed",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			Value:       matchedStr,
			Offset:      loc[0],
		})
	}

	// 5. Custom Rules
	for _, customRule := range d.customRules {
		for _, loc := range customRule.Pattern.FindAllStringIndex(value, -1) {
			matchedStr := value[loc[0]:loc[1]]
			matches = append(matches, Match{
				RuleID:      customRule.ID,
				Description: customRule.Description,
				Severity:    customRule.Severity,
				Confidence:  customRule.Confidence,
				Value:       matchedStr,
				Offset:      loc[0],
			})
		}
	}

	return matches
}

func isAWSContext(scanContext ScanContext) bool {
	if awsContextRegex.MatchString(scanContext.KeyName) || awsContextRegex.MatchString(scanContext.FieldPath) {
		return true
	}
	for _, nearbyKey := range scanContext.NearbyKeys {
		if awsContextRegex.MatchString(nearbyKey) || strings.EqualFold(nearbyKey, "AWS_ACCESS_KEY_ID") || strings.EqualFold(nearbyKey, "AWS_ACCESS_KEY") {
			return true
		}
	}
	return false
}

func isSuspiciousSecretKey(s string) bool {
	// Filter out strings made of only 1 or 2 distinct characters (e.g. "AAAAAAAAAAAAAAAAAAAA...")
	seen := make(map[rune]struct{}, len(s))
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen) > 8
}
