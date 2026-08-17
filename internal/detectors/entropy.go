// internal/detectors/entropy.go
package detectors

import (
	"math"
	"regexp"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

var (
	uuidRegex          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexHashRegex       = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	pureNumericRegex   = regexp.MustCompile(`^[0-9]+$`)
	imagePatternRegex  = regexp.MustCompile(`(?i)(?:^|/)[a-z0-9._-]+(?:/[a-z0-9._-]+)*(?::[a-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
	k8sResourceIDRegex = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$`)
	sensitiveKeyRegex  = regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey|auth|credential|private_key|key|bearer)`)
)

// EntropyDetector evaluates high-entropy strings in sensitive contexts using Shannon entropy.
type EntropyDetector struct {
	threshold float64
}

// NewEntropyDetector creates a Shannon entropy detector with a configurable threshold.
func NewEntropyDetector(threshold float64) *EntropyDetector {
	if threshold <= 0 {
		threshold = 4.5
	}
	return &EntropyDetector{
		threshold: threshold,
	}
}

func (d *EntropyDetector) Detect(value string, scanContext ScanContext) []Match {
	var matches []Match

	// Entropy is only used as an auxiliary detector in sensitive contexts to prevent false positives
	if !isSensitiveContext(scanContext) {
		return matches
	}

	tokens := extractTokens(value)
	for _, token := range tokens {
		if len(token.text) < 16 {
			continue
		}

		if shouldSuppressEntropy(token.text) {
			continue
		}

		entropy := CalculateShannonEntropy(token.text)
		if entropy >= d.threshold {
			matches = append(matches, Match{
				RuleID:      "internal.shannon-entropy",
				Description: "High-entropy string detected in sensitive context",
				Severity:    rules.SeverityMedium,
				Confidence:  rules.ConfidenceMedium,
				Value:       token.text,
				Offset:      token.offset,
			})
		}
	}

	return matches
}

// CalculateShannonEntropy computes H(X) = -sum(p(x) * log2(p(x))) for a given string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}

	total := float64(len(s))
	var entropy float64

	for _, count := range freq {
		prob := float64(count) / total
		entropy -= prob * math.Log2(prob)
	}

	return entropy
}

type tokenInfo struct {
	text   string
	offset int
}

func extractTokens(s string) []tokenInfo {
	var tokens []tokenInfo
	var current strings.Builder
	startOffset := -1

	for i, r := range s {
		if r > ' ' && r != '"' && r != '\'' && r != '`' && r != ',' {
			if startOffset == -1 {
				startOffset = i
			}
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, tokenInfo{
					text:   current.String(),
					offset: startOffset,
				})
				current.Reset()
				startOffset = -1
			}
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, tokenInfo{
			text:   current.String(),
			offset: startOffset,
		})
	}

	return tokens
}

func isSensitiveContext(scanContext ScanContext) bool {
	if sensitiveKeyRegex.MatchString(scanContext.KeyName) || sensitiveKeyRegex.MatchString(scanContext.FieldPath) {
		return true
	}
	for _, nearbyKey := range scanContext.NearbyKeys {
		if sensitiveKeyRegex.MatchString(nearbyKey) {
			return true
		}
	}
	return false
}

func shouldSuppressEntropy(s string) bool {
	if pureNumericRegex.MatchString(s) {
		return true
	}
	if uuidRegex.MatchString(s) {
		return true
	}
	if hexHashRegex.MatchString(s) {
		return true
	}
	if imagePatternRegex.MatchString(s) {
		return true
	}
	if k8sResourceIDRegex.MatchString(s) && !strings.Contains(s, "_") {
		return true
	}
	return false
}
