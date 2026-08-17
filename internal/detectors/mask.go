// internal/detectors/mask.go
package detectors

import "strings"

// MaskSecret returns a masked representation of a secret string to prevent leakage in outputs,
// reports, logs, errors, and traces. Strings of length 8 or fewer are fully masked with asterisks.
// Longer strings retain the first 4 and last 4 characters with the middle masked.
func MaskSecret(raw string) string {
	raw = strings.TrimSpace(raw)
	length := len(raw)
	if length == 0 {
		return ""
	}

	if length <= 8 {
		return strings.Repeat("*", 8)
	}

	maskedMiddle := strings.Repeat("*", length-8)
	return raw[:4] + maskedMiddle + raw[length-4:]
}
