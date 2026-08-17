// internal/detectors/jwt.go
package detectors

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

const (
	MaxJWTTokenLength   = 4096
	MaxJWTHeaderLength  = 1024
	MaxJWTPayloadLength = 2048
)

var jwtCandidateRegex = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b`)

// JWTDetector performs structural validation of candidate JSON Web Tokens.
type JWTDetector struct{}

// NewJWTDetector creates a new JWT structural validator detector.
func NewJWTDetector() *JWTDetector {
	return &JWTDetector{}
}

func (d *JWTDetector) Detect(value string, scanContext ScanContext) []Match {
	var matches []Match

	candidates := jwtCandidateRegex.FindAllStringIndex(value, -1)
	for _, loc := range candidates {
		candidate := value[loc[0]:loc[1]]

		if len(candidate) > MaxJWTTokenLength {
			continue
		}

		if isValidJWTStructure(candidate) {
			matches = append(matches, Match{
				RuleID:      "internal.jwt-token",
				Description: "JSON Web Token (JWT) exposed",
				Severity:    rules.SeverityCritical,
				Confidence:  rules.ConfidenceHigh,
				Value:       candidate,
				Offset:      loc[0],
			})
		}
	}

	return matches
}

func isValidJWTStructure(token string) bool {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return false
	}

	headerSegment := segments[0]
	payloadSegment := segments[1]
	signatureSegment := segments[2]

	if headerSegment == "" || payloadSegment == "" || signatureSegment == "" {
		return false
	}

	if len(headerSegment) > MaxJWTHeaderLength || len(payloadSegment) > MaxJWTPayloadLength {
		return false
	}

	headerBytes, err := decodeBase64URL(headerSegment)
	if err != nil {
		return false
	}

	payloadBytes, err := decodeBase64URL(payloadSegment)
	if err != nil {
		return false
	}

	// Validate that header is a valid JSON object
	trimmedHeader := strings.TrimSpace(string(headerBytes))
	if !strings.HasPrefix(trimmedHeader, "{") || !strings.HasSuffix(trimmedHeader, "}") {
		return false
	}
	var headerObj map[string]any
	if err := json.Unmarshal(headerBytes, &headerObj); err != nil {
		return false
	}

	// Validate that payload is a valid JSON object
	trimmedPayload := strings.TrimSpace(string(payloadBytes))
	if !strings.HasPrefix(trimmedPayload, "{") || !strings.HasSuffix(trimmedPayload, "}") {
		return false
	}
	var payloadObj map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadObj); err != nil {
		return false
	}

	return true
}

func decodeBase64URL(seg string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err == nil {
		return data, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}
