// internal/detectors/detector.go
package detectors

import (
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

// Finding represents a detected credential finding.
// The Match field is strictly guaranteed to contain only the masked value.
type Finding struct {
	RuleID      string           `json:"rule_id"`
	Description string           `json:"description"`
	Severity    rules.Severity   `json:"severity"`
	Confidence  rules.Confidence `json:"confidence"`
	File        string           `json:"file"`
	Line        int              `json:"line"`
	Column      int              `json:"column"`
	FieldPath   string           `json:"field_path"`
	Resource    string           `json:"resource,omitempty"`
	Kind        string           `json:"kind,omitempty"`
	Match       string           `json:"match"`
}

// ScanContext provides metadata about the YAML location and surrounding resource context.
type ScanContext struct {
	File       string
	Resource   string
	Kind       string
	FieldPath  string
	Line       int
	Column     int
	KeyName    string
	NearbyKeys []string
}

// Match represents a short-lived internal detection result before conversion to Finding.
type Match struct {
	RuleID      string
	Description string
	Severity    rules.Severity
	Confidence  rules.Confidence
	Value       string
	Offset      int
}

// Detector is the common interface implemented by all pattern and heuristic detectors.
type Detector interface {
	Detect(value string, scanContext ScanContext) []Match
}

// NewFinding converts an internal Match into a public Finding with the secret value masked.
func NewFinding(match Match, scanContext ScanContext) Finding {
	return Finding{
		RuleID:      match.RuleID,
		Description: match.Description,
		Severity:    match.Severity,
		Confidence:  match.Confidence,
		File:        scanContext.File,
		Line:        scanContext.Line,
		Column:      scanContext.Column,
		FieldPath:   scanContext.FieldPath,
		Resource:    scanContext.Resource,
		Kind:        scanContext.Kind,
		Match:       MaskSecret(match.Value),
	}
}
