// internal/admission/policy.go
package admission

import (
	"fmt"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/internal/detectors"
	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

type PolicyMode string

const (
	ModeEnforce PolicyMode = "enforce"
	ModeWarn    PolicyMode = "warn"
)

type PolicyConfig struct {
	Mode             PolicyMode
	MinimumSeverity  rules.Severity
	IgnoreNamespaces []string
}

type AdmissionDecision struct {
	Allowed     bool
	DenyMessage string
	Warnings    []string
}

// SeverityRank converts rules.Severity into an integer rank for comparison.
func SeverityRank(s rules.Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ParseSeverity parses a string representation into a rules.Severity with fallback to High.
func ParseSeverity(s string) rules.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return rules.SeverityCritical
	case "high":
		return rules.SeverityHigh
	case "medium":
		return rules.SeverityMedium
	case "low":
		return rules.SeverityLow
	default:
		return rules.SeverityHigh
	}
}

// Evaluate applies policy enforcement or warning generation on detected findings.
func Evaluate(findings []detectors.Finding, scanErrors []scanner.ScanError, req *AdmissionRequest, cfg PolicyConfig) AdmissionDecision {
	// 1. Check if the target namespace is in the ignore list
	if req != nil && req.Namespace != "" {
		for _, ignored := range cfg.IgnoreNamespaces {
			if strings.EqualFold(req.Namespace, strings.TrimSpace(ignored)) {
				return AdmissionDecision{
					Allowed:  true,
					Warnings: nil,
				}
			}
		}
	}

	// 2. Filter findings by minimum severity threshold
	minRank := SeverityRank(cfg.MinimumSeverity)
	var activeFindings []detectors.Finding
	for _, f := range findings {
		if SeverityRank(f.Severity) >= minRank {
			activeFindings = append(activeFindings, f)
		}
	}

	// 3. If no findings meet the minimum severity, allow the admission
	if len(activeFindings) == 0 {
		return AdmissionDecision{
			Allowed:  true,
			Warnings: nil,
		}
	}

	// 4. Generate sanitized warnings for all active findings
	var warnings []string
	for _, f := range activeFindings {
		warnings = append(warnings, fmt.Sprintf("potential credential detected by rule %s in field %s", f.RuleID, f.FieldPath))
	}

	// 5. Apply mode-specific decision
	if cfg.Mode == ModeWarn {
		return AdmissionDecision{
			Allowed:  true,
			Warnings: warnings,
		}
	}

	// Mode Enforce: Deny admission with sanitized summary message without exposing secrets or YAML
	firstFinding := activeFindings[0]
	denyMsg := fmt.Sprintf(
		"admission denied: potential credential detected by rule %s in field %s (resource: %s/%s)",
		firstFinding.RuleID,
		firstFinding.FieldPath,
		req.Kind.Kind,
		req.Name,
	)

	return AdmissionDecision{
		Allowed:     false,
		DenyMessage: denyMsg,
		Warnings:    warnings,
	}
}
