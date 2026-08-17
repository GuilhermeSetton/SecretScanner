// internal/report/sarif.go
package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

// SARIFReport conforms to SARIF v2.1.0 specification for GitHub Security integration.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Results     []SARIFResult     `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	FullDescription      *SARIFMessage          `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFRuleConfiguration `json:"defaultConfiguration"`
	Properties           map[string]any         `json:"properties,omitempty"`
}

type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

type SARIFInvocation struct {
	ExecutionSuccessful       bool                `json:"executionSuccessful"`
	ToolExecutionNotification []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

type SARIFNotification struct {
	Message    SARIFMessage `json:"message"`
	Level      string       `json:"level"`
	Descriptor SARIFMessage `json:"descriptor"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// SARIFFormatter generates a SARIF v2.1.0 compliant JSON output.
type SARIFFormatter struct{}

func (f *SARIFFormatter) Format(w io.Writer, report *scanner.ScanReport) error {
	if report == nil {
		return fmt.Errorf("cannot format nil scan report")
	}

	rulesMap := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(report.Findings))

	for _, finding := range report.Findings {
		sarifLevel := mapSeverityToSARIFLevel(finding.Severity)

		if _, exists := rulesMap[finding.RuleID]; !exists {
			rulesMap[finding.RuleID] = SARIFRule{
				ID: finding.RuleID,
				ShortDescription: SARIFMessage{
					Text: finding.Description,
				},
				DefaultConfiguration: SARIFRuleConfiguration{
					Level: sarifLevel,
				},
			}
		}

		// Non-secret deterministic fingerprint
		fingerprintInput := fmt.Sprintf("%s:%s:%d:%d:%s",
			finding.RuleID, finding.File, finding.Line, finding.Column, finding.FieldPath)
		fingerprintHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fingerprintInput)))

		startLine := finding.Line
		if startLine <= 0 {
			startLine = 1
		}
		startCol := finding.Column
		if startCol <= 0 {
			startCol = 1
		}

		resultMessage := fmt.Sprintf("Potential secret detected by rule %s in field %s",
			finding.RuleID, finding.FieldPath)

		results = append(results, SARIFResult{
			RuleID: finding.RuleID,
			Level:  sarifLevel,
			Message: SARIFMessage{
				Text: resultMessage,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: finding.File,
						},
						Region: SARIFRegion{
							StartLine:   startLine,
							StartColumn: startCol,
						},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fingerprintHash,
			},
		})
	}

	ruleList := make([]SARIFRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		ruleList = append(ruleList, r)
	}

	var notifications []SARIFNotification
	for _, scanErr := range report.Errors {
		notifications = append(notifications, SARIFNotification{
			Message: SARIFMessage{
				Text: fmt.Sprintf("Scan warning in %s: %s", scanErr.File, scanErr.Message),
			},
			Level: "warning",
			Descriptor: SARIFMessage{
				Text: "ScanWarning",
			},
		})
	}

	sarifDoc := SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "SecretScanner-K8s",
						Version:        "1.0.0",
						InformationURI: "https://github.com/secretscanner/secretscanner-k8s",
						Rules:          ruleList,
					},
				},
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful:       report.Summary.Errors == 0,
						ToolExecutionNotification: notifications,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarifDoc); err != nil {
		return fmt.Errorf("failed to encode SARIF report: %w", err)
	}

	return nil
}

func mapSeverityToSARIFLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow:
		return "note"
	default:
		return "warning"
	}
}
