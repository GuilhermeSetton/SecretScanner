// internal/report/json.go
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/secretscanner/secretscanner-k8s/internal/detectors"
	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
)

// JSONReport represents the structured JSON output format.
type JSONReport struct {
	SchemaVersion string              `json:"schema_version"`
	Summary       scanner.ScanSummary `json:"summary"`
	Findings      []detectors.Finding `json:"findings"`
	Errors        []scanner.ScanError `json:"errors"`
}

// JSONFormatter outputs the scan report as formatted JSON to the writer.
type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, report *scanner.ScanReport) error {
	if report == nil {
		return fmt.Errorf("cannot format nil scan report")
	}

	schemaVersion := report.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = scanner.CurrentSchemaVersion
	}

	jsonOut := JSONReport{
		SchemaVersion: schemaVersion,
		Summary:       report.Summary,
		Findings:      report.Findings,
		Errors:        report.Errors,
	}

	if jsonOut.Findings == nil {
		jsonOut.Findings = []detectors.Finding{}
	}
	if jsonOut.Errors == nil {
		jsonOut.Errors = []scanner.ScanError{}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(jsonOut); err != nil {
		return fmt.Errorf("failed to encode JSON scan report: %w", err)
	}

	return nil
}
