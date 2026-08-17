// internal/report/text.go
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
)

// TextFormatter writes the scan report as a clean tabular view to stdout using text/tabwriter.
type TextFormatter struct{}

func (f *TextFormatter) Format(w io.Writer, report *scanner.ScanReport) error {
	if report == nil {
		return fmt.Errorf("cannot format nil scan report")
	}

	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "No secrets detected across %d scanned files.\n", report.Summary.FilesScanned)
		if report.Summary.Errors > 0 {
			fmt.Fprintf(w, "Encountered %d scan errors (see stderr for details).\n", report.Summary.Errors)
		}
		return nil
	}

	tabWriter := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tabWriter, "SEVERITY\tCONFIDENCE\tRULE ID\tLOCATION\tRESOURCE\tFIELD PATH\tMATCH")

	for _, finding := range report.Findings {
		location := fmt.Sprintf("%s:%d:%d", finding.File, finding.Line, finding.Column)
		resource := finding.Resource
		if resource == "" {
			resource = "-"
		}
		fieldPath := finding.FieldPath
		if fieldPath == "" {
			fieldPath = "-"
		}

		fmt.Fprintf(tabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(finding.Severity)),
			strings.ToUpper(string(finding.Confidence)),
			finding.RuleID,
			location,
			resource,
			fieldPath,
			finding.Match,
		)
	}

	if err := tabWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush table output: %w", err)
	}

	fmt.Fprintf(w, "\nScan summary: %d files scanned | %d findings detected | %d errors\n",
		report.Summary.FilesScanned,
		report.Summary.Findings,
		report.Summary.Errors,
	)

	return nil
}
