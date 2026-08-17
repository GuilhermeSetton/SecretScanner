// internal/report/formatter.go
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
)

// Formatter formats and outputs the scan report to a writer.
type Formatter interface {
	Format(w io.Writer, report *scanner.ScanReport) error
}

// NewFormatter creates a Formatter for the given format string (text, json, sarif).
func NewFormatter(format string) (Formatter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text", "":
		return &TextFormatter{}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "sarif":
		return &SARIFFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q (supported formats: text, json, sarif)", format)
	}
}
