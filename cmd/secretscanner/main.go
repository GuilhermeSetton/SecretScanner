// cmd/secretscanner/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/secretscanner/secretscanner-k8s/internal/report"
	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

func main() {
	exitCode := run(os.Args[1:])
	os.Exit(exitCode)
}

func run(args []string) int {
	return runWithIO(args, os.Stdout, os.Stderr)
}

func runWithIO(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("secretscanner", flag.ContinueOnError)
	flags.SetOutput(stderr)

	targetDir := flags.String("dir", ".", "Target directory containing Kubernetes YAML manifests to scan")
	formatFlag := flags.String("format", "text", "Output format: text, json, or sarif")
	rulesFile := flags.String("rules", "", "Optional path to custom YAML rules definition file")
	workersFlag := flags.Int("workers", scanner.CalculateDefaultWorkers(), "Number of concurrent scanning workers (1-128)")
	entropyThreshold := flags.Float64("entropy-threshold", 4.5, "Shannon entropy threshold for sensitive context string detection")
	maxFileSize := flags.Int64("max-file-size", scanner.DefaultMaxFileSize, "Maximum file size in bytes to process")
	verbose := flags.Bool("verbose", false, "Enable verbose diagnostic logs on stderr")

	if err := flags.Parse(args); err != nil {
		return 2
	}

	formatter, err := report.NewFormatter(*formatFlag)
	if err != nil {
		fmt.Fprintf(stderr, "Configuration error: %v\n", err)
		return 2
	}

	var customRules []rules.Rule
	if *rulesFile != "" {
		loadedRules, err := rules.LoadCustomRules(*rulesFile)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load custom rules: %v\n", err)
			return 2
		}
		customRules = loadedRules
		if *verbose {
			fmt.Fprintf(stderr, "Loaded %d custom rule(s) from %s\n", len(customRules), *rulesFile)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(stderr, "\nScan cancelled by user signal")
		cancel()
	}()

	scannerOpts := scanner.ScannerOptions{
		TargetDir:        *targetDir,
		Workers:          *workersFlag,
		CustomRules:      customRules,
		EntropyThreshold: *entropyThreshold,
		MaxFileSize:      *maxFileSize,
		Verbose:          *verbose,
	}

	scn := scanner.NewScanner(scannerOpts)
	if *verbose {
		fmt.Fprintf(stderr, "Starting scan on %s with %d workers\n", *targetDir, scanner.ClampWorkers(*workersFlag))
	}

	scanReport, err := scn.Scan(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Fatal scan error: %v\n", err)
		return 2
	}

	// Print per-file recoverable errors to stderr
	if len(scanReport.Errors) > 0 {
		for _, scanErr := range scanReport.Errors {
			fmt.Fprintf(stderr, "Warning in %s: %s\n", scanErr.File, scanErr.Message)
		}
	}

	// Output structured report to stdout
	if err := formatter.Format(stdout, scanReport); err != nil {
		fmt.Fprintf(stderr, "Failed to format scan output: %v\n", err)
		return 2
	}

	// Exit Code Policy:
	// 2: Scan was incomplete due to errors (e.g. invalid YAML syntax in a file, invalid flags, missing directory)
	// 1: Scan was complete, but findings were detected
	// 0: Scan was complete with zero findings and zero errors
	if scanReport.Summary.Errors > 0 {
		return 2
	}
	if scanReport.Summary.Findings > 0 {
		return 1
	}
	return 0
}
