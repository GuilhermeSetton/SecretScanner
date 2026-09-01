// internal/scanner/scanner.go
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/secretscanner/secretscanner-k8s/internal/detectors"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

const (
	CurrentSchemaVersion = "1.0"
	ScannerVersion       = "0.1.0"
	DefaultMaxFileSize   = 5 * 1024 * 1024 // 5 MB
	MinWorkers           = 1
	MaxWorkers           = 128
)

type ScanError struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

type FileScanResult struct {
	File     string              `json:"file"`
	Findings []detectors.Finding `json:"findings"`
	Errors   []ScanError         `json:"errors"`
}

type ScanSummary struct {
	FilesScanned   int    `json:"files_scanned"`
	Findings       int    `json:"findings"`
	Errors         int    `json:"errors"`
	Critical       int    `json:"critical"`
	High           int    `json:"high"`
	Medium         int    `json:"medium"`
	Low            int    `json:"low"`
	DurationMs     int64  `json:"duration_ms"`
	ScannerVersion string `json:"scanner_version"`
}

type ScanReport struct {
	SchemaVersion string              `json:"schema_version"`
	Summary       ScanSummary         `json:"summary"`
	Findings      []detectors.Finding `json:"findings"`
	Errors        []ScanError         `json:"errors"`
}

type ScanRequest struct {
	Documents        []byte
	SourceName       string
	Workers          int
	EntropyThreshold float64
	RulesPath        string
}

type ScannerService interface {
	Scan(ctx context.Context) (*ScanReport, error)
	ScanDocuments(ctx context.Context, sourceName string, data []byte) (*ScanReport, error)
}

type ScannerOptions struct {
	TargetDir        string
	Workers          int
	CustomRules      []rules.Rule
	EntropyThreshold float64
	MaxFileSize      int64
	Verbose          bool
}

// CalculateDefaultWorkers returns a bounded worker count between 1 and 32.
func CalculateDefaultWorkers() int {
	w := runtime.NumCPU() * 2
	if w > 32 {
		w = 32
	}
	if w < 1 {
		w = 1
	}
	return w
}

// ClampWorkers clamps the worker count within [1, 128].
func ClampWorkers(w int) int {
	if w < MinWorkers {
		return MinWorkers
	}
	if w > MaxWorkers {
		return MaxWorkers
	}
	return w
}

// Scanner orchestrates directory traversal, AST parsing, and detector execution.
type Scanner struct {
	options      ScannerOptions
	detectorList []detectors.Detector
}

// NewScanner initializes a new Scanner instance with all standard detectors and custom rules.
func NewScanner(opts ScannerOptions) *Scanner {
	if opts.Workers <= 0 {
		opts.Workers = CalculateDefaultWorkers()
	} else {
		opts.Workers = ClampWorkers(opts.Workers)
	}

	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}

	if opts.EntropyThreshold <= 0 {
		opts.EntropyThreshold = 4.5
	}

	detectorList := []detectors.Detector{
		detectors.NewRegexDetector(opts.CustomRules),
		detectors.NewJWTDetector(),
		detectors.NewEntropyDetector(opts.EntropyThreshold),
		detectors.NewK8sEnvDetector(),
	}

	return &Scanner{
		options:      opts,
		detectorList: detectorList,
	}
}

// Scan traverses the target directory and scans all eligible YAML files concurrently.
func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error) {
	startTime := time.Now()
	fileInfo, err := os.Stat(s.options.TargetDir)
	if err != nil {
		return nil, fmt.Errorf("target directory %s inaccessible: %w", s.options.TargetDir, err)
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("target path %s is not a directory", s.options.TargetDir)
	}

	jobsChan := make(chan string, s.options.Workers*4)
	resultsChan := make(chan FileScanResult, s.options.Workers*4)

	var workerWg sync.WaitGroup

	// Start worker pool
	for i := 0; i < s.options.Workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case filePath, ok := <-jobsChan:
					if !ok {
						return
					}
					result := s.scanSingleFile(filePath)
					select {
					case <-ctx.Done():
						return
					case resultsChan <- result:
					}
				}
			}
		}()
	}

	// Traversal goroutine
	var walkErr error
	go func() {
		defer close(jobsChan)

		walkErr = filepath.WalkDir(s.options.TargetDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Ignore directories: .git, vendor, node_modules
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "vendor" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}

			// Ignore symlinks
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}

			// Only process .yaml and .yml files
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			if info.Size() > s.options.MaxFileSize {
				// Record file size limit warning
				resultsChan <- FileScanResult{
					File: filepath.ToSlash(path),
					Errors: []ScanError{
						{
							File:    filepath.ToSlash(path),
							Message: fmt.Sprintf("file size (%d bytes) exceeds maximum limit of %d bytes", info.Size(), s.options.MaxFileSize),
						},
					},
				}
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case jobsChan <- path:
			}

			return nil
		})
	}()

	// Wait for workers to complete in a separate goroutine and close results
	go func() {
		workerWg.Wait()
		close(resultsChan)
	}()

	// Collect all results
	var allFindings []detectors.Finding
	var allErrors []ScanError
	filesScanned := 0

	for res := range resultsChan {
		filesScanned++
		allFindings = append(allFindings, res.Findings...)
		allErrors = append(allErrors, res.Errors...)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if walkErr != nil {
		return nil, fmt.Errorf("directory traversal error: %w", walkErr)
	}

	// Deduplicate and sort findings deterministically
	deduplicatedFindings := deduplicateFindings(allFindings)
	sortFindings(deduplicatedFindings)

	// Sort errors deterministically
	sortErrors(allErrors)

	summary := calculateSummary(filesScanned, deduplicatedFindings, allErrors, time.Since(startTime))

	report := &ScanReport{
		SchemaVersion: CurrentSchemaVersion,
		Summary:       summary,
		Findings:      deduplicatedFindings,
		Errors:        allErrors,
	}

	return report, nil
}

// ScanDocuments processes raw YAML/JSON document bytes in memory (e.g. from Kubernetes AdmissionReview)
// without writing to disk or requiring file paths.
func (s *Scanner) ScanDocuments(ctx context.Context, sourceName string, data []byte) (*ScanReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	startTime := time.Now()
	findings, scanErrors := ParseAndScanYAML(sourceName, data, s.detectorList)

	deduplicatedFindings := deduplicateFindings(findings)
	sortFindings(deduplicatedFindings)
	sortErrors(scanErrors)

	summary := calculateSummary(1, deduplicatedFindings, scanErrors, time.Since(startTime))

	return &ScanReport{
		SchemaVersion: CurrentSchemaVersion,
		Summary:       summary,
		Findings:      deduplicatedFindings,
		Errors:        scanErrors,
	}, nil
}

func calculateSummary(filesScanned int, findings []detectors.Finding, errors []ScanError, duration time.Duration) ScanSummary {
	summary := ScanSummary{
		FilesScanned:   filesScanned,
		Findings:       len(findings),
		Errors:         len(errors),
		DurationMs:     duration.Milliseconds(),
		ScannerVersion: ScannerVersion,
	}

	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			summary.Critical++
		case rules.SeverityHigh:
			summary.High++
		case rules.SeverityMedium:
			summary.Medium++
		case rules.SeverityLow:
			summary.Low++
		}
	}

	return summary
}

func (s *Scanner) scanSingleFile(filePath string) FileScanResult {
	normalizedPath := filepath.ToSlash(filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return FileScanResult{
			File: normalizedPath,
			Errors: []ScanError{
				{
					File:    normalizedPath,
					Message: fmt.Sprintf("failed to read file: %v", err),
				},
			},
		}
	}

	findings, scanErrors := ParseAndScanYAML(normalizedPath, data, s.detectorList)
	return FileScanResult{
		File:     normalizedPath,
		Findings: findings,
		Errors:   scanErrors,
	}
}

func deduplicateFindings(findings []detectors.Finding) []detectors.Finding {
	// Rule Precedence Hierarchy:
	// 1. Specific Pattern Rules (e.g. AWS Secret Key, Google API Key, SSH Private Key, JWT, Custom Rules)
	// 2. Sensitive Environment Variable Heuristic (internal.sensitive-env-var)
	// 3. Shannon Entropy Detector (internal.shannon-entropy)
	specificMatches := make(map[string]bool)
	envMatches := make(map[string]bool)

	for _, f := range findings {
		locKey := fmt.Sprintf("%s:%d:%d:%s", f.File, f.Line, f.Column, f.FieldPath)
		if isSpecificPatternRule(f.RuleID) {
			specificMatches[locKey] = true
		} else if f.RuleID == "internal.sensitive-env-var" {
			envMatches[locKey] = true
		}
	}

	seen := make(map[string]bool, len(findings))
	var result []detectors.Finding

	for _, f := range findings {
		locKey := fmt.Sprintf("%s:%d:%d:%s", f.File, f.Line, f.Column, f.FieldPath)

		// 1. If a specific pattern rule matched, suppress both sensitive-env-var and shannon-entropy
		if (f.RuleID == "internal.shannon-entropy" || f.RuleID == "internal.sensitive-env-var") && specificMatches[locKey] {
			continue
		}

		// 2. If a sensitive-env-var matched (without specific rule), suppress redundant shannon-entropy
		if f.RuleID == "internal.shannon-entropy" && envMatches[locKey] {
			continue
		}

		exactKey := fmt.Sprintf("%s:%s", locKey, f.RuleID)
		if !seen[exactKey] {
			seen[exactKey] = true
			result = append(result, f)
		}
	}

	return result
}

func isSpecificPatternRule(ruleID string) bool {
	return ruleID != "internal.shannon-entropy" && ruleID != "internal.sensitive-env-var"
}

func sortFindings(findings []detectors.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].FieldPath < findings[j].FieldPath
	})
}

func sortErrors(errors []ScanError) {
	sort.Slice(errors, func(i, j int) bool {
		if errors[i].File != errors[j].File {
			return errors[i].File < errors[j].File
		}
		return errors[i].Message < errors[j].Message
	})
}
