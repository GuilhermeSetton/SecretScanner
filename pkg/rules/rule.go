// pkg/rules/rule.go
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

func (c Confidence) IsValid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}

type RuleConfig struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Confidence  string `yaml:"confidence"`
	Pattern     string `yaml:"pattern"`
	SecretType  string `yaml:"secret_type"`
}

type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Confidence  Confidence
	Pattern     *regexp.Regexp
	SecretType  string
}

const (
	MaxPatternLength = 1024
	MaxRulesCount    = 500
	InternalPrefix   = "internal."
)

type CustomRulesFile struct {
	Rules []RuleConfig `yaml:"rules"`
}

// LoadCustomRules reads a YAML file with custom rule definitions, validates constraints,
// and returns the compiled rules. Rejects duplicate IDs, malformed regexes, and reserved internal prefixes.
func LoadCustomRules(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom rules file %s: %w", filePath, err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("custom rules file %s is empty", filePath)
	}

	var fileContent CustomRulesFile
	if err := yaml.Unmarshal(data, &fileContent); err != nil {
		return nil, fmt.Errorf("failed to parse custom rules YAML %s: %w", filePath, err)
	}

	if len(fileContent.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in custom rules file %s", filePath)
	}

	if len(fileContent.Rules) > MaxRulesCount {
		return nil, fmt.Errorf("custom rules file %s exceeds maximum allowed rules count of %d (found %d)", filePath, MaxRulesCount, len(fileContent.Rules))
	}

	seenIDs := make(map[string]struct{}, len(fileContent.Rules))
	seenPatterns := make(map[string]struct{}, len(fileContent.Rules))
	compiledRules := make([]Rule, 0, len(fileContent.Rules))

	for index, ruleConfig := range fileContent.Rules {
		ruleID := strings.TrimSpace(ruleConfig.ID)
		if ruleID == "" {
			return nil, fmt.Errorf("rule at index %d has empty id", index)
		}

		if strings.HasPrefix(ruleID, InternalPrefix) {
			return nil, fmt.Errorf("rule %q uses reserved prefix %q", ruleID, InternalPrefix)
		}

		if _, exists := seenIDs[ruleID]; exists {
			return nil, fmt.Errorf("duplicate rule id %q detected", ruleID)
		}
		seenIDs[ruleID] = struct{}{}

		description := strings.TrimSpace(ruleConfig.Description)
		if description == "" {
			return nil, fmt.Errorf("rule %q has empty description", ruleID)
		}

		severity := Severity(strings.ToLower(strings.TrimSpace(ruleConfig.Severity)))
		if !severity.IsValid() {
			return nil, fmt.Errorf("rule %q has invalid severity %q (must be critical, high, medium, or low)", ruleID, ruleConfig.Severity)
		}

		confidence := Confidence(strings.ToLower(strings.TrimSpace(ruleConfig.Confidence)))
		if !confidence.IsValid() {
			return nil, fmt.Errorf("rule %q has invalid confidence %q (must be high, medium, or low)", ruleID, ruleConfig.Confidence)
		}

		patternStr := strings.TrimSpace(ruleConfig.Pattern)
		if patternStr == "" {
			return nil, fmt.Errorf("rule %q has empty pattern", ruleID)
		}

		if len(patternStr) > MaxPatternLength {
			return nil, fmt.Errorf("rule %q pattern length exceeds %d characters", ruleID, MaxPatternLength)
		}

		if _, exists := seenPatterns[patternStr]; exists {
			return nil, fmt.Errorf("duplicate pattern detected in rule %q", ruleID)
		}
		seenPatterns[patternStr] = struct{}{}

		compiledPattern, err := regexp.Compile(patternStr)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid regex pattern %q: %w", ruleID, patternStr, err)
		}

		secretType := strings.TrimSpace(ruleConfig.SecretType)
		if secretType == "" {
			secretType = "custom-secret"
		}

		compiledRules = append(compiledRules, Rule{
			ID:          ruleID,
			Description: description,
			Severity:    severity,
			Confidence:  confidence,
			Pattern:     compiledPattern,
			SecretType:  secretType,
		})
	}

	return compiledRules, nil
}
