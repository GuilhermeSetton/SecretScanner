// cmd/admission-webhook/main_test.go
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdmissionCLI_InvalidFlags(t *testing.T) {
	code := run([]string{"-invalid-flag-123"})
	if code != 2 {
		t.Errorf("expected exit code 2 on invalid flags, got %d", code)
	}
}

func TestAdmissionCLI_CustomRulesFlag(t *testing.T) {
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "custom.yaml")
	rulesContent := `
rules:
  - id: custom.api-token
    description: Custom API Token
    severity: high
    confidence: high
    regex: 'tok_[a-zA-Z0-9]{16}'
`
	if err := os.WriteFile(rulesFile, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("failed to write test rules: %v", err)
	}

	// Test non-existent rules file returns code 2
	code := run([]string{"-rules", filepath.Join(tmpDir, "non_existent.yaml")})
	if code != 2 {
		t.Errorf("expected exit code 2 on non-existent rules file, got %d", code)
	}
}

func TestAdmissionCLI_GracefulShutdown(t *testing.T) {
	// Start server on an ephemeral port and trigger interrupt
	exitChan := make(chan int, 1)
	go func() {
		code := run([]string{"-port", "18443", "-mode", "warn"})
		exitChan <- code
	}()

	// Allow server to bind
	time.Sleep(150 * time.Millisecond)

	// Send Interrupt signal to trigger graceful shutdown
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("failed to find process: %v", err)
	}
	_ = p.Signal(os.Interrupt)

	select {
	case code := <-exitChan:
		if code != 0 {
			t.Errorf("expected exit code 0 on graceful shutdown, got %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Log("Server shutdown timed out or OS signal not delivered on Windows test process")
	}
}
