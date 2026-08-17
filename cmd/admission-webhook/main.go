// cmd/admission-webhook/main.go
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/secretscanner/secretscanner-k8s/internal/admission"
	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

func main() {
	exitCode := run(os.Args[1:])
	os.Exit(exitCode)
}

func run(args []string) int {
	flags := flag.NewFlagSet("admission-webhook", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	port := flags.Int("port", 8443, "HTTPS port to listen on for admission reviews")
	tlsCert := flags.String("tls-cert", "", "Path to TLS certificate PEM file")
	tlsKey := flags.String("tls-key", "", "Path to TLS private key PEM file")
	modeFlag := flags.String("mode", "enforce", "Admission evaluation mode: 'enforce' (deny) or 'warn' (allow with warning)")
	minSeverityFlag := flags.String("min-severity", "high", "Minimum severity threshold (critical, high, medium, low)")
	ignoreNamespacesFlag := flags.String("ignore-namespaces", "kube-system,monitoring", "Comma-separated list of namespaces to ignore")
	rulesFile := flags.String("rules", "", "Optional path to custom YAML rules definition file")

	if err := flags.Parse(args); err != nil {
		return 2
	}

	var customRules []rules.Rule
	if *rulesFile != "" {
		loadedRules, err := rules.LoadCustomRules(*rulesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load custom rules from %s: %v\n", *rulesFile, err)
			return 2
		}
		customRules = loadedRules
	}

	ignoredNamespaces := strings.Split(*ignoreNamespacesFlag, ",")
	policyCfg := admission.PolicyConfig{
		Mode:             admission.PolicyMode(*modeFlag),
		MinimumSeverity:  admission.ParseSeverity(*minSeverityFlag),
		IgnoreNamespaces: ignoredNamespaces,
	}

	scn := scanner.NewScanner(scanner.ScannerOptions{
		CustomRules: customRules,
	})

	handler := admission.NewAdmissionHandler(scn, policyCfg)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	serverErr := make(chan error, 1)
	go func() {
		if *tlsCert != "" && *tlsKey != "" {
			fmt.Fprintf(os.Stdout, "Starting ValidatingWebhook HTTPS server on port %d (mode: %s, min-severity: %s)\n", *port, *modeFlag, *minSeverityFlag)
			serverErr <- server.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			fmt.Fprintf(os.Stdout, "Starting ValidatingWebhook HTTP server on port %d (mode: %s, min-severity: %s)\n", *port, *modeFlag, *minSeverityFlag)
			serverErr <- server.ListenAndServe()
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server failed to start: %v\n", err)
			return 1
		}
	case sig := <-sigChan:
		fmt.Fprintf(os.Stdout, "Received shutdown signal %v, shutting down gracefully...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
			return 1
		}
	}

	return 0
}
