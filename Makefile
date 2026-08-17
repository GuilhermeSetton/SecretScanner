# SecretScanner-K8s Makefile
# Automates local builds, testing, linting, TLS certificate generation, and Docker builds.

SHELL := /bin/bash
BIN_DIR ?= bin
VERSION ?= 1.0.0
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT)

.PHONY: all
all: lint test build

.PHONY: help
help:
	@echo "SecretScanner-K8s Automation Commands:"
	@echo "  make build               Build all Go binaries (CLI, Webhook, Cert Generator)"
	@echo "  make test                Run all tests (Go unit/coverage + Python pytest)"
	@echo "  make test-go             Run Go unit tests with coverage"
	@echo "  make test-go-race        Run Go tests with race detector (requires CGO/Linux)"
	@echo "  make test-python         Run Python pytest suite"
	@echo "  make lint                Run go vet and format verification"
	@echo "  make fmt                 Format all Go code using gofmt"
	@echo "  make certs               Generate CA and TLS certificates using pure Go generator"
	@echo "  make docker-build-cli    Build secretscanner-cli Docker image"
	@echo "  make docker-build-webhook Build secretscanner-webhook Docker image"
	@echo "  make deploy-kind         Deploy webhook manifests into local Kubernetes cluster"
	@echo "  make clean               Clean build artifacts and temporary files"

.PHONY: build
build: build-cli build-webhook build-gencerts

.PHONY: build-cli
build-cli:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/secretscanner ./cmd/secretscanner

.PHONY: build-webhook
build-webhook:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/admission-webhook ./cmd/admission-webhook

.PHONY: build-gencerts
build-gencerts:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/gencerts ./cmd/gencerts

.PHONY: test
test: test-go test-python

.PHONY: test-go
test-go:
	go test -v -cover ./...

.PHONY: test-go-race
test-go-race:
	go test -v -race -cover ./...

.PHONY: test-python
test-python:
	python -m pytest python

.PHONY: scan-fixtures
scan-fixtures: build-cli
	@mkdir -p scan-output
	@./$(BIN_DIR)/secretscanner -dir ./examples/clean -format json > scan-output/clean.json 2> scan-output/clean.log; \
	status=$$?; \
	if [ $$status -ne 0 ]; then \
		echo "Erro inesperado no scan limpo (exit code $$status)"; exit $$status; \
	fi
	@./$(BIN_DIR)/secretscanner -dir ./examples/vulnerable -format json > scan-output/scan-result.json 2> scan-output/scan.log; \
	status=$$?; \
	if [ $$status -ne 0 ] && [ $$status -ne 1 ]; then \
		echo "Erro de execucao no scan vulneravel (exit code $$status)"; exit $$status; \
	fi
	@./$(BIN_DIR)/secretscanner -dir ./examples/vulnerable -format sarif > scan-output/scan-result.sarif 2>> scan-output/scan.log; \
	status=$$?; \
	if [ $$status -ne 0 ] && [ $$status -ne 1 ]; then \
		echo "Erro de execucao no scan SARIF (exit code $$status)"; exit $$status; \
	fi
	@echo "Scan concluido. Resultados salvos em scan-output/scan-result.json e scan-output/scan-result.sarif"

.PHONY: report
report: scan-fixtures
	python -m report_generator --input scan-output/scan-result.json --output scan-output/report.html --format html
	python -m report_generator --input scan-output/scan-result.json --output scan-output/summary.json --format json
	@echo "Relatorio concluido. Relatorio HTML gerado em scan-output/report.html"

.PHONY: lint
lint:
	go vet ./...
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Files requiring gofmt:"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi

.PHONY: fmt
fmt:
	gofmt -w -s .

.PHONY: certs
certs:
	go run ./cmd/gencerts -out deploy/certs/out -service secretscanner-webhook -namespace secretscanner-system

.PHONY: docker-build-cli
docker-build-cli:
	docker build -f Dockerfile.cli -t secretscanner-cli:$(VERSION) -t secretscanner-cli:latest .

.PHONY: docker-build-webhook
docker-build-webhook:
	docker build -f Dockerfile.webhook -t secretscanner-webhook:$(VERSION) -t secretscanner-webhook:latest .

.PHONY: deploy-kind
deploy-kind: certs
	kubectl apply -f deploy/00-namespace.yaml
	kubectl apply -f deploy/01-serviceaccount.yaml
	kubectl apply -f deploy/02-secret-tls.yaml
	kubectl apply -f deploy/03-deployment.yaml
	kubectl apply -f deploy/04-service.yaml
	kubectl apply -f deploy/05-validatingwebhook.yaml

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf deploy/certs/out
	rm -rf scan-output
	rm -f testdata/samples/report.html testdata/samples/summary.json
