# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-17

### Added
- **Core Go Engine (`internal/scanner`, `internal/detectors`)**:
  - AST-level YAML scalar parsing preserving exact line, column, and field path coordinates.
  - Context-aware AWS Secret Access Key detection eliminating false positives from unrelated keys.
  - Shannon entropy detector for high-entropy tokens and API keys.
  - Sensitive environment variable detector for hardcoded container configurations.
  - Transparent in-memory decoding and inspection of Kubernetes `Secret.data` (Base64) and `stringData`.
  - Hierarchical deduplication (Specific Rule > Sensitive Env Var > Shannon Entropy).
  - Deterministic ordering of findings and strict masking (`MaskSecret`) to guarantee zero secret leaks.
  - Text, JSON (v1.0 schema), and SARIF formatters.

- **Python Report Generator (`python/report_generator`)**:
  - Independent presentation layer consuming standard JSON v1.0 schema contract.
  - Strict payload validation rejecting unexpected extra properties (`additionalProperties: false`) and derived count discrepancies.
  - Standalone, responsive HTML report rendered via Jinja2 with full autoescape against XSS.
  - Structured JSON summary generator for pipeline integrations.

- **GitHub Action & CI/CD (`action.yml`, `.github/workflows`)**:
  - Composite GitHub Action with `directory`, `rules`, `fail-on`, `generate-html`, and `output-dir` inputs.
  - Workflows for automated unit/coverage testing and SARIF upload to GitHub Code Scanning.

- **Kubernetes Admission Controller Webhook (`cmd/admission-webhook`, `internal/admission`)**:
  - `admission.k8s.io/v1` validating webhook running in memory without fetching cluster secrets.
  - Support for `enforce` (blocking) and `warn` (alerting) evaluation modes.
  - Minimum severity threshold filtering and configurable ignored namespaces.
  - Hardened deployment manifests (`deploy/`) with non-root execution and read-only root filesystems.
  - Zero-dependency TLS certificate generator in pure Go (`cmd/gencerts`).
