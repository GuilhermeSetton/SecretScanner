# Scan result JSON contract

The canonical contract between the Go scanner and downstream consumers is [scan-result-v1.json](scan-result-v1.json). The currently supported version is exactly `1.0`.

## Compatibility policy

- Every report must include `"schema_version": "1.0"`.
- The Go producer refuses to emit a report carrying an unsupported version.
- The Python consumer refuses to process an unsupported version.
- The contract is strict: properties not declared by the schema are rejected.
- Backward-compatible additions require a new minor contract version; breaking changes require a new major version. Consumers must be explicitly upgraded before accepting either.
- Reports contain masked matches only. Raw secret values must never be emitted.

The CI suite validates the schema itself, checks the Go and Python version constants against it, and validates every versioned example under `docs/` and `testdata/samples/`.
