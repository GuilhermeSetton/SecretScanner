# Contributing to SecretScanner-K8s

Contributions to SecretScanner-K8s are welcome. Please follow these guidelines to maintain code quality, security posture, and testing standards.

---

## 1. Development Prerequisites

- **Go**: 1.22+ (recommended 1.24+)
- **Python**: 3.10+ (recommended 3.12+)
- **Git**

---

## 2. Local Setup & Testing

1. Clone the repository:
   ```bash
   git clone https://github.com/secretscanner/secretscanner-k8s.git
   cd secretscanner-k8s
   ```

2. Install Python dependencies in editable mode:
   ```bash
   python -m pip install -e "python[dev]"
   ```

3. Run the complete test suite:
   ```bash
   make test
   # Or manually:
   go test -v -cover ./...
   python -m pytest python
   ```

4. Format and lint code:
   ```bash
   make fmt
   make lint
   ```

---

## 3. Authoring New Detection Rules

### Custom YAML Rules
To add custom regex patterns without modifying Go source code, define them in a custom rules file:
```yaml
rules:
  - id: custom.example-token
    description: Example Service Token
    severity: high        # critical, high, medium, low
    confidence: high      # critical, high, medium, low
    regex: 'tok_[a-zA-Z0-9]{32}'
```
*Note: Custom rule IDs must NOT begin with `internal.`.*

### Built-in Go Detectors
When implementing new built-in detectors in `internal/detectors/`:
1. Add regex patterns or contextual validation logic in `internal/detectors/regex_rules.go`.
2. Ensure secrets are masked immediately using `MaskSecret(raw)`.
3. Add unit tests in `internal/detectors/detectors_test.go` including positive matches, negative matches (to prevent false positives), and anti-leak assertions (`TestFindingZeroLeak`).

---

## 4. Code Standards & Pull Request Requirements

- **Zero-Leak Commitment**: Ensure no test output, log line, error message, or documentation leaks unmasked secret credentials.
- **Strict Formatting**: Run `gofmt -w -s .` before committing.
- **Coverage**: All new detector rules and admission handlers must include unit and integration tests.
- **No Emojis**: Do not use emojis in commit messages, comments, logs, test names, or documentation.
