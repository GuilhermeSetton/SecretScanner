# Security Policy & Threat Model (STRIDE)

## 1. Threat Model & Security Architecture

SecretScanner-K8s is designed under strict DevSecOps and Least Privilege principles. The following STRIDE threat assessment analyzes the attack surface across CLI scanning, CI/CD reporting, and the Kubernetes Admission Webhook.

### STRIDE Assessment Matrix

| Threat Category | Potential Attack Vector | Mitigation in SecretScanner-K8s |
| :--- | :--- | :--- |
| **Spoofing** | Rogue pod impersonating the Kubernetes Admission Webhook | Webhook mandates TLS 1.2+ mutual handshake configured via Kubernetes `ValidatingWebhookConfiguration.clientConfig.caBundle`. |
| **Tampering** | Malicious payload injecting arbitrary properties into JSON reports or YAML manifests | Strict JSON Schema validation (`additionalProperties: false`) in Python; strict AST-level scalar extraction via `gopkg.in/yaml.v3` in Go. |
| **Repudiation** | Denied resource admissions without diagnostic trace | Admission reviews return structured status logs (HTTP 200 with `status.code: 403` and rule ID / field path), preserving the original request `UID`. |
| **Information Disclosure** | Credential leakage in terminal stdout, CI logs, SARIF outputs, or AdmissionReview deny messages | **Anti-Leak Architectural Guarantee**: Raw secrets are masked immediately upon detection (`AKIA************MPLE`). Formatters and admission responses never emit unmasked strings. |
| **Denial of Service (DoS)** | Exhausting scanner memory with gigantic files or YAML recursion bombs | Maximum file size limit enforced (10 MB per manifest in Go, 50 MB in Python validator); stream readers capped with `http.MaxBytesReader`. |
| **Elevation of Privilege** | Compromised webhook container attempting to read cluster secrets or modify workloads | Webhook runs as a non-root user (`UID 10001:10001`) with `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, and zero cluster secret read RBAC permissions. |

---

## 2. Anti-Leak Guarantees & Memory Handling

1. **Deterministic Masking**:
   - Secrets are masked immediately at the detector level (`internal/detectors/mask.go`).
   - String slices representing matches retain only masked scalar values (`AKIA************MPLE`).
2. **Memory-Only Ingestion**:
   - The Go engine processes documents in memory and does not write unmasked intermediate temporary files.
   - Kubernetes Secret `data` fields are decoded in memory, evaluated against rules, and immediately discarded without writing plain text to disk.
3. **No Cluster Secret Fetching**:
   - The Admission Webhook inspects only the serialized `AdmissionRequest.object` submitted in the HTTPS request body. It does not issue API calls to read existing cluster secrets.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability or credential leak within SecretScanner-K8s:

1. **Do NOT open a public issue on GitHub.**
2. Send a detailed report to the security team via email at `security@secretscanner.local` or submit a private security advisory via GitHub Security Advisories.
3. Include:
   - Description of the vulnerability and attack vector.
   - Minimal reproducible example or manifest payload.
   - Impact assessment on CI/CD or Kubernetes clusters.

The maintainers will acknowledge receipt within 48 hours and provide a remediation timeline.
