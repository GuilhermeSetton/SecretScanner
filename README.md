# SecretScanner-K8s

[English](README.md) | [Português (Brasil)](README.pt-BR.md)

[![CI](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/test.yml/badge.svg)](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/test.yml)
[![Security Scan](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/security-scan.yml)
[![Example Report](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/pages.yml/badge.svg)](https://guilhermesetton.github.io/SecretScanner/)
[![License](https://img.shields.io/github/license/GuilhermeSetton/SecretScanner)](LICENSE)

**Stop exposed credentials before a Kubernetes manifest reaches Git, CI, or your cluster.**

Kubernetes manifests often carry API keys, access tokens, passwords, and encoded secrets alongside ordinary configuration. One leaked value can be copied into Git history, exposed in CI logs, or deployed before a reviewer notices it.

SecretScanner-K8s helps developers, platform teams, and security teams catch those credentials before deployment. It scans YAML manifests locally or in CI, masks every reported value, assigns a severity, and can block vulnerable workloads through a Kubernetes admission webhook.

- Detects AWS and Google Cloud keys, private SSH keys, JWTs, sensitive environment variables, and suspicious high-entropy strings.
- Produces text, JSON, SARIF, and self-contained HTML reports without exposing the detected value.
- Fits local development, GitHub Code Scanning, and admission-time enforcement.

<p align="center">
  <img src="docs/demo.gif" alt="SecretScanner-K8s finds five masked credentials in vulnerable Kubernetes manifests" width="900">
</p>

One command. Five findings. Every detected value stays masked.

---

## Quickstart

Prerequisites: [Git](https://git-scm.com/) and [Docker](https://docs.docker.com/get-docker/) with Docker Compose.

After cloning the repository, run one command:

```bash
docker compose run --build --rm quickstart
```

Starting from an empty directory:

```bash
git clone https://github.com/GuilhermeSetton/SecretScanner.git && cd SecretScanner && docker compose run --build --rm quickstart
```

The quickstart builds for your machine's architecture, scans intentionally vulnerable Kubernetes manifests, and prints masked findings. It treats the scanner's expected `1` exit code as a successful detection while preserving operational failures.

Generated files:

- `scan-output/quickstart-result.json`
- `scan-output/quickstart-report.html`

Both outputs contain masked matches. The HTML report is self-contained and requires no network connection to open.

See the same kind of masked, self-contained output in the [published example report](https://guilhermesetton.github.io/SecretScanner/). The page is rebuilt and deployed automatically from fictional scan data on every relevant change to `main`.

---

## Kubernetes Validation (Kind / Minikube)

```bash
# 1. Generate TLS certificates and apply the admission webhook manifests
make certs
kubectl apply -f deploy/00-namespace.yaml
kubectl apply -f deploy/01-serviceaccount.yaml
kubectl apply -f deploy/02-secret-tls.yaml
kubectl apply -f deploy/03-deployment.yaml
kubectl apply -f deploy/04-service.yaml
kubectl apply -f deploy/05-validatingwebhook.yaml

# 2. Verify that a vulnerable manifest is blocked
kubectl apply -f examples/vulnerable/deployment.yaml
# kubectl result: Error from server (Forbidden): admission webhook "validate.secretscanner.k8s" denied the request

# 3. Verify that a safe manifest is admitted
kubectl apply -f examples/clean/deployment.yaml
# kubectl result: deployment.apps/order-service created
```

### Admission protocol and webhook responses

- **HTTP transport**: The Kubernetes API Server request to `/validate` always receives **HTTP 200 OK**.
- **Decision envelope (`AdmissionResponse`)**:
  - Blocked workload: `response.allowed: false` and `response.status.code: 403` (Forbidden).
  - Accepted workload: `response.allowed: true`.
- **Client (`kubectl`)**: Displays the formal `Error from server (Forbidden)` rejection without exposing credentials in logs.

---

## Architecture and Data Contract

```
                      +-----------------------------+
                      |   Kubernetes Manifests      |
                      |   (YAML / Multi-Doc / Data) |
                      +--------------+--------------+
                                     |
                                     v
                 +---------------------------------------+
                 |       SecretScanner Engine (Go)       |
                 |  - Regex Detectors (AWS, GCP, SSH)    |
                 |  - Shannon Entropy Analysis           |
                 |  - Base64 Secret.data In-Memory       |
                 |  - Hierarchical Deduplication         |
                 +-------------------+-------------------+
                                     |
                  +------------------+------------------+
                  |                                     |
                  v                                     v
       +--------------------+                +--------------------+
       | Standard JSON v1.0 |                |    SARIF Report    |
       |  (Strict Contract) |                | (GitHub CodeScan)  |
       +----------+---------+                +--------------------+
                  |
                  v
       +--------------------+
       |  Python Reporter   |
       |  - Jinja2 HTML     |
       |  - JSON Summary    |
       +--------------------+
```

---

## Built-in Detection Rules

| Rule ID | Description | Default Severity | Confidence |
| :--- | :--- | :--- | :--- |
| `internal.aws-access-key-id` | AWS Access Key ID (`AKIA...`) | Critical | High |
| `internal.aws-secret-access-key` | AWS Secret Access Key in a sensitive context | Critical | High |
| `internal.google-api-key` | Google Cloud API Key (`AIza...`) | Critical | High |
| `internal.ssh-private-key` | OpenSSH / RSA private key headers | Critical | High |
| `internal.jwt-token` | Base64-encoded JSON Web Tokens | Critical | High |
| `internal.sensitive-env-var` | Sensitive names (`PASSWORD`, `TOKEN`) in plain environment variables | High | High |
| `internal.shannon-entropy` | High-entropy strings (Shannon $H \ge 4.5$) | Medium | Medium |

---

## Security and Anti-Leak Guarantees

- **Proactive masking**: Every tested finding is masked before serialization or display (`AKIA************MPLE`).
- **Memory isolation**: The scanner processes manifests and `Secret.data` fields in memory without persisting decoded credentials to temporary disk files.
- **Least privilege**: The admission webhook does not query or read existing secrets from cluster etcd.
- **Self-scanning CI**: The project scans every YAML file in its own repository and fails on findings outside explicitly vulnerable test fixtures.
- The complete STRIDE threat model is documented in [SECURITY.md](SECURITY.md).

---

## Project Maturity

The project is ready for GitHub publication, technical demonstrations, and validation in local or staging environments. Production adoption still requires ongoing operational testing, TLS certificate infrastructure review (for example, cert-manager), `failurePolicy` calibration, observability, and validation in a controlled cluster.

Initial release: `v0.1.0`.

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
