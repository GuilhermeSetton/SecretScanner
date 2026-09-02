# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Two audiences read the published report, in this order of priority:

1. **Technical recruiters and engineering leads** (target: Porto Digital companies, Recife). They arrive from the author's portfolio, give the page around thirty seconds, and decide whether he builds serious software. They are not evaluating the tool; they are evaluating the craft.
2. **Platform and DevOps engineers** evaluating adoption. They want to know what the scanner detects, how noisy the output is, and whether it fits their CI. For them the same page has to survive real reading.

The design must serve both without lying to either: impact for the first, density and accuracy for the second.

## Product Purpose

SecretScanner-K8s finds hardcoded credentials in Kubernetes manifests before they reach a cluster or a public repository. The Go engine detects and classifies severity; the Python layer turns the JSON contract into a standalone HTML report. Success is a maintainer catching a secret at pull-request time instead of after it is published.

## Positioning

- The detection engine and the presentation layer are separate programs joined by a versioned JSON contract, so the report is not welded to the scanner.
- Every reported value is masked before serialization: the report itself can never leak the secret it found.
- The project scans its own repository in CI and fails on any finding outside declared vulnerable fixtures. It found a real private key in its own history and the incident was handled as an incident.
- Ships as a GitHub Action with SARIF upload and as a Kubernetes admission webhook, not only as a local CLI.

## Operating Context

The report is read in three places: on GitHub Pages as the public example, as a downloaded CI artifact after a pipeline run, and locally after `secretscanner` runs against a manifest directory. Findings are acted on inside a pull request, next to the YAML that produced them. Readers arrive already knowing Kubernetes vocabulary: `kind`, `Secret`, `stringData`, field paths, image tags.

## Capabilities and Constraints

- The report is one self-contained HTML file. No CDN, no external fonts, no network requests: it must render identically offline, inside a CI artifact viewer, and on Pages. Inline CSS and inline JavaScript are allowed.
- Rendered through Jinja2 with full autoescape; every finding value arrives already masked (`AKIA************MPLE`).
- `docs/index.html` is generated from `docs/example-scan.json` and CI fails if the committed file differs from a fresh render, so output must stay deterministic.
- Data available per finding: rule id, description, severity, confidence, file, line, column, field path, resource, kind, masked match, remediation. Aggregate: files scanned, affected files, per-severity counts, scan errors, duration, scanner and schema versions.
- Severity vocabulary is fixed: critical, high, medium, low. Status vocabulary is fixed: PASSED, FINDINGS DETECTED, SCAN ERROR.
- Engine version 0.1.0; JSON schema version 1.0. Apache-2.0.

## Brand Commitments

- Name: SecretScanner-K8s. Repository: github.com/GuilhermeSetton/SecretScanner.
- The identity must read as belonging to this scanner specifically — not as a generic template.
- Explicit anti-reference from the author: nothing that looks AI-generated.

## Evidence on Hand

- `docs/example-scan.json`: a real scan of the vulnerable fixtures — 5 findings across 2 files (3 critical, 1 high, 1 medium), all values masked.
- `testdata/near-miss/`: values that look like secrets and are not, used to prove the false-positive work.
- Repository self-scan in CI: 21 YAML files, 6 expected fixture findings, 0 unexpected.
- No users, customers, benchmarks, testimonials, or download counts exist. None may be invented.

## Product Principles

1. **The masked value is the product's promise.** Nothing in any output may risk exposing what it found.
2. **A finding is only useful next to its coordinates.** File, line, field path and resource travel together; a severity without a location is noise.
3. **Quiet on clean.** A scan with no findings should read as calm and finished, not as an empty page.
4. **The report survives without the internet.** Single file, no external dependency, readable in a locked-down environment.
5. **Never claim what the repository cannot show.** Demonstration data is labeled as fixtures; adoption claims do not exist.
