#!/bin/sh
set -eu

workspace_dir="/workspace"
output_dir="${workspace_dir}/scan-output"
report_path="${output_dir}/self-scan.json"

mkdir -p "${output_dir}"

set +e
/usr/local/bin/secretscanner -dir "${workspace_dir}" -format json > "${report_path}"
scan_status=$?
set -e

case "${scan_status}" in
  0|1|2) ;;
  *)
    echo "Self-scan failed: scanner exited with unexpected code ${scan_status}." >&2
    exit "${scan_status}"
    ;;
esac

python - "${report_path}" <<'PY'
import json
import sys

report_path = sys.argv[1]
with open(report_path, encoding="utf-8") as report_file:
    report = json.load(report_file)

allowed_finding_prefixes = (
    "/workspace/examples/vulnerable/",
    "/workspace/testdata/vulnerable/",
)
allowed_error_files = {
    "/workspace/testdata/invalid/broken.yaml",
}

unexpected_findings = [
    finding
    for finding in report["findings"]
    if not finding["file"].startswith(allowed_finding_prefixes)
]
unexpected_errors = [
    error
    for error in report["errors"]
    if error["file"] not in allowed_error_files
]

if unexpected_findings or unexpected_errors:
    for finding in unexpected_findings:
        print(
            f"Unexpected finding: {finding['rule_id']} in {finding['file']}",
            file=sys.stderr,
        )
    for error in unexpected_errors:
        print(f"Unexpected scan error: {error['file']}", file=sys.stderr)
    raise SystemExit(1)

print(
    "Self-scan passed: "
    f"{report['summary']['files_scanned']} YAML files, "
    f"{len(report['findings'])} expected fixture findings, "
    "0 unexpected findings."
)
PY
