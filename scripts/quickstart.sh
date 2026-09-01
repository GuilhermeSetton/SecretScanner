#!/bin/sh
set -eu

workspace_dir="/workspace"
output_dir="${workspace_dir}/scan-output"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "${fixture_dir}"' EXIT

mkdir -p "${output_dir}"
cp "${workspace_dir}/examples/vulnerable/deployment.yaml" "${fixture_dir}/deployment.yaml"

google_api_key="AIza""SyD-1234567890abcdefghijklmnopqrst2345"
sed "s|__GOOGLE_API_KEY__|${google_api_key}|g" \
  "${workspace_dir}/examples/vulnerable/secret.yaml.tmpl" \
  > "${fixture_dir}/secret.yaml"

run_expected_findings() {
  set +e
  /usr/local/bin/secretscanner "$@"
  scan_status=$?
  set -e

  if [ "${scan_status}" -eq 1 ]; then
    return 0
  fi

  if [ "${scan_status}" -eq 0 ]; then
    echo "Quickstart failed: vulnerable fixtures produced no findings." >&2
    return 1
  fi

  echo "Quickstart failed: scanner exited with code ${scan_status}." >&2
  return "${scan_status}"
}

echo "Scanning intentionally vulnerable Kubernetes manifests..."
run_expected_findings -dir "${fixture_dir}" -format text

result_path="${output_dir}/quickstart-result.json"
report_path="${output_dir}/quickstart-report.html"

run_expected_findings -dir "${fixture_dir}" -format json > "${result_path}"
python -m report_generator \
  --input "${result_path}" \
  --output "${report_path}" \
  --format html

chmod -R a+rwX "${output_dir}"

echo
echo "Quickstart complete."
echo "JSON: ${result_path}"
echo "HTML: ${report_path}"
