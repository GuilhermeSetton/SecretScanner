#!/usr/bin/env sh
set -eu

python -m report_generator \
  --input docs/example-scan.json \
  --output docs/index.html \
  --format html

printf '%s\n' 'Generated docs/index.html from docs/example-scan.json'
