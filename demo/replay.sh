#!/usr/bin/env sh
set -eu

sleep 0.4
printf '\033[1;36m%s\033[0m\n\n' 'Scanning intentionally vulnerable Kubernetes manifests...'
sleep 0.6
printf '\033[1m%-10s %-34s %-23s %s\033[0m\n' 'SEVERITY' 'RULE ID' 'RESOURCE' 'MASKED MATCH'
printf '%-10s %-34s %-23s %s\n' 'HIGH' 'internal.sensitive-env-var' 'payment-api' 'Supe**************d123'
sleep 0.5
printf '\033[1;31m%-10s\033[0m %-34s %-23s %s\n' 'CRITICAL' 'internal.aws-access-key-id' 'payment-api' 'AKIA************MPLE'
sleep 0.5
printf '\033[1;31m%-10s\033[0m %-34s %-23s %s\n' 'CRITICAL' 'internal.jwt-token' 'payment-api' 'eyJh********sw5c'
sleep 0.5
printf '\033[1;31m%-10s\033[0m %-34s %-23s %s\n' 'CRITICAL' 'internal.aws-secret-access-key' 'cloud-api-credentials' 'wJal********EKEY'
sleep 0.5
printf '\033[1;33m%-10s\033[0m %-34s %-23s %s\n' 'MEDIUM' 'internal.shannon-entropy' 'cloud-api-credentials' 'AIza********2345'
sleep 0.7
printf '\n\033[1m%s\033[0m\n' 'Scan summary: 2 files scanned | 5 findings detected | 0 errors'
printf '\033[32m%s\033[0m\n' 'All reported values are masked.'
printf '%s\n' 'HTML: scan-output/quickstart-report.html'
