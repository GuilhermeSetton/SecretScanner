# deploy/certs/generate-certs.ps1
# Generates self-signed CA and TLS certificates for SecretScanner Admission Webhook in Kind / Minikube.

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Join-Path $scriptDir "../.."

Write-Host "Running pure Go certificate generator..."
Push-Location $rootDir
try {
    go run ./cmd/gencerts -out deploy/certs/out -service secretscanner-webhook -namespace secretscanner-system
} finally {
    Pop-Location
}
