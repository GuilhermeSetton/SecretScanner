#!/usr/bin/env bash
# deploy/certs/generate-certs.sh
# Generates self-signed CA and TLS certificates for SecretScanner Admission Webhook in Kind / Minikube.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/out"
mkdir -p "${OUTPUT_DIR}"

SERVICE_NAME="secretscanner-webhook"
NAMESPACE="secretscanner-system"
CSR_NAME="${SERVICE_NAME}.${NAMESPACE}.svc"

echo "Generating CA private key and certificate..."
openssl genrsa -out "${OUTPUT_DIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${OUTPUT_DIR}/ca.key" -subj "/CN=SecretScanner Webhook CA" -days 365 -out "${OUTPUT_DIR}/ca.crt"

echo "Generating Webhook server private key..."
openssl genrsa -out "${OUTPUT_DIR}/tls.key" 2048

cat <<EOF > "${OUTPUT_DIR}/csr.conf"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

echo "Generating Webhook CSR..."
openssl req -new -key "${OUTPUT_DIR}/tls.key" -subj "/CN=${CSR_NAME}" -out "${OUTPUT_DIR}/tls.csr" -config "${OUTPUT_DIR}/csr.conf"

echo "Signing Webhook certificate with CA..."
openssl x509 -req -in "${OUTPUT_DIR}/tls.csr" -CA "${OUTPUT_DIR}/ca.crt" -CAkey "${OUTPUT_DIR}/ca.key" -CAcreateserial -out "${OUTPUT_DIR}/tls.crt" -days 365 -extensions v3_req -extfile "${OUTPUT_DIR}/csr.conf"

CA_BUNDLE=$(base64 < "${OUTPUT_DIR}/ca.crt" | tr -d '\n')
TLS_CRT_B64=$(base64 < "${OUTPUT_DIR}/tls.crt" | tr -d '\n')
TLS_KEY_B64=$(base64 < "${OUTPUT_DIR}/tls.key" | tr -d '\n')

echo "Updating deploy/02-secret-tls.yaml..."
cat <<EOF > "${SCRIPT_DIR}/../02-secret-tls.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: secretscanner-webhook-tls
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: secretscanner-webhook
    app.kubernetes.io/part-of: secretscanner-k8s
type: kubernetes.io/tls
data:
  tls.crt: ${TLS_CRT_B64}
  tls.key: ${TLS_KEY_B64}
EOF

echo "Injecting caBundle into deploy/05-validatingwebhook.yaml..."
sed -i "s|caBundle:.*|caBundle: ${CA_BUNDLE}|g" "${SCRIPT_DIR}/../05-validatingwebhook.yaml"

echo "Certificate generation complete. Files saved in ${OUTPUT_DIR}"
