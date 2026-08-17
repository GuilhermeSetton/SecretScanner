// cmd/gencerts/main.go
// Standalone, zero-external-dependency certificate generator for SecretScanner Admission Webhook.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	outDir := flag.String("out", "deploy/certs/out", "Output directory for PEM certificates")
	serviceName := flag.String("service", "secretscanner-webhook", "Webhook Kubernetes service name")
	namespace := flag.String("namespace", "secretscanner-system", "Webhook Kubernetes namespace")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// 1. Generate CA Private Key & Certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate CA key: %v\n", err)
		os.Exit(1)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(202601),
		Subject: pkix.Name{
			CommonName:   "SecretScanner Webhook CA",
			Organization: []string{"SecretScanner-K8s"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create CA certificate: %v\n", err)
		os.Exit(1)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	_ = os.WriteFile(filepath.Join(*outDir, "ca.crt"), caPEM, 0644)
	_ = os.WriteFile(filepath.Join(*outDir, "ca.key"), caKeyPEM, 0600)

	// 2. Generate Server Private Key & Certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate server key: %v\n", err)
		os.Exit(1)
	}

	dnsNames := []string{
		*serviceName,
		fmt.Sprintf("%s.%s", *serviceName, *namespace),
		fmt.Sprintf("%s.%s.svc", *serviceName, *namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", *serviceName, *namespace),
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(202602),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s.%s.svc", *serviceName, *namespace),
			Organization: []string{"SecretScanner-K8s"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server certificate: %v\n", err)
		os.Exit(1)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	_ = os.WriteFile(filepath.Join(*outDir, "tls.crt"), serverCertPEM, 0644)
	_ = os.WriteFile(filepath.Join(*outDir, "tls.key"), serverKeyPEM, 0600)

	// 3. Update deploy/02-secret-tls.yaml
	tlsCrtB64 := base64.StdEncoding.EncodeToString(serverCertPEM)
	tlsKeyB64 := base64.StdEncoding.EncodeToString(serverKeyPEM)
	caBundleB64 := base64.StdEncoding.EncodeToString(caPEM)

	secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: secretscanner-webhook-tls
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/part-of: secretscanner-k8s
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, *namespace, *serviceName, tlsCrtB64, tlsKeyB64)

	_ = os.WriteFile("deploy/02-secret-tls.yaml", []byte(secretYAML), 0644)

	// 4. Inject caBundle into deploy/05-validatingwebhook.yaml
	webhookPath := "deploy/05-validatingwebhook.yaml"
	webhookBytes, err := os.ReadFile(webhookPath)
	if err == nil {
		lines := strings.Split(string(webhookBytes), "\n")
		var outLines []string
		for _, line := range lines {
			if strings.Contains(line, "caBundle:") {
				indent := line[:strings.Index(line, "caBundle:")]
				outLines = append(outLines, fmt.Sprintf("%scaBundle: %s", indent, caBundleB64))
			} else {
				outLines = append(outLines, line)
			}
		}
		_ = os.WriteFile(webhookPath, []byte(strings.Join(outLines, "\n")), 0644)
	}

	fmt.Printf("Certificates generated successfully in %s\n", *outDir)
	fmt.Println("Updated deploy/02-secret-tls.yaml and deploy/05-validatingwebhook.yaml with CA bundle.")
}
