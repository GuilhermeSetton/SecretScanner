// internal/admission/admission_test.go
package admission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
	"github.com/secretscanner/secretscanner-k8s/pkg/rules"
)

func createTestHandler(mode PolicyMode, minSeverity rules.Severity, ignoredNamespaces []string) *AdmissionHandler {
	scn := scanner.NewScanner(scanner.ScannerOptions{})
	cfg := PolicyConfig{
		Mode:             mode,
		MinimumSeverity:  minSeverity,
		IgnoreNamespaces: ignoredNamespaces,
	}
	return NewAdmissionHandler(scn, cfg)
}

func buildReviewRequest(uid string, namespace string, name string, kind string, rawObject string) []byte {
	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       uid,
			Name:      name,
			Namespace: namespace,
			Kind: GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    kind,
			},
			Operation: "CREATE",
			Object:    json.RawMessage(rawObject),
		},
	}
	data, _ := json.Marshal(review)
	return data
}

func TestAdmissionHandler_CleanResourceAllowed(t *testing.T) {
	handler := createTestHandler(ModeEnforce, rules.SeverityHigh, []string{"kube-system"})

	cleanYAML := `{
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {
			"name": "web-service"
		},
		"spec": {
			"ports": [{"port": 80}]
		}
	}`

	reqBody := buildReviewRequest("uid-clean-123", "default", "web-service", "Service", cleanYAML)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var respReview AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &respReview); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if respReview.Response == nil {
		t.Fatalf("expected non-nil response in review")
	}
	if respReview.Response.UID != "uid-clean-123" {
		t.Errorf("expected UID 'uid-clean-123', got %s", respReview.Response.UID)
	}
	if !respReview.Response.Allowed {
		t.Errorf("expected clean resource to be allowed")
	}
}

func TestAdmissionHandler_VulnerableResourceEnforceMode(t *testing.T) {
	handler := createTestHandler(ModeEnforce, rules.SeverityHigh, []string{"kube-system"})

	rawVulnDeploy := `{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "auth-svc"
		},
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "auth",
						"env": [{
							"name": "AWS_ACCESS_KEY_ID",
							"value": "AKIAIOSFODNN7EXAMPLE"
						}]
					}]
				}
			}
		}
	}`

	reqBody := buildReviewRequest("uid-vuln-456", "production", "auth-svc", "Deployment", rawVulnDeploy)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	handler.HandleValidate(w, req)

	// 1. HTTP transport status must be 200 OK for Kubernetes AdmissionReview protocol
	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP status 200, got %d", w.Code)
	}

	var respReview AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &respReview); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if respReview.Response == nil {
		t.Fatalf("expected non-nil response in AdmissionReview")
	}

	// 2. AdmissionResponse.Allowed must be false
	if respReview.Response.Allowed {
		t.Errorf("expected AdmissionResponse.Allowed to be false in enforce mode")
	}

	// 3. AdmissionResponse.UID must match request UID
	if respReview.Response.UID != "uid-vuln-456" {
		t.Errorf("expected UID 'uid-vuln-456', got %s", respReview.Response.UID)
	}

	// 4. AdmissionResponse.Status.Code must be 403 Forbidden
	if respReview.Response.Status == nil || respReview.Response.Status.Code != http.StatusForbidden {
		t.Errorf("expected AdmissionResponse.Status.Code 403 Forbidden, got %v", respReview.Response.Status)
	}

	// 5. Deny message must be sanitized and contain no raw secrets
	msg := respReview.Response.Status.Message
	if !strings.Contains(msg, "admission denied: potential credential detected by rule internal.aws-access-key-id") {
		t.Errorf("unexpected deny message: %s", msg)
	}

	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("SECURITY VIOLATION: raw secret leaked in admission response message: %s", msg)
	}
}

func TestAdmissionHandler_VulnerableResourceWarnMode(t *testing.T) {
	handler := createTestHandler(ModeWarn, rules.SeverityHigh, []string{"kube-system"})

	rawVulnDeploy := `{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "auth-svc"
		},
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "auth",
						"env": [{
							"name": "DATABASE_PASSWORD",
							"value": "SuperSecretPass123"
						}]
					}]
				}
			}
		}
	}`

	reqBody := buildReviewRequest("uid-warn-789", "staging", "auth-svc", "Deployment", rawVulnDeploy)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	handler.HandleValidate(w, req)

	var respReview AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &respReview)

	if !respReview.Response.Allowed {
		t.Errorf("expected resource to be allowed in warn mode")
	}
	if len(respReview.Response.Warnings) == 0 {
		t.Errorf("expected warnings list to be populated in warn mode")
	}
	if !strings.Contains(respReview.Response.Warnings[0], "potential credential detected by rule internal.sensitive-env-var") {
		t.Errorf("unexpected warning string: %s", respReview.Response.Warnings[0])
	}
}

func TestAdmissionHandler_IgnoredNamespace(t *testing.T) {
	handler := createTestHandler(ModeEnforce, rules.SeverityHigh, []string{"kube-system", "monitoring"})

	rawVulnDeploy := `{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "system-agent"
		},
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "agent",
						"env": [{
							"name": "AWS_ACCESS_KEY_ID",
							"value": "AKIAIOSFODNN7EXAMPLE"
						}]
					}]
				}
			}
		}
	}`

	reqBody := buildReviewRequest("uid-ignore-101", "kube-system", "system-agent", "Deployment", rawVulnDeploy)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	handler.HandleValidate(w, req)

	var respReview AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &respReview)

	if !respReview.Response.Allowed {
		t.Errorf("expected resource in ignored namespace 'kube-system' to be allowed")
	}
}

func TestAdmissionHandler_MinimumSeverityFilter(t *testing.T) {
	// Policy configured to only enforce on Critical
	handler := createTestHandler(ModeEnforce, rules.SeverityCritical, []string{"kube-system"})

	// Deployment with High severity finding (sensitive-env-var) but no Critical finding
	rawDeployHighOnly := `{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "db-app"
		},
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "db",
						"env": [{
							"name": "DATABASE_PASSWORD",
							"value": "PlainDbPass12345"
						}]
					}]
				}
			}
		}
	}`

	reqBody := buildReviewRequest("uid-thresh-202", "production", "db-app", "Deployment", rawDeployHighOnly)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	handler.HandleValidate(w, req)

	var respReview AdmissionReview
	_ = json.Unmarshal(w.Body.Bytes(), &respReview)

	// Since threshold is Critical and finding is High, it should be allowed
	if !respReview.Response.Allowed {
		t.Errorf("expected finding below minimum severity threshold to be allowed")
	}
}

func TestAdmissionHandler_HealthEndpoints(t *testing.T) {
	handler := createTestHandler(ModeEnforce, rules.SeverityHigh, nil)

	// Test /healthz
	healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthW := httptest.NewRecorder()
	handler.HandleHealthz(healthW, healthReq)
	if healthW.Code != http.StatusOK || healthW.Body.String() != "OK" {
		t.Errorf("expected /healthz to return 200 OK")
	}

	// Test /readyz
	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	readyW := httptest.NewRecorder()
	handler.HandleReadyz(readyW, readyReq)
	if readyW.Code != http.StatusOK || readyW.Body.String() != "OK" {
		t.Errorf("expected /readyz to return 200 OK")
	}
}

func TestAdmissionHandler_InvalidRequests(t *testing.T) {
	handler := createTestHandler(ModeEnforce, rules.SeverityHigh, nil)

	// 1. GET method on /validate
	getReq := httptest.NewRequest(http.MethodGet, "/validate", nil)
	getW := httptest.NewRecorder()
	handler.HandleValidate(getW, getReq)
	if getW.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405 on GET request, got %d", getW.Code)
	}

	// 2. Malformed JSON
	badJSONReq := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{broken json:"))
	badJSONW := httptest.NewRecorder()
	handler.HandleValidate(badJSONW, badJSONReq)
	if badJSONW.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 on malformed JSON, got %d", badJSONW.Code)
	}

	// 3. Missing Request field
	emptyReviewReq := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`))
	emptyReviewW := httptest.NewRecorder()
	handler.HandleValidate(emptyReviewW, emptyReviewReq)
	if emptyReviewW.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 on missing request envelope, got %d", emptyReviewW.Code)
	}
}
