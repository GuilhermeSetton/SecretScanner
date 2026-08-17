// internal/admission/handler.go
package admission

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/secretscanner/secretscanner-k8s/internal/scanner"
)

const maxRequestBodySize = 10 * 1024 * 1024 // 10 MB

// AdmissionHandler handles Kubernetes ValidatingWebhook HTTP requests.
type AdmissionHandler struct {
	scanner *scanner.Scanner
	config  PolicyConfig
}

// NewAdmissionHandler creates a new AdmissionHandler instance.
func NewAdmissionHandler(scn *scanner.Scanner, config PolicyConfig) *AdmissionHandler {
	return &AdmissionHandler{
		scanner: scn,
		config:  config,
	}
}

// RegisterRoutes registers admission webhook and health check routes on a ServeMux.
func (h *AdmissionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/validate", h.HandleValidate)
	mux.HandleFunc("/healthz", h.HandleHealthz)
	mux.HandleFunc("/readyz", h.HandleReadyz)
}

func (h *AdmissionHandler) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (h *AdmissionHandler) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (h *AdmissionHandler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed: Admission webhooks only accept POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodySize))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unmarshal AdmissionReview: %v", err), http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "Invalid AdmissionReview: missing request envelope", http.StatusBadRequest)
		return
	}

	req := review.Request
	var decision AdmissionDecision

	if len(req.Object) == 0 {
		decision = AdmissionDecision{Allowed: true}
	} else {
		sourceName := fmt.Sprintf("%s/%s", req.Kind.Kind, req.Name)
		if req.Namespace != "" {
			sourceName = fmt.Sprintf("%s/%s", req.Namespace, sourceName)
		}

		scanReport, scanErr := h.scanner.ScanDocuments(r.Context(), sourceName, req.Object)
		if scanErr != nil {
			// On scan engine error, enforce safe fallback
			decision = AdmissionDecision{
				Allowed:     false,
				DenyMessage: fmt.Sprintf("admission denied: internal scanner failure: %v", scanErr),
			}
		} else {
			decision = Evaluate(scanReport.Findings, scanReport.Errors, req, h.config)
		}
	}

	response := &AdmissionResponse{
		UID:      req.UID,
		Allowed:  decision.Allowed,
		Warnings: decision.Warnings,
	}

	if !decision.Allowed {
		response.Status = &StatusResult{
			Code:    http.StatusForbidden,
			Message: decision.DenyMessage,
		}
	}

	responseReview := AdmissionReview{
		APIVersion: review.APIVersion,
		Kind:       review.Kind,
		Response:   response,
	}

	respBytes, err := json.Marshal(responseReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal AdmissionResponse: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
