// internal/admission/review.go
package admission

import "encoding/json"

// AdmissionReview represents the Kubernetes admission.k8s.io/v1 AdmissionReview envelope.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest contains metadata and raw payload of the submitted Kubernetes object.
type AdmissionRequest struct {
	UID         string               `json:"uid"`
	Kind        GroupVersionKind     `json:"kind"`
	Resource    GroupVersionResource `json:"resource"`
	SubResource string               `json:"subResource,omitempty"`
	Name        string               `json:"name,omitempty"`
	Namespace   string               `json:"namespace,omitempty"`
	Operation   string               `json:"operation"`
	DryRun      *bool                `json:"dryRun,omitempty"`
	Object      json.RawMessage      `json:"object,omitempty"`
	OldObject   json.RawMessage      `json:"oldObject,omitempty"`
}

// GroupVersionKind identifies a Kubernetes API type.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// GroupVersionResource identifies a Kubernetes API resource.
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// AdmissionResponse contains the webhook evaluation decision.
type AdmissionResponse struct {
	UID      string        `json:"uid"`
	Allowed  bool          `json:"allowed"`
	Status   *StatusResult `json:"status,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// StatusResult provides additional HTTP-like status details for denied admissions.
type StatusResult struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
