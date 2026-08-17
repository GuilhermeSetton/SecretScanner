// internal/scanner/parser.go
package scanner

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/secretscanner/secretscanner-k8s/internal/detectors"
	"gopkg.in/yaml.v3"
)

// ParseAndScanYAML parses multi-document YAML manifests using AST yaml.Node,
// navigates targeted Kubernetes fields, executes detectors, and collects findings.
func ParseAndScanYAML(filePath string, data []byte, detectorList []detectors.Detector) ([]detectors.Finding, []ScanError) {
	var findings []detectors.Finding
	var scanErrors []ScanError

	decoder := yaml.NewDecoder(bytes.NewReader(data))

	docIndex := 0
	for {
		var docNode yaml.Node
		err := decoder.Decode(&docNode)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			scanErrors = append(scanErrors, ScanError{
				File:    filePath,
				Message: fmt.Sprintf("invalid YAML syntax in document %d: %v", docIndex+1, err),
			})
			break
		}

		docIndex++
		if docNode.Kind == 0 {
			continue
		}

		// Traverse the root node of the document
		docFindings, docErrors := processDocNode(filePath, &docNode, detectorList)
		findings = append(findings, docFindings...)
		scanErrors = append(scanErrors, docErrors...)
	}

	return findings, scanErrors
}

func processDocNode(filePath string, rootNode *yaml.Node, detectorList []detectors.Detector) ([]detectors.Finding, []ScanError) {
	if rootNode.Kind == yaml.DocumentNode && len(rootNode.Content) > 0 {
		rootNode = rootNode.Content[0]
	}

	if rootNode.Kind != yaml.MappingNode {
		return nil, nil
	}

	meta := extractK8sMetadata(rootNode)

	// If the resource is kind: Secret, apply specialized Secret handling
	if strings.EqualFold(meta.Kind, "Secret") {
		return scanSecretResource(filePath, meta, rootNode, detectorList)
	}

	// For general Kubernetes resources (Deployment, Pod, ConfigMap, etc.)
	return scanGeneralResource(filePath, meta, rootNode, detectorList)
}

type k8sMetadata struct {
	Kind string
	Name string
}

func extractK8sMetadata(mappingNode *yaml.Node) k8sMetadata {
	var meta k8sMetadata
	for i := 0; i < len(mappingNode.Content)-1; i += 2 {
		key := mappingNode.Content[i].Value
		valNode := mappingNode.Content[i+1]
		if strings.EqualFold(key, "kind") {
			meta.Kind = valNode.Value
		} else if strings.EqualFold(key, "metadata") && valNode.Kind == yaml.MappingNode {
			for j := 0; j < len(valNode.Content)-1; j += 2 {
				if strings.EqualFold(valNode.Content[j].Value, "name") {
					meta.Name = valNode.Content[j+1].Value
				}
			}
		}
	}
	return meta
}

func scanSecretResource(filePath string, meta k8sMetadata, rootNode *yaml.Node, detectorList []detectors.Detector) ([]detectors.Finding, []ScanError) {
	var findings []detectors.Finding
	var scanErrors []ScanError

	for i := 0; i < len(rootNode.Content)-1; i += 2 {
		keyNode := rootNode.Content[i]
		valNode := rootNode.Content[i+1]

		if keyNode.Value == "data" && valNode.Kind == yaml.MappingNode {
			for j := 0; j < len(valNode.Content)-1; j += 2 {
				secretKeyNode := valNode.Content[j]
				secretValNode := valNode.Content[j+1]
				fieldPath := fmt.Sprintf("data.%s", secretKeyNode.Value)

				rawBase64 := strings.TrimSpace(secretValNode.Value)
				if rawBase64 == "" {
					continue
				}

				decodedBytes, err := base64.StdEncoding.DecodeString(rawBase64)
				if err != nil {
					// Fallback: try raw URL or unpadded encoding
					decodedBytes, err = base64.RawStdEncoding.DecodeString(rawBase64)
				}

				if err != nil {
					// Anti-leak: do not include the rawBase64 value in error message
					scanErrors = append(scanErrors, ScanError{
						File:    filePath,
						Message: fmt.Sprintf("failed to decode Secret.data.%s: invalid base64 encoding", secretKeyNode.Value),
					})
					continue
				}

				// Check if binary payload (contains null byte or invalid UTF-8)
				if bytes.IndexByte(decodedBytes, 0x00) != -1 || !utf8.Valid(decodedBytes) {
					continue
				}

				decodedStr := string(decodedBytes)
				scanCtx := detectors.ScanContext{
					File:      filePath,
					Resource:  meta.Name,
					Kind:      meta.Kind,
					FieldPath: fieldPath,
					Line:      secretValNode.Line,
					Column:    secretValNode.Column,
					KeyName:   secretKeyNode.Value,
				}

				for _, det := range detectorList {
					matches := det.Detect(decodedStr, scanCtx)
					for _, m := range matches {
						findings = append(findings, detectors.NewFinding(m, scanCtx))
					}
				}
			}
		} else if keyNode.Value == "stringData" && valNode.Kind == yaml.MappingNode {
			for j := 0; j < len(valNode.Content)-1; j += 2 {
				secretKeyNode := valNode.Content[j]
				secretValNode := valNode.Content[j+1]
				fieldPath := fmt.Sprintf("stringData.%s", secretKeyNode.Value)

				scanCtx := detectors.ScanContext{
					File:      filePath,
					Resource:  meta.Name,
					Kind:      meta.Kind,
					FieldPath: fieldPath,
					Line:      secretValNode.Line,
					Column:    secretValNode.Column,
					KeyName:   secretKeyNode.Value,
				}

				for _, det := range detectorList {
					matches := det.Detect(secretValNode.Value, scanCtx)
					for _, m := range matches {
						findings = append(findings, detectors.NewFinding(m, scanCtx))
					}
				}
			}
		}
	}

	return findings, scanErrors
}

func scanGeneralResource(filePath string, meta k8sMetadata, rootNode *yaml.Node, detectorList []detectors.Detector) ([]detectors.Finding, []ScanError) {
	var findings []detectors.Finding
	var scanErrors []ScanError

	var walkNode func(node *yaml.Node, currentPath string, parentKey string)
	walkNode = func(node *yaml.Node, currentPath string, parentKey string) {
		if node == nil {
			return
		}

		switch node.Kind {
		case yaml.MappingNode:
			for i := 0; i < len(node.Content)-1; i += 2 {
				kNode := node.Content[i]
				vNode := node.Content[i+1]
				keyName := kNode.Value

				// Skip labels and selectors
				if keyName == "labels" || keyName == "selector" || keyName == "matchLabels" {
					continue
				}

				// Skip envFrom (structural reference)
				if keyName == "envFrom" {
					continue
				}

				// Annotations: only scan if key indicates sensitive content
				if keyName == "annotations" && vNode.Kind == yaml.MappingNode {
					for a := 0; a < len(vNode.Content)-1; a += 2 {
						annKeyNode := vNode.Content[a]
						annValNode := vNode.Content[a+1]
						if isSensitiveKey(annKeyNode.Value) {
							annPath := fmt.Sprintf("%s.annotations[%s]", currentPath, annKeyNode.Value)
							scanCtx := detectors.ScanContext{
								File:      filePath,
								Resource:  meta.Name,
								Kind:      meta.Kind,
								FieldPath: annPath,
								Line:      annValNode.Line,
								Column:    annValNode.Column,
								KeyName:   annKeyNode.Value,
							}
							for _, det := range detectorList {
								for _, m := range det.Detect(annValNode.Value, scanCtx) {
									findings = append(findings, detectors.NewFinding(m, scanCtx))
								}
							}
						}
					}
					continue
				}

				// ConfigMap data: only scan if key is sensitive
				if strings.EqualFold(meta.Kind, "ConfigMap") && keyName == "data" && vNode.Kind == yaml.MappingNode {
					for c := 0; c < len(vNode.Content)-1; c += 2 {
						cmKeyNode := vNode.Content[c]
						cmValNode := vNode.Content[c+1]
						if isSensitiveKey(cmKeyNode.Value) {
							cmPath := fmt.Sprintf("data.%s", cmKeyNode.Value)
							scanCtx := detectors.ScanContext{
								File:      filePath,
								Resource:  meta.Name,
								Kind:      meta.Kind,
								FieldPath: cmPath,
								Line:      cmValNode.Line,
								Column:    cmValNode.Column,
								KeyName:   cmKeyNode.Value,
							}
							for _, det := range detectorList {
								for _, m := range det.Detect(cmValNode.Value, scanCtx) {
									findings = append(findings, detectors.NewFinding(m, scanCtx))
								}
							}
						}
					}
					continue
				}

				var nextPath string
				if currentPath == "" {
					nextPath = keyName
				} else {
					nextPath = currentPath + "." + keyName
				}

				walkNode(vNode, nextPath, keyName)
			}

		case yaml.SequenceNode:
			// Detect container env arrays
			if parentKey == "env" {
				for idx, item := range node.Content {
					if item.Kind == yaml.MappingNode {
						var envName, envVal string
						var valNode *yaml.Node
						for e := 0; e < len(item.Content)-1; e += 2 {
							if item.Content[e].Value == "name" {
								envName = item.Content[e+1].Value
							} else if item.Content[e].Value == "value" {
								envVal = item.Content[e+1].Value
								valNode = item.Content[e+1]
							}
						}
						if envName != "" && envVal != "" && valNode != nil {
							envPath := fmt.Sprintf("%s[%d].value", currentPath, idx)
							scanCtx := detectors.ScanContext{
								File:      filePath,
								Resource:  meta.Name,
								Kind:      meta.Kind,
								FieldPath: envPath,
								Line:      valNode.Line,
								Column:    valNode.Column,
								KeyName:   envName,
							}
							for _, det := range detectorList {
								for _, m := range det.Detect(envVal, scanCtx) {
									findings = append(findings, detectors.NewFinding(m, scanCtx))
								}
							}
						}
					}
				}
			} else {
				for idx, item := range node.Content {
					elemPath := fmt.Sprintf("%s[%d]", currentPath, idx)
					walkNode(item, elemPath, parentKey)
				}
			}

		case yaml.ScalarNode:
			// Only scan generic scalars if key indicates sensitive context or if JWT detector matches
			if isSensitiveKey(parentKey) {
				scanCtx := detectors.ScanContext{
					File:      filePath,
					Resource:  meta.Name,
					Kind:      meta.Kind,
					FieldPath: currentPath,
					Line:      node.Line,
					Column:    node.Column,
					KeyName:   parentKey,
				}
				for _, det := range detectorList {
					for _, m := range det.Detect(node.Value, scanCtx) {
						findings = append(findings, detectors.NewFinding(m, scanCtx))
					}
				}
			} else {
				// JWT can be checked on any scalar
				jwtDet := detectors.NewJWTDetector()
				scanCtx := detectors.ScanContext{
					File:      filePath,
					Resource:  meta.Name,
					Kind:      meta.Kind,
					FieldPath: currentPath,
					Line:      node.Line,
					Column:    node.Column,
					KeyName:   parentKey,
				}
				for _, m := range jwtDet.Detect(node.Value, scanCtx) {
					findings = append(findings, detectors.NewFinding(m, scanCtx))
				}
			}
		}
	}

	walkNode(rootNode, "", "")
	return findings, scanErrors
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	return strings.Contains(lower, "pass") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "auth") ||
		strings.Contains(lower, "credential") ||
		strings.Contains(lower, "private_key") ||
		strings.Contains(lower, "key")
}
