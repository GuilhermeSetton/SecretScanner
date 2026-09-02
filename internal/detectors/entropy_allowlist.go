// internal/detectors/entropy_allowlist.go
package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// Decoding the aligned head of a token is enough to see a PEM header
	// (27 bytes) without decoding megabyte-sized certificate bodies.
	base64PeekChars    = 64
	base64MinPeekChars = 40
)

// Format validation and allowlisting applied before an entropy match is reported.
//
// Shannon entropy alone cannot tell a credential apart from any other dense
// string: public keys, certificates, signed URLs and secret-manager references
// all score above the default threshold of 4.5 while carrying no secret at all.
// The checks below recognize those shapes explicitly so the entropy detector
// stays an auxiliary heuristic instead of a source of noise.
//
// Every rule here suppresses the entropy detector only. Specific pattern rules
// (AWS keys, SSH private keys, JWTs, custom rules) are unaffected, so a real
// credential embedded in an allowlisted shape is still reported by its own rule.
var (
	// Public key material carries no secret, but scores high on entropy.
	pemPublicBlockRegex  = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?(?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST)-----`)
	pemPrivateBlockRegex = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	sshPublicKeyRegex    = regexp.MustCompile(`^(?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\s`)

	// Wire format of an SSH public key: a 4-byte length prefix followed by the
	// algorithm name, which makes these base64 prefixes stable. The blob decodes
	// to binary, so it cannot be recognized by decoding it back to text.
	base64SSHPublicPrefixes = []string{
		"AAAAB3NzaC1yc2E",             // ssh-rsa
		"AAAAC3NzaC1lZDI1NTE5",        // ssh-ed25519
		"AAAAE2VjZHNhLXNoYTItbmlzdHA", // ecdsa-sha2-nistp
	}

	// Pointers to a secret held elsewhere are not the secret itself.
	secretReferenceRegex = regexp.MustCompile(`^(?:` +
		`arn:aws(?:-[a-z]+)*:` + // AWS ARNs, including Secrets Manager references
		`|vault:` +
		`|projects/[^/]+/secrets/` + // GCP Secret Manager resource names
		`|(?:awssm|gcpsm|azurekeyvault|akeyless|sops|k8s)://` +
		`)`)

	// A URL is a location, not a credential -- unless it embeds one.
	urlSchemeRegex   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)
	urlUserInfoRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/@\s]*:[^/@\s]+@`)

	// crypt(3) and PHC-style password hashes: derived material, not a usable credential.
	cryptHashRegex = regexp.MustCompile(`^\$(?:1|2[abxy]?|5|6|7|y|md5|sha1|argon2(?:i|d|id)?|scrypt|pbkdf2(?:-[a-z0-9]+)?)\$`)

	// Data URIs are inline payloads, usually icons or certificates.
	dataURIRegex = regexp.MustCompile(`^data:[a-zA-Z0-9.+\-]+/`)

	// Unresolved templating: the real value is injected at deploy time.
	templatePlaceholderRegex = regexp.MustCompile(`\{\{|\}\}|\$\{|\$\(|^<[^>]+>$`)

	// Matched on word boundaries only. Substring matching would suppress real
	// credentials that merely happen to contain one of these fragments, and the
	// AWS documentation keys used in the fixtures are a reminder of how easily
	// a word like "example" shows up inside an actual key.
	placeholderWordRegex = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:` +
		`change[-_]?me` +
		`|replace[-_]?me` +
		`|placeholder` +
		`|redacted` +
		`|not[-_]?a[-_]?secret` +
		`|fixme` +
		`|dummy[-_](?:value|secret|token|password|key)` +
		`|your[-_](?:secret|password|token|key)` +
		`)(?:[^a-z0-9]|$)`)
)

// isPublicKeyMaterial reports whether the whole field value is public key or
// certificate material. It is evaluated on the complete value rather than on a
// single token because PEM blocks span many lines.
func isPublicKeyMaterial(value string) bool {
	trimmed := strings.TrimSpace(value)
	if sshPublicKeyRegex.MatchString(trimmed) {
		return true
	}
	// A bundle holding a private key is never allowlisted, even when a public
	// certificate sits next to it in the same field.
	if pemPublicBlockRegex.MatchString(trimmed) && !pemPrivateBlockRegex.MatchString(trimmed) {
		return true
	}
	return false
}

// isTemplateExpression reports whether the whole field value is an unresolved
// templating expression. It is checked on the value because tokenization splits
// `{{ .Values.password }}` into three tokens, leaving the middle one bare.
func isTemplateExpression(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	switch {
	case strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}"):
		return true
	case strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}"):
		return true
	case strings.HasPrefix(trimmed, "$(") && strings.HasSuffix(trimmed, ")"):
		return true
	case strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && !strings.Contains(trimmed, " "):
		return true
	}
	return false
}

// isNonSecretValue reports whether the whole field value is a shape that never
// holds a credential. It complements isKnownNonSecretToken for values that
// tokenization would break apart: PEM blocks span lines, and both PHC hashes and
// data URIs contain commas, which are token separators.
func isNonSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return isPublicKeyMaterial(trimmed) ||
		isTemplateExpression(trimmed) ||
		cryptHashRegex.MatchString(trimmed) ||
		dataURIRegex.MatchString(trimmed)
}

// isKnownNonSecretToken reports whether a single high-entropy token has a shape
// that is known not to be a credential.
func isKnownNonSecretToken(token string) bool {
	for _, prefix := range base64SSHPublicPrefixes {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}

	if decodesToPublicKeyMaterial(token) {
		return true
	}

	if secretReferenceRegex.MatchString(token) {
		return true
	}

	// URLs are suppressed unless they carry credentials in the userinfo part.
	if urlSchemeRegex.MatchString(token) && !urlUserInfoRegex.MatchString(token) {
		return true
	}

	if cryptHashRegex.MatchString(token) {
		return true
	}

	if dataURIRegex.MatchString(token) {
		return true
	}

	if templatePlaceholderRegex.MatchString(token) {
		return true
	}

	return placeholderWordRegex.MatchString(token)
}

// decodesToPublicKeyMaterial reports whether a base64 token decodes to a public
// PEM header. Only the aligned head of the token is decoded, so the check also
// works on values that were truncated or wrapped elsewhere. Private key material
// is deliberately not recognized here: it must keep being reported.
func decodesToPublicKeyMaterial(token string) bool {
	prefixLen := len(token) - len(token)%4
	if prefixLen > base64PeekChars {
		prefixLen = base64PeekChars
	}
	if prefixLen < base64MinPeekChars {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(token[:prefixLen])
	if err != nil || !utf8.Valid(decoded) {
		return false
	}

	text := string(decoded)
	return pemPublicBlockRegex.MatchString(text) || sshPublicKeyRegex.MatchString(text)
}

// compileAllowlist compiles user-supplied allowlist patterns, discarding the
// ones that are not valid regular expressions. Callers that can surface an
// error to the user (the CLI) are expected to validate the patterns first.
func compileAllowlist(patterns []string) []*regexp.Regexp {
	if len(patterns) == 0 {
		return nil
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}
