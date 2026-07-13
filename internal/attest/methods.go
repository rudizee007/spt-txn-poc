package attest

// methods.go — thin, well-labelled wrappers over VerifyJWT for each attested
// ingress type, plus a StaticKeySource for static trust bundles and tests.

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"time"
)

// StaticKeySource resolves keys from an in-memory bundle keyed by kid. Use it
// for a pinned trust bundle or in tests. An empty kid matches a single
// registered key only if exactly one is present (common for SPIFFE bundles
// that omit kid).
type StaticKeySource struct {
	keys map[string]crypto.PublicKey
}

// NewStaticKeySource builds a key source from a kid→key map.
func NewStaticKeySource(keys map[string]crypto.PublicKey) *StaticKeySource {
	cp := make(map[string]crypto.PublicKey, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &StaticKeySource{keys: cp}
}

// Key implements KeySource.
func (s *StaticKeySource) Key(_ context.Context, kid, _ string) (crypto.PublicKey, error) {
	if kid != "" {
		if k, ok := s.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("no key for kid %q", kid)
	}
	// No kid: accept only if the bundle is unambiguous.
	if len(s.keys) == 1 {
		for _, k := range s.keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no kid supplied and bundle is ambiguous (%d keys)", len(s.keys))
}

// VerifySPIFFEJWTSVID verifies a SPIFFE JWT-SVID. The subject MUST be a
// spiffe:// ID and the audience is REQUIRED (binds the SVID to this endpoint).
func VerifySPIFFEJWTSVID(ctx context.Context, token string, audiences []string, ks KeySource) (Identity, error) {
	if len(audiences) == 0 {
		return Identity{}, fmt.Errorf("%w: SPIFFE JWT-SVID requires an expected audience", ErrAudience)
	}
	return VerifyJWT(ctx, token, JWTConfig{
		Method:               MethodSPIFFEJWTSVID,
		Audiences:            audiences,
		RequireSPIFFESubject: true,
		RequireExpiry:        true,
	}, ks)
}

// VerifyK8sSAToken verifies a Kubernetes projected ServiceAccount token. The
// issuer is the cluster's OIDC issuer; audience is REQUIRED (the projected
// token's requested audience).
func VerifyK8sSAToken(ctx context.Context, token, issuer string, audiences []string, ks KeySource) (Identity, error) {
	if issuer == "" {
		return Identity{}, fmt.Errorf("%w: k8s issuer required", ErrIssuer)
	}
	if len(audiences) == 0 {
		return Identity{}, fmt.Errorf("%w: k8s SA token requires an expected audience", ErrAudience)
	}
	id, err := VerifyJWT(ctx, token, JWTConfig{
		Method:         MethodK8sSA,
		ExpectedIssuer: issuer,
		Audiences:      audiences,
		RequireExpiry:  true,
	}, ks)
	if err != nil {
		return Identity{}, err
	}
	// A well-formed SA subject is system:serviceaccount:<ns>:<name>; require it
	// so a generic OIDC token from the same issuer can't masquerade as an SA.
	if !strings.HasPrefix(id.Subject, "system:serviceaccount:") {
		return Identity{}, fmt.Errorf("%w: not a serviceaccount subject %q", ErrSubject, id.Subject)
	}
	return id, nil
}

// VerifyCloudWorkload verifies a cloud workload-identity OIDC assertion (AWS
// IRSA / GCP WIF / Azure federated credential / generic OIDC). Issuer and
// audience are REQUIRED for the federated methods.
func VerifyCloudWorkload(ctx context.Context, token string, method Method, issuer string, audiences []string, ks KeySource) (Identity, error) {
	switch method {
	case MethodAWSIRSA, MethodGCPWIF, MethodAzureFC, MethodOIDC:
	default:
		return Identity{}, fmt.Errorf("attest: %q is not a cloud workload method", method)
	}
	if issuer == "" {
		return Identity{}, fmt.Errorf("%w: cloud workload issuer required", ErrIssuer)
	}
	// Audience is required for ALL cloud/federation methods, generic OIDC
	// included: without it a workload assertion minted for another relying
	// party could be replayed at this exchange endpoint.
	if len(audiences) == 0 {
		return Identity{}, fmt.Errorf("%w: %s requires an expected audience", ErrAudience, method)
	}
	return VerifyJWT(ctx, token, JWTConfig{
		Method:         method,
		ExpectedIssuer: issuer,
		Audiences:      audiences,
		RequireExpiry:  true,
	}, ks)
}

// MethodFromTokenType maps an RFC 8693 subject_token_type URN to a Method.
// Unknown types are rejected (fail closed).
func MethodFromTokenType(urn string) (Method, error) {
	switch urn {
	case "urn:violetsky:token-type:spiffe-jwt-svid":
		return MethodSPIFFEJWTSVID, nil
	case "urn:violetsky:token-type:spiffe-x509-svid":
		return MethodSPIFFEX509SVID, nil
	case "urn:violetsky:token-type:k8s-sa":
		return MethodK8sSA, nil
	case "urn:violetsky:token-type:aws-irsa":
		return MethodAWSIRSA, nil
	case "urn:violetsky:token-type:gcp-wif":
		return MethodGCPWIF, nil
	case "urn:violetsky:token-type:azure-fc":
		return MethodAzureFC, nil
	case "urn:ietf:params:oauth:token-type:jwt", "urn:violetsky:token-type:oidc":
		return MethodOIDC, nil
	default:
		return "", fmt.Errorf("attest: unsupported subject_token_type %q", urn)
	}
}

// SealExpiryOK reports whether a token expiry does not exceed the attestation
// expiry (spec §4: a token must not outlive the proof it was minted on). now
// is accepted for symmetry with other temporal checks but not required.
func SealExpiryOK(tokenExp, attestationExp time.Time) bool {
	if attestationExp.IsZero() {
		return true // no attestation expiry to bound against
	}
	return !tokenExp.After(attestationExp)
}
