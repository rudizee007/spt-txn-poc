// Package attest verifies attested non-human (workload) identities and turns
// them into a sealed, transaction-scoped authorization grant — SPT-Txn P4
// (NHI attested issuance). Spec: docs/spec/NHI-ATTESTED-ISSUANCE.md.
//
// The market inventories secrets; SPIFFE gives workloads names; this package
// closes the last mile — per-action authorization conditioned on *attestation
// state*. A workload presents an attested identity (SPIFFE JWT/X.509-SVID, a
// Kubernetes projected ServiceAccount token, or a cloud workload-identity
// OIDC assertion); we verify it against the trust domain's keys (never the
// workload's self-report), and produce an Identity whose evidence digest gets
// sealed into the issued token.
//
// Scope boundary (CLAUDE.md §0): this covers runtime workload identity and
// attestation freshness ONLY. It does NOT condition on build provenance
// (SLSA/SBOM) — that is separate, unpublished work and must not appear here.
//
// Memory-safe standard library only: crypto/rsa, crypto/ed25519, crypto/x509.
// No cgo, no custom crypto.
package attest

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Method enumerates the attested-identity ingress types (spec §2).
type Method string

const (
	MethodSPIFFEJWTSVID  Method = "spiffe-jwt-svid"
	MethodSPIFFEX509SVID Method = "spiffe-x509-svid"
	MethodK8sSA          Method = "k8s-sa"
	MethodAWSIRSA        Method = "aws-irsa"
	MethodGCPWIF         Method = "gcp-wif"
	MethodAzureFC        Method = "azure-fc"
	MethodOIDC           Method = "oidc"
)

// evidenceTag domain-separates attestation evidence digests from every other
// SHA-256 use in the system.
const evidenceTag = "spt-txn-attest-v1"

// Common errors. Verification failures are deliberately coarse to the caller;
// the wrapped detail is for logs/receipts, not the wire.
var (
	ErrMalformed   = errors.New("attest: malformed assertion")
	ErrAlg         = errors.New("attest: algorithm not allowed (RS256/EdDSA only; alg:none rejected)")
	ErrIssuer      = errors.New("attest: issuer / trust-domain mismatch")
	ErrAudience    = errors.New("attest: audience mismatch")
	ErrExpired     = errors.New("attest: assertion expired")
	ErrNotYetValid = errors.New("attest: assertion not yet valid (nbf)")
	ErrSubject     = errors.New("attest: subject not a valid SPIFFE ID")
	ErrSignature   = errors.New("attest: signature verification failed")
	ErrStale       = errors.New("attest: attestation older than the freshness predicate allows")
	ErrKey         = errors.New("attest: no usable verification key")
)

// Identity is a verified attested workload identity.
type Identity struct {
	Method      Method
	Subject     string   // spiffe:// URI, or OIDC sub / system:serviceaccount:...
	TrustDomain string   // SPIFFE trust domain, or OIDC issuer
	Audience    []string // audience the assertion was bound to
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	// EvidenceDigest is base64url(SHA-256(tag || 0x00 || presented-evidence)).
	// Sealed into the issued token; the raw evidence is never carried onward.
	EvidenceDigest string
	// Claims is the verified claim set (JWT methods) for policy inspection.
	// Never contains secret material.
	Claims map[string]any
}

// Age returns how long ago the attestation was issued, relative to now.
func (id Identity) Age(now time.Time) time.Duration { return now.Sub(id.IssuedAt) }

// SealClaim renders the attestation seal to embed as the token's
// spt_attestation claim (spec §4). Hashes and enums only — no raw evidence.
func (id Identity) SealClaim() map[string]any {
	return map[string]any{
		"method":          string(id.Method),
		"subject":         id.Subject,
		"trust_domain":    id.TrustDomain,
		"evidence_digest": id.EvidenceDigest,
		"iat":             id.IssuedAt.Unix(),
		"exp":             id.ExpiresAt.Unix(),
	}
}

// evidenceDigest computes the domain-separated digest over presented evidence.
func evidenceDigest(evidence []byte) string {
	h := sha256.New()
	h.Write([]byte(evidenceTag))
	h.Write([]byte{0x00})
	h.Write(evidence)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ── Freshness predicates (spec §5) ──────────────────────────────────────

// Freshness is a max-age predicate. The zero value (MaxAge <= 0) imposes no
// freshness requirement.
type Freshness struct {
	MaxAge time.Duration
}

// Check reports ErrStale when the identity's attestation is older than MaxAge.
// A future-dated iat (age < 0) beyond a small skew is also rejected as
// malformed — an attestation cannot be issued in the future.
func (f Freshness) Check(id Identity, now time.Time) error {
	if f.MaxAge <= 0 {
		return nil
	}
	age := id.Age(now)
	if age < -clockSkew {
		return fmt.Errorf("%w: attestation iat is in the future by %s", ErrMalformed, (-age).String())
	}
	if age > f.MaxAge {
		return fmt.Errorf("%w: age %s > max %s", ErrStale, age.Truncate(time.Second), f.MaxAge)
	}
	return nil
}

// clockSkew is the tolerated clock difference for freshness/temporal checks.
const clockSkew = 30 * time.Second
