package cattoken_test

// P4: sealing an attested-workload identity into a CAT (spec §4).

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

func kp(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestCAT_SealsAttestation(t *testing.T) {
	issPub, issPriv := kp(t)
	holderPub, _ := kp(t)

	att := attest.Identity{
		Method:         attest.MethodSPIFFEJWTSVID,
		Subject:        "spiffe://prod.example/ns/pay/sa/charger",
		TrustDomain:    "prod.example",
		EvidenceDigest: "abc123",
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "workload:charger", PrincipalName: "charger",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 5000, "currency": "USD"},
		DelegationDepthMax: 2, TTL: 5 * time.Minute, HolderPublicKey: holderPub,
		Attestation: att.SealClaim(),
	}, issPriv)
	if err != nil {
		t.Fatalf("issue attested CAT: %v", err)
	}
	seal, ok := cat.Claims["spt_attestation"].(map[string]any)
	if !ok {
		t.Fatal("spt_attestation not sealed into CAT")
	}
	if seal["evidence_digest"] != "abc123" || seal["subject"] != att.Subject {
		t.Fatalf("bad seal %v", seal)
	}
	// The seal is inside the signature: verifying the CAT returns it intact.
	claims, err := cattoken.Verify(cat.Token, issPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, ok := claims["spt_attestation"].(map[string]any); !ok {
		t.Fatal("sealed attestation not covered by signature / not returned on verify")
	}
}

// TestCAT_RejectsTokenOutlivingAttestation: a CAT TTL beyond the attestation's
// own expiry must be rejected — you cannot outlive the proof you were minted on.
func TestCAT_RejectsTokenOutlivingAttestation(t *testing.T) {
	_, issPriv := kp(t)
	holderPub, _ := kp(t)

	att := attest.Identity{
		Method:    attest.MethodK8sSA,
		Subject:   "system:serviceaccount:pay:charger",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Minute), // short-lived proof
	}
	_, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "workload:charger", PrincipalName: "charger",
		Scope:              cattoken.CapabilityScope{"max_amount": 100},
		DelegationDepthMax: 1, TTL: time.Hour, // outlives the 1-min attestation
		HolderPublicKey: holderPub,
		Attestation:     att.SealClaim(),
	}, issPriv)
	if err == nil {
		t.Fatal("CAT outliving its sealed attestation was issued")
	}
}
