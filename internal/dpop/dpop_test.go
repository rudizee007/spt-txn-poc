package dpop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
)

const verifyURL = "https://foss.violetskysecurity.com/b/verify"

func TestProofVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, err := dpop.Proof(priv, "POST", verifyURL, "")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	jkt, jti, err := dpop.Verify(proof, "POST", verifyURL, "", 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if jkt != dpop.Thumbprint(pub) {
		t.Error("returned thumbprint does not match the holder key thumbprint")
	}
	if jti == "" {
		t.Error("Verify must return the proof jti for replay tracking")
	}
}

func TestVerify_HTMMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "GET", "https://x/y", "", 0); err == nil {
		t.Error("htm mismatch must be rejected")
	}
}

func TestVerify_HTUMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "POST", "https://x/z", "", 0); err == nil {
		t.Error("htu mismatch must be rejected")
	}
}

func TestVerify_Expired(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "POST", "https://x/y", "", 1*time.Nanosecond); err == nil {
		t.Error("stale proof must be rejected")
	}
}

// ath binding: a proof carrying one token's hash must not verify against another.
func TestVerify_ATHBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	athA := dpop.ATH("token-A")
	proof, _ := dpop.Proof(priv, "POST", verifyURL, athA)

	if _, _, err := dpop.Verify(proof, "POST", verifyURL, athA, 0); err != nil {
		t.Errorf("proof should verify against its own token's ath: %v", err)
	}
	if _, _, err := dpop.Verify(proof, "POST", verifyURL, dpop.ATH("token-B"), 0); err == nil {
		t.Error("proof bound to token-A must not verify against token-B's ath")
	}
}

func TestThumbprint_Stable(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if dpop.Thumbprint(pub) != dpop.Thumbprint(pub) {
		t.Error("thumbprint must be stable for the same key")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if dpop.Thumbprint(pub) == dpop.Thumbprint(other) {
		t.Error("different keys must yield different thumbprints")
	}
}
