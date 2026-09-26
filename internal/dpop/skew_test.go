package dpop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/dpop"
)

const (
	skewTestHTM = "POST"
	skewTestHTU = "https://verifier.example/verify"
)

// proofIssuedAt builds a DPoP proof the way dpop.Proof does, with a chosen iat.
func proofIssuedAt(t *testing.T, priv ed25519.PrivateKey, iat int64) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	header := map[string]any{"typ": "dpop+jwt", "alg": "EdDSA",
		"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}}
	claims := map[string]any{"jti": "skew-test", "htm": skewTestHTM, "htu": skewTestHTU, "iat": iat}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

// TestVerify_IatBeyondMaxFutureSkewIsRefused: the forward tolerance Verify
// applies is MaxFutureSkew, which callers use to size replay records.
func TestVerify_IatBeyondMaxFutureSkewIsRefused(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skew := int64(dpop.MaxFutureSkew / time.Second)
	now := time.Now().Unix()
	if _, _, err := dpop.Verify(proofIssuedAt(t, priv, now+skew+2), skewTestHTM, skewTestHTU, "", 0); err == nil {
		t.Fatal("a proof whose iat is further ahead than MaxFutureSkew was accepted")
	}
	if _, _, err := dpop.Verify(proofIssuedAt(t, priv, now+skew-2), skewTestHTM, skewTestHTU, "", 0); err != nil {
		t.Fatalf("a proof whose iat is within MaxFutureSkew was refused: %v", err)
	}
}
