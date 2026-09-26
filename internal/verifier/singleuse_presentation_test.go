package verifier_test

// End to end: a DPoP proof's record is scoped to the key that signed the proof.
// A proof under another key with the same jti is refused at step 5, and the
// presentation is then still allowed. scripts/mutate-single-use-records.sh
// requires this test to fail under mutation R-H.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// proofWithJTI builds a DPoP proof the way dpop.Proof does, with the jti given.
func proofWithJTI(t *testing.T, priv ed25519.PrivateKey, token, jti string) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	header := map[string]any{"typ": "dpop+jwt", "alg": "EdDSA",
		"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}}
	claims := map[string]any{"jti": jti, "htm": htm, "htu": htu, "iat": time.Now().Unix(), "ath": dpop.ATH(token)}
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

// proofJTI returns the jti claim of a compact DPoP proof.
func proofJTI(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.JTI == "" {
		t.Fatal("proof has no jti")
	}
	return claims.JTI
}

// checkProofRecordScopedToKey presents in's SPT-Txn with a proof under another
// key carrying in's proof jti, requires it to be refused at step 5, and then
// requires in to be allowed.
func checkProofRecordScopedToKey(t *testing.T, eng *verifier.Engine, in verifier.Input) {
	t.Helper()
	_, otherPriv := genKey(t)
	other := in
	other.DPoPProof = proofWithJTI(t, otherPriv, in.TxnToken, proofJTI(t, in.DPoPProof))
	if d := eng.Verify(context.Background(), other); d.Allow || d.Step != 5 {
		t.Fatalf("a proof is refused at step 5 unless its record is scoped to the signing key: allow=%v step=%d: %s",
			d.Allow, d.Step, d.Reason)
	}
	if d := eng.Verify(context.Background(), in); !d.Allow {
		t.Fatalf("after a proof under another key with the same jti, the presentation was refused at step %d: %s",
			d.Step, d.Reason)
	}
}

// TestSingleUse_ProofRecordsAreScopedToTheSigningKey: for a plain SPT-Txn and
// for one spent against a committed sub-band slice.
func TestSingleUse_ProofRecordsAreScopedToTheSigningKey(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		h := build(t)
		checkProofRecordScopedToKey(t, h.eng, h.in)
	})
	t.Run("sub-band slice", func(t *testing.T) {
		w := buildBudgetWorld(t, true)
		slices := w.slices(t)
		checkProofRecordScopedToKey(t, w.eng, w.mintTxn(t, slices[0].Token, "10"))
	})
}
