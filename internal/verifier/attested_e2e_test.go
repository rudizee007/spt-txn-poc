package verifier_test

// Full P4 path end to end: an attested SPIFFE JWT-SVID is verified, sealed into
// a CAT, delegated to a sub-agent CT, used to mint a transaction token, and
// verified through the eight-step engine — proving attested-workload identity
// flows all the way to an offline authorization decision with the attestation
// evidence sealed and carried.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintSVID builds a signed SPIFFE JWT-SVID for the test trust domain.
func mintSVID(t *testing.T, kid string, priv ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"sub": "spiffe://prod.example/ns/pay/sa/charger",
		"aud": []string{"spt-txn-exchange"},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	signingInput := b64url(hdr) + "." + b64url(claims)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64url(sig)
}

func TestAttestedWorkload_EndToEnd(t *testing.T) {
	now := time.Now()

	// 1. Attest a SPIFFE JWT-SVID.
	svidPub, svidPriv, _ := ed25519.GenerateKey(nil)
	ks := attest.NewStaticKeySource(map[string]crypto.PublicKey{"k1": svidPub})
	svid := mintSVID(t, "k1", svidPriv, now)
	id, err := attest.VerifySPIFFEJWTSVID(context.Background(), svid, []string{"spt-txn-exchange"}, ks)
	if err != nil {
		t.Fatalf("SVID attestation failed: %v", err)
	}

	// 2. Registry + issuer keys.
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	ctPub, ctPriv := genKey(t)
	ttsPub, ttsPriv := genKey(t)
	agentPub, agentPriv := genKey(t)
	subPub, subPriv := genKey(t)
	register(t, reg, issCT, trustregistry.RoleCTIssuer, ctPub)
	register(t, reg, issCTA, trustregistry.RoleCTIssuer, ctPub) // same issuer signs the delegated hop here
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	// 3. Seal the attestation into a CAT (root authority for this workload).
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "workload:" + id.Subject, PrincipalName: id.Subject,
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: 4 * time.Minute, HolderPublicKey: agentPub,
		Attestation: id.SealClaim(),
	}, ctPriv)
	if err != nil {
		t.Fatalf("attested CAT issuance failed: %v", err)
	}
	// The attestation is sealed and signature-covered.
	if _, ok := cat.Claims["spt_attestation"].(map[string]any); !ok {
		t.Fatal("attestation not sealed into CAT")
	}

	// 4. CAT -> CT_A (agent), CT_A -> CT_B (sub-agent).
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CT_A: %v", err)
	}
	ctB, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issCTA, ParentCT: ctA.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: subPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CT_B delegate: %v", err)
	}
	_ = agentPriv

	// 5. Sub-agent mints a per-transaction token and it verifies.
	l, _ := ledger.Get("xrpl")
	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "3000", Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ctB.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: subPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		t.Fatalf("txn issue: %v", err)
	}
	proof, err := dpop.Proof(subPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}

	eng := verifier.New(reg)
	d := eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ctA.Token, ctB.Token}, CAT: cat.Token, Txn: tc, Audience: aud,
	})
	if !d.Allow {
		t.Fatalf("attested end-to-end chain denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
	_ = ttsPub
}
