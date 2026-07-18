package zkdidmock_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/zkdidmock"
)

func newProvider(t *testing.T) (*zkdidmock.MockProvider, ed25519.PublicKey) {
	t.Helper()
	p, pub, err := zkdidmock.NewMockProvider()
	if err != nil {
		t.Fatal(err)
	}
	return p, pub
}

// The core .zkdid property SPT-Txn needs: a nullifier that is STABLE per
// (subject, context) — for per-context Sybil detection — but UNLINKABLE across
// contexts, and a fresh anchor per issuance.
func TestNullifier_StablePerContext_UnlinkableAcross(t *testing.T) {
	p, _ := newProvider(t)
	if err := p.Enroll("alice"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	a1, err := p.Resolve(ctx, "alice", "bank-A")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := p.Resolve(ctx, "alice", "bank-A") // same subject, same context, again
	if err != nil {
		t.Fatal(err)
	}
	a3, err := p.Resolve(ctx, "alice", "bank-B") // same subject, DIFFERENT context
	if err != nil {
		t.Fatal(err)
	}

	// Stable within a context → the same human re-appearing in bank-A is detectable.
	if a1.Nullifier != a2.Nullifier {
		t.Fatal("nullifier not stable per (subject, context) — Sybil detection would fail")
	}
	// Unlinkable across contexts → bank-A and bank-B cannot correlate the person.
	if a1.Nullifier == a3.Nullifier {
		t.Fatal("nullifier identical across contexts — cross-context linkability")
	}
	// Anchor is fresh every issuance → tokens unlinkable even within one context.
	if a1.Anchor == a2.Anchor {
		t.Fatal("anchor not freshly randomized per issuance")
	}
}

func TestNullifier_DistinctSubjects(t *testing.T) {
	p, _ := newProvider(t)
	_ = p.Enroll("alice")
	_ = p.Enroll("bob")
	a, _ := p.Resolve(context.Background(), "alice", "bank-A")
	b, _ := p.Resolve(context.Background(), "bob", "bank-A")
	if a.Nullifier == b.Nullifier {
		t.Fatal("distinct subjects produced the same nullifier in the same context")
	}
}

func TestResolve_FailsClosed(t *testing.T) {
	p, _ := newProvider(t)
	if _, err := p.Resolve(context.Background(), "nobody", "bank-A"); err == nil {
		t.Fatal("unenrolled subject resolved")
	}
	_ = p.Enroll("alice")
	if _, err := p.Resolve(context.Background(), "alice", ""); err == nil {
		t.Fatal("empty context accepted")
	}
}

func TestVerifyAssertion(t *testing.T) {
	p, pub := newProvider(t)
	_ = p.Enroll("alice")
	a, err := p.Resolve(context.Background(), "alice", "bank-A")
	if err != nil {
		t.Fatal(err)
	}

	if err := zkdidmock.VerifyAssertion(a, pub); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}

	// Wrong authority key.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := zkdidmock.VerifyAssertion(a, otherPub); err == nil {
		t.Fatal("assertion verified under wrong authority key")
	}

	// Tamper with each bound field — the proof must reject.
	mutate := []func(x *zkdidmock.Assertion){
		func(x *zkdidmock.Assertion) { x.Anchor[0] ^= 1 },
		func(x *zkdidmock.Assertion) { x.Nullifier[0] ^= 1 },
		func(x *zkdidmock.Assertion) { x.Context = "bank-B" },
		func(x *zkdidmock.Assertion) { x.IssuedAt = x.IssuedAt.Add(time.Second) },
		func(x *zkdidmock.Assertion) { x.Method = "real-zkdid" },
	}
	for i, mut := range mutate {
		cp := *a
		cp.Proof = append([]byte(nil), a.Proof...)
		mut(&cp)
		if err := zkdidmock.VerifyAssertion(&cp, pub); err == nil {
			t.Fatalf("mutation %d: tampered assertion verified", i)
		}
	}
}

// The seam end to end: a mock .zkdid anchor is sealed as the CAT humanAnchor and
// the CAT verifies carrying exactly that anchor. This is the single place a real
// .zkdid would plug in — swap the provider, the issuance code is unchanged.
func TestSealsMockAnchorIntoCAT(t *testing.T) {
	p, pub := newProvider(t)
	_ = p.Enroll("alice")
	assertion, err := p.Resolve(context.Background(), "alice", "bank-A")
	if err != nil {
		t.Fatal(err)
	}
	if err := zkdidmock.VerifyAssertion(assertion, pub); err != nil {
		t.Fatalf("assertion invalid: %v", err)
	}

	issPub, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 2, TTL: time.Hour, HolderPublicKey: holderPub,
		IdentityAnchor: assertion.Anchor.Bytes(), // ← the .zkdid seam
	}, issPriv)
	if err != nil {
		t.Fatalf("issue CAT with mock anchor: %v", err)
	}

	// The CAT's humanAnchor IS the mock provider's anchor, not a derived one.
	if cat.HumanAnchor != assertion.Anchor {
		t.Fatalf("CAT humanAnchor %s != mock anchor %s", cat.HumanAnchor, assertion.Anchor)
	}
	claims, err := cattoken.Verify(cat.Token, issPub)
	if err != nil {
		t.Fatalf("verify CAT: %v", err)
	}
	if claims["human_anchor"] != assertion.Anchor.String() {
		t.Fatal("verified CAT does not carry the mock anchor")
	}

	// A bad-length anchor is rejected (the seam is strict).
	if _, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: cattoken.CapabilityScope{"max_amount": 1}, DelegationDepthMax: 1,
		TTL: time.Hour, HolderPublicKey: holderPub, IdentityAnchor: []byte("too-short"),
	}, issPriv); err == nil {
		t.Fatal("CAT issued with a malformed identity anchor")
	}
}
