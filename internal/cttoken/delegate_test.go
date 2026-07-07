package cttoken_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// TestDelegate_NarrowsAndDecrements is the core CT->CT case: agent A delegates a
// strictly narrower capability to sub-agent B. Scope must attenuate, depth must
// decrement by one, the humanAnchor and root CAT reference must propagate
// unchanged, and the child must name its immediate parent.
func TestDelegate_NarrowsAndDecrements(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderA, _ := keypair(t)
	holderB, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderA,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"}, 3)

	// Hop 1: CAT -> CT_A (remaining 2).
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: holderA,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT_A: %v", err)
	}

	// Hop 2: CT_A -> CT_B (remaining 1), bound to sub-agent B.
	ctB, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        ctA.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: holderB,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("delegate CT_B: %v", err)
	}

	if ctB.Claims["txn_token_type"] != "CT" {
		t.Errorf("txn_token_type = %v, want CT", ctB.Claims["txn_token_type"])
	}
	// Depth decremented from CT_A's remaining (2) to 1.
	if ctB.Claims["delegation_depth_remaining"] != 1 {
		t.Errorf("delegation_depth_remaining = %v, want 1", ctB.Claims["delegation_depth_remaining"])
	}
	// humanAnchor propagated unchanged.
	if ctB.HumanAnchor != cat.HumanAnchor.String() {
		t.Errorf("humanAnchor not propagated: got %s want %s", ctB.HumanAnchor, cat.HumanAnchor.String())
	}
	// Immediate-parent reference is CT_A; root CAT reference is propagated.
	if ctB.Claims["spt_parent_ref"] != ctA.Claims["jti"] {
		t.Errorf("spt_parent_ref = %v, want CT_A jti %v", ctB.Claims["spt_parent_ref"], ctA.Claims["jti"])
	}
	if ctB.Claims["spt_cat_ref"] != cat.Claims["jti"] {
		t.Errorf("spt_cat_ref = %v, want root CAT jti %v", ctB.Claims["spt_cat_ref"], cat.Claims["jti"])
	}
	// Child verifies under the delegating issuer key.
	if _, err := cttoken.Verify(ctB.Token, issuerPub); err != nil {
		t.Errorf("delegated CT must verify: %v", err)
	}
}

// TestDelegate_RejectsWidening confirms a sub-agent cannot be handed more than
// its delegator holds — the foundational least-authority guarantee.
func TestDelegate_RejectsWidening(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderA, _ := keypair(t)
	holderB, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderA,
		cattoken.CapabilityScope{"max_amount": 10000, "currency": "USD"}, 3)
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: holderA,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT_A: %v", err)
	}

	_, err = cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        ctA.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 9000, "currency": "USD"}, // exceeds CT_A's 8000
		HolderPublicKey: holderB,
	}, issuerPriv)
	if err == nil {
		t.Fatal("delegating a scope wider than the parent CT must be rejected")
	}
}

// TestDelegate_DepthExhaustion confirms the delegation depth bound is enforced:
// once a CT's remaining depth reaches zero, it cannot delegate further.
func TestDelegate_DepthExhaustion(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderA, _ := keypair(t)
	holderB, _ := keypair(t)

	// depth 1 -> CT_A remaining 0, the last permitted hop.
	cat := issueParentCAT(t, issuerPriv, holderA,
		cattoken.CapabilityScope{"max_amount": 100, "currency": "USD"}, 1)
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 100, "currency": "USD"},
		HolderPublicKey: holderA,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT_A: %v", err)
	}
	if ctA.Claims["delegation_depth_remaining"] != 0 {
		t.Fatalf("CT_A remaining = %v, want 0", ctA.Claims["delegation_depth_remaining"])
	}

	_, err = cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        ctA.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 100, "currency": "USD"},
		HolderPublicKey: holderB,
	}, issuerPriv)
	if err == nil {
		t.Fatal("delegating from a depth-exhausted CT (remaining 0) must be rejected")
	}
}
