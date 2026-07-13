package verifier_test

// Regression test for the attenuation bypass found in adversarial review
// (docs/THREAT-MODEL.md §4.2): a delegated CT that DROPS a ceiling/equality
// dimension leaves that axis unconstrained at transaction time unless the
// verifier enforces the chain INTERSECTION rather than the leaf scope alone.
//
// Each case builds human -> agent A (max_amount 8000) -> sub-agent B, where B
// drops a dimension, then presents an out-of-bounds transaction. The verifier
// MUST deny at step 7 (scope), because the effective ceiling is inherited from
// an ancestor the leaf tried to shed.

import (
	"context"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

func (a *agenticChain) delegateB(t *testing.T, scope tbac.Scope) *cttoken.CT {
	t.Helper()
	ct, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issCTA, ParentCT: a.ctA.Token, ParentIssuerKey: keyOf(t, a.reg, issCT),
		RequestedScope:  scope,
		HolderPublicKey: a.agentBPub,
	}, a.ctaPriv)
	if err != nil {
		t.Fatalf("delegate CT_B with scope %v: %v", scope, err)
	}
	return ct
}

// TestAttenuation_DroppedCeilingCannotWiden: CT_B drops max_amount entirely.
// The transaction (1,000,000) is far above the inherited 8000 ceiling and MUST
// be denied — dropping the dimension is not attenuation.
func TestAttenuation_DroppedCeilingCannotWiden(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"currency": "USD"}) // max_amount dropped

	tc := paymentTxn("1000000")
	txn, proof := a.txnFor(t, ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if d.Allow {
		t.Fatal("BYPASS: dropped-ceiling leaf allowed an over-limit transaction")
	}
	if d.Step != 7 {
		t.Fatalf("expected deny at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

// TestAttenuation_DroppedCeilingStillHonoursInheritedLimit: same dropped-ceiling
// leaf, but a transaction WITHIN the inherited 8000 ceiling must still be
// allowed — the fix must not over-deny legitimate traffic.
func TestAttenuation_DroppedCeilingStillHonoursInheritedLimit(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"currency": "USD"})

	tc := paymentTxn("6000") // ≤ inherited 8000
	txn, proof := a.txnFor(t, ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if !d.Allow {
		t.Fatalf("in-bounds transaction under inherited ceiling denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

// TestAttenuation_DroppedCurrencyCannotWiden: CT_B keeps a (higher) amount
// ceiling but drops currency; a transaction in a different currency must be
// denied against the inherited currency=USD constraint.
func TestAttenuation_DroppedCurrencyCannotWiden(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"max_amount": 5000}) // currency dropped

	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "1000", Currency: "EUR", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, proof := a.txnFor(t, ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if d.Allow {
		t.Fatal("BYPASS: dropped-currency leaf allowed an off-currency transaction")
	}
	if d.Step != 7 {
		t.Fatalf("expected deny at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}
