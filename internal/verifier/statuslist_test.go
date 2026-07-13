package verifier_test

// End-to-end status-list revocation through the eight-step verifier: a leaf CT
// bound to a Token Status List entry is denied once that entry is flipped to
// INVALID, while an unrevoked entry still verifies. Spec docs/spec/STATUS-LIST.md.

import (
	"context"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

const slURI = "https://domain-a.authorg/statuslists/1"

// buildStatusChain builds CAT -> CT(status idx) and wires a resolver with a
// signed status list. leafIdx is the CT's status-list index.
func buildStatusChain(t *testing.T, leafIdx int, setStatus statuslist.Status) (*verifier.Engine, verifier.Input, ledger.TxnContext) {
	t.Helper()
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	ctPub, ctPriv := genKey(t)
	ttsPub, ttsPriv := genKey(t)
	agentPub, agentPriv := genKey(t)
	slPub, slPriv := genKey(t)

	register(t, reg, issCT, trustregistry.RoleCTIssuer, ctPub)
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 2, TTL: time.Hour, HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub,
		Status:          map[string]any{"status_list": map[string]any{"idx": leafIdx, "uri": slURI}},
	}, ctPriv)
	if err != nil {
		t.Fatal(err)
	}

	l, _ := ledger.Get("xrpl")
	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "4000", Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: agentPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.Proof(agentPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}

	// Status list: 1024 entries, flip leafIdx to setStatus, sign, resolve.
	sl, _ := statuslist.New(2, 1024)
	if err := sl.Set(leafIdx, setStatus); err != nil {
		t.Fatal(err)
	}
	slTok, err := statuslist.SignToken(sl, slURI, time.Now(), time.Hour, slPriv)
	if err != nil {
		t.Fatal(err)
	}
	res := statuslist.NewResolver()
	if err := res.AddVerified(slTok, slURI, slPub, time.Now()); err != nil {
		t.Fatal(err)
	}

	eng := verifier.New(reg)
	eng.StatusResolver = res
	in := verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ct.Token}, CAT: cat.Token, Txn: tc, Audience: aud,
	}
	return eng, in, tc
}

func TestStatusList_ValidEntryAllows(t *testing.T) {
	eng, in, _ := buildStatusChain(t, 500, statuslist.StatusValid)
	d := eng.Verify(context.Background(), in)
	if !d.Allow {
		t.Fatalf("valid status entry denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

func TestStatusList_RevokedEntryDeniedAtChain(t *testing.T) {
	eng, in, _ := buildStatusChain(t, 500, statuslist.StatusInvalid)
	d := eng.Verify(context.Background(), in)
	if d.Allow {
		t.Fatal("revoked CT (status INVALID) was allowed")
	}
	if d.Step != 6 {
		t.Fatalf("expected deny at step 6 (chain status), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

func TestStatusList_SuspendedEntryDenied(t *testing.T) {
	eng, in, _ := buildStatusChain(t, 7, statuslist.StatusSuspended)
	d := eng.Verify(context.Background(), in)
	if d.Allow {
		t.Fatal("suspended CT was allowed")
	}
}

// TestStatusList_UnavailableFailsClosed: a token references a list the resolver
// doesn't hold ⇒ deny (never allow on an unresolvable list).
func TestStatusList_UnavailableFailsClosed(t *testing.T) {
	eng, in, _ := buildStatusChain(t, 500, statuslist.StatusValid)
	eng.StatusResolver = statuslist.NewResolver() // empty: list not cached
	d := eng.Verify(context.Background(), in)
	if d.Allow {
		t.Fatal("unresolvable status list allowed the token (fail-open)")
	}
}

// TestStatusList_DisabledWhenNoResolver: without a resolver, a status-bearing
// token verifies as before (no regression, no accidental hard dependency).
func TestStatusList_DisabledWhenNoResolver(t *testing.T) {
	eng, in, _ := buildStatusChain(t, 500, statuslist.StatusInvalid)
	eng.StatusResolver = nil // disabled
	d := eng.Verify(context.Background(), in)
	if !d.Allow {
		t.Fatalf("status checking not disabled with nil resolver: step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}
