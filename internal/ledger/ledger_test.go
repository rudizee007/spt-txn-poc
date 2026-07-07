package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

func TestContextHash_Deterministic(t *testing.T) {
	tc := ledger.TxnContext{
		Chain:       "none",
		Originator:  "alice",
		Beneficiary: "bob",
		Amount:      "5000.00",
		Currency:    "USD",
		Timestamp:   1750000000,
		Extra:       map[string]string{"memo": "invoice-7", "ref": "abc"},
	}
	l, err := ledger.Get("none")
	if err != nil {
		t.Fatal(err)
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, h2, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
}

// TestContextHash_ExtraOrderIndependent confirms that Extra map iteration order
// does not change the hash (extras are sorted in canonicalization).
func TestContextHash_ExtraOrderIndependent(t *testing.T) {
	l, _ := ledger.Get("none")
	a := ledger.TxnContext{Beneficiary: "bob", Amount: "1", Currency: "USD",
		Extra: map[string]string{"a": "1", "b": "2", "c": "3"}}
	b := ledger.TxnContext{Beneficiary: "bob", Amount: "1", Currency: "USD",
		Extra: map[string]string{"c": "3", "b": "2", "a": "1"}}
	_, ha, _ := ledger.ContextHash(l, a)
	_, hb, _ := ledger.ContextHash(l, b)
	if ha != hb {
		t.Errorf("extra ordering changed the hash: %s != %s", ha, hb)
	}
}

func TestContextHash_AmountChangesHash(t *testing.T) {
	l, _ := ledger.Get("none")
	base := ledger.TxnContext{Beneficiary: "bob", Amount: "100", Currency: "USD"}
	other := ledger.TxnContext{Beneficiary: "bob", Amount: "101", Currency: "USD"}
	_, h1, _ := ledger.ContextHash(l, base)
	_, h2, _ := ledger.ContextHash(l, other)
	if h1 == h2 {
		t.Error("different amount must produce a different context hash")
	}
}

func TestXRPL_Validate(t *testing.T) {
	l, err := ledger.Get("xrpl")
	if err != nil {
		t.Fatal(err)
	}
	good := ledger.TxnContext{
		Chain:       "xrpl",
		Originator:  "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "5000",
		Currency:    "XRP",
		Extra:       map[string]string{"DestinationTag": "12345"},
	}
	if _, _, err := ledger.ContextHash(l, good); err != nil {
		t.Errorf("valid XRPL payment should hash: %v", err)
	}

	bad := good
	bad.Beneficiary = "not-an-address"
	if _, _, err := ledger.ContextHash(l, bad); err == nil {
		t.Error("invalid beneficiary address must be rejected")
	}

	badTag := good
	badTag.Extra = map[string]string{"DestinationTag": "-1"}
	if _, _, err := ledger.ContextHash(l, badTag); err == nil {
		t.Error("negative DestinationTag must be rejected")
	}
}

func TestGet_UnknownAdapter(t *testing.T) {
	if _, err := ledger.Get("no-such-chain"); err == nil {
		t.Error("unregistered adapter must return an error")
	}
}
