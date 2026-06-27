package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func solanaAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("solana")
	if err != nil {
		t.Fatalf("solana adapter not registered: %v", err)
	}
	if l.Name() != "solana" {
		t.Fatalf("Name() = %q, want solana", l.Name())
	}
	return l
}

func TestSolana_Validate_AcceptsValidTransfer(t *testing.T) {
	l := solanaAdapter(t)
	// Example devnet-style base58 addresses (not the production wallet).
	const acctA = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
	const acctB = "7C4jsPZpht42Tw6MjXWF56Q5RQUocjBBmciEjDa8HRtp"
	const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	cases := []ledger.TxnContext{
		{Chain: "solana", Originator: acctA, Beneficiary: acctB, Amount: "5.5", Currency: "SOL", Timestamp: 1750000000},
		{Chain: "solana", Originator: acctA, Beneficiary: acctB, Amount: "1000", Currency: usdcMint, Timestamp: 1750000000, Extra: map[string]string{"memo": "invoice-7"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestSolana_Validate_Rejects(t *testing.T) {
	l := solanaAdapter(t)
	long := make([]byte, 567)
	for i := range long {
		long[i] = 'a'
	}
	const acctB = "7C4jsPZpht42Tw6MjXWF56Q5RQUocjBBmciEjDa8HRtp"
	bad := map[string]ledger.TxnContext{
		"too short":       {Beneficiary: "abc", Amount: "1", Currency: "SOL"},
		"non-base58 (0)":  {Beneficiary: "0000000000000000000000000000000000000000000", Amount: "1", Currency: "SOL"},
		"bad originator":  {Originator: "!!!", Beneficiary: acctB, Amount: "1", Currency: "SOL"},
		"empty amount":    {Beneficiary: acctB, Amount: "", Currency: "SOL"},
		"negative amount": {Beneficiary: acctB, Amount: "-5", Currency: "SOL"},
		"empty currency":  {Beneficiary: acctB, Amount: "1", Currency: ""},
		"over-long memo":  {Beneficiary: acctB, Amount: "1", Currency: "SOL", Extra: map[string]string{"memo": string(long)}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestSolana_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := solanaAdapter(t)
	const acctA = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
	const acctB = "7C4jsPZpht42Tw6MjXWF56Q5RQUocjBBmciEjDa8HRtp"
	tc := ledger.TxnContext{
		Chain: "solana", Originator: acctA, Beneficiary: acctB,
		Amount: "5000.00", Currency: "SOL", Timestamp: 1750000000,
		Extra: map[string]string{"memo": "ref-1"},
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
	tc2 := tc
	tc2.Amount = "5001.00"
	_, h3, _ := ledger.ContextHash(l, tc2)
	if h1 == h3 {
		t.Error("amount change did not alter the context hash")
	}
	// Chain tag is part of the preimage: a Solana transfer must not collide with
	// a Hedera transfer of the same field values.
	hd, _ := ledger.Get("hedera")
	htc := ledger.TxnContext{Originator: "0.0.1001", Beneficiary: "0.0.2002", Amount: "5000.00", Currency: "SOL", Timestamp: 1750000000}
	_, hh, _ := ledger.ContextHash(hd, htc)
	if h1 == hh {
		t.Error("solana and hedera context hashes collided")
	}
}
