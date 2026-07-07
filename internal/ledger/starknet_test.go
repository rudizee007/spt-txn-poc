package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

const (
	stkA     = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	stkB     = "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	stkToken = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
)

func starknetAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("starknet")
	if err != nil {
		t.Fatalf("starknet adapter not registered: %v", err)
	}
	if l.Name() != "starknet" {
		t.Fatalf("Name() = %q, want starknet", l.Name())
	}
	return l
}

func TestStarknet_Validate_AcceptsValidTransfer(t *testing.T) {
	l := starknetAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "starknet", Originator: stkA, Beneficiary: stkB, Amount: "5.5", Currency: "STRK", Timestamp: 1750000000},
		// ERC-20 token transfer (token = contract address) + an on-chain anchor hash.
		{Chain: "starknet", Originator: stkA, Beneficiary: stkB, Amount: "1000", Currency: stkToken, Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestStarknet_Validate_Rejects(t *testing.T) {
	l := starknetAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no 0x prefix":   {Beneficiary: "deadbeef", Amount: "1", Currency: "ETH"},
		"too long hex":   {Beneficiary: "0x" + "f" + stkB[2:], Amount: "1", Currency: "ETH"}, // 65 hex
		"non-hex":        {Beneficiary: "0xZZZ", Amount: "1", Currency: "ETH"},
		"bad originator": {Originator: "nope", Beneficiary: stkB, Amount: "1", Currency: "ETH"},
		"empty amount":   {Beneficiary: stkB, Amount: "", Currency: "ETH"},
		"negative":       {Beneficiary: stkB, Amount: "-5", Currency: "ETH"},
		"empty currency": {Beneficiary: stkB, Amount: "1", Currency: ""},
		"bad token cur":  {Beneficiary: stkB, Amount: "1", Currency: "USDC"}, // not ETH/STRK and not a 0x addr
		"bad anchor":     {Beneficiary: stkB, Amount: "1", Currency: "ETH", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestStarknet_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := starknetAdapter(t)
	tc := ledger.TxnContext{
		Chain: "starknet", Originator: stkA, Beneficiary: stkB,
		Amount: "5000.00", Currency: "STRK", Timestamp: 1750000000,
		Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"},
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
	// Chain tag is in the preimage: Starknet must not collide with Stellar.
	stl, _ := ledger.Get("stellar")
	stc := ledger.TxnContext{Originator: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW",
		Beneficiary: "G234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ", Amount: "5000.00", Currency: "STRK", Timestamp: 1750000000}
	_, hstl, _ := ledger.ContextHash(stl, stc)
	if h1 == hstl {
		t.Error("starknet and stellar context hashes collided")
	}
}
