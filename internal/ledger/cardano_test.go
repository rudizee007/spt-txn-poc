package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func cardanoAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("cardano")
	if err != nil {
		t.Fatalf("cardano adapter not registered: %v", err)
	}
	if l.Name() != "cardano" {
		t.Fatalf("Name() = %q, want cardano", l.Name())
	}
	return l
}

const (
	adaMain = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl3agrewslhze7"
	adaTest = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl3agrews8xzr9j"
	adaByro = "DdzFFzCqrht5AaL5KGUxfD7sSNiGNmz6DaUmmRAmXApD5wjr1zAT7RxDNy1QT8"
	adaPol  = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d" // 56-hex policy id
)

func TestCardano_Validate_AcceptsValidTransfer(t *testing.T) {
	l := cardanoAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "cardano", Originator: adaMain, Beneficiary: adaTest, Amount: "1000000", Currency: "ADA", Timestamp: 1750000000},
		{Chain: "cardano", Originator: adaByro, Beneficiary: adaMain, Amount: "5.5", Currency: adaPol + ".53505400", Timestamp: 1750000000, Extra: map[string]string{"anchor_hash": "0326eeafb91ae3ba941891c5df4c12fcd8a85087553b6cf6aa864d912c327fea"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestCardano_Validate_Rejects(t *testing.T) {
	long := make([]byte, 1100)
	for i := range long {
		long[i] = 'a'
	}
	l := cardanoAdapter(t)
	bad := map[string]ledger.TxnContext{
		"too short":       {Beneficiary: "addr1", Amount: "1", Currency: "ADA"},
		"uppercase":       {Beneficiary: "ADDR1QX2FXV2UMYHTTKXYXP8", Amount: "1", Currency: "ADA"},
		"wrong prefix":    {Beneficiary: "xrb1abcdefghijklmnop", Amount: "1", Currency: "ADA"},
		"bad originator":  {Originator: "!!!", Beneficiary: adaMain, Amount: "1", Currency: "ADA"},
		"empty amount":    {Beneficiary: adaMain, Amount: "", Currency: "ADA"},
		"negative amount": {Beneficiary: adaMain, Amount: "-5", Currency: "ADA"},
		"empty currency":  {Beneficiary: adaMain, Amount: "1", Currency: ""},
		"bad currency":    {Beneficiary: adaMain, Amount: "1", Currency: "XYZ"},
		"bad anchor_hash": {Beneficiary: adaMain, Amount: "1", Currency: "ADA", Extra: map[string]string{"anchor_hash": "deadbeef"}},
		"over-long meta":  {Beneficiary: adaMain, Amount: "1", Currency: "ADA", Extra: map[string]string{"metadata": string(long)}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestCardano_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := cardanoAdapter(t)
	tc := ledger.TxnContext{
		Chain: "cardano", Originator: adaMain, Beneficiary: adaTest,
		Amount: "5000000", Currency: "ADA", Timestamp: 1750000000,
		Extra: map[string]string{"anchor_hash": "0326eeafb91ae3ba941891c5df4c12fcd8a85087553b6cf6aa864d912c327fea"},
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
	tc2.Amount = "5000001"
	_, h3, _ := ledger.ContextHash(l, tc2)
	if h1 == h3 {
		t.Error("amount change did not alter the context hash")
	}
	// Chain tag is part of the preimage: a Cardano transfer must not collide with
	// a NEAR transfer of the same field values.
	near, _ := ledger.Get("near")
	ntc := ledger.TxnContext{Originator: "agent.alice.testnet", Beneficiary: "merchant.testnet", Amount: "5000000", Currency: "ADA", Timestamp: 1750000000}
	_, nh, _ := ledger.ContextHash(near, ntc)
	if h1 == nh {
		t.Error("cardano and near context hashes collided")
	}
}
