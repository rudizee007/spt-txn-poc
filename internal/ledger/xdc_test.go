package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

const (
	xdcA   = "xdc0102030405060708090a0b0c0d0e0f1011121314"
	xdcB   = "0xfFEEdDcCBbAa99887766554433221100ffEEddCc"
	xdcTok = "xdcA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
)

func xdcAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("xdc")
	if err != nil {
		t.Fatalf("xdc adapter not registered: %v", err)
	}
	if l.Name() != "xdc" {
		t.Fatalf("Name() = %q, want xdc", l.Name())
	}
	return l
}

func TestXDC_Validate_AcceptsValidTransfer(t *testing.T) {
	l := xdcAdapter(t)
	cases := []ledger.TxnContext{
		// native XDC, xdc-prefixed addresses
		{Chain: "xdc", Originator: xdcA, Beneficiary: "xdc" + xdcB[2:], Amount: "5.5", Currency: "XDC", Timestamp: 1750000000},
		// 0x-prefixed addresses + XRC-20 token + anchor
		{Chain: "xdc", Originator: xdcB, Beneficiary: "0x" + xdcA[3:], Amount: "1000", Currency: xdcTok, Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestXDC_Validate_Rejects(t *testing.T) {
	l := xdcAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no prefix":      {Beneficiary: "fFEEdDcCBbAa99887766554433221100ffEEddCc", Amount: "1", Currency: "XDC"},
		"too long hex":   {Beneficiary: xdcB + "ff", Amount: "1", Currency: "XDC"},
		"too short hex":  {Beneficiary: xdcB[:len(xdcB)-1], Amount: "1", Currency: "XDC"},
		"non-hex":        {Beneficiary: "xdcZZZ", Amount: "1", Currency: "XDC"},
		"bad originator": {Originator: "nope", Beneficiary: xdcB, Amount: "1", Currency: "XDC"},
		"empty amount":   {Beneficiary: xdcB, Amount: "", Currency: "XDC"},
		"negative":       {Beneficiary: xdcB, Amount: "-5", Currency: "XDC"},
		"empty currency": {Beneficiary: xdcB, Amount: "1", Currency: ""},
		"bad currency":   {Beneficiary: xdcB, Amount: "1", Currency: "USDC"},
		"bad anchor":     {Beneficiary: xdcB, Amount: "1", Currency: "XDC", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestXDC_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := xdcAdapter(t)
	tc := ledger.TxnContext{
		Chain: "xdc", Originator: xdcA, Beneficiary: xdcB,
		Amount: "5000.00", Currency: "XDC", Timestamp: 1750000000,
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, h2, _ := ledger.ContextHash(l, tc)
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
	// Chain tag must keep XDC distinct from Ethereum (both accept 0x addresses).
	eth, _ := ledger.Get("ethereum")
	etc := ledger.TxnContext{Chain: "ethereum", Originator: xdcB, Beneficiary: xdcB,
		Amount: "5000.00", Currency: "ETH", Timestamp: 1750000000}
	_, heth, _ := ledger.ContextHash(eth, etc)
	if h1 == heth {
		t.Error("xdc and ethereum context hashes collided")
	}
}
