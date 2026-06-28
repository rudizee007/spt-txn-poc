package zkproof_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// A valid 3-hop chain (10000 -> 8000 -> 5000, same currency, depth 3) proves and
// verifies; a wrong declared depth is rejected.
func TestChain_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: 840}, // root CAT ceiling
		{MaxAmount: 8000, Currency: 840},  // CT
		{MaxAmount: 5000, Currency: 840},  // leaf (agent)
	}
	proof, h0, cleaf, err := art.ProveChain([]byte("alice-human-anchor"), []byte("salt-xyz"), 3, hops)
	if err != nil {
		t.Fatalf("prove (valid chain): %v", err)
	}
	if err := art.VerifyChain(proof, h0, cleaf, 3); err != nil {
		t.Fatalf("verify (valid chain) failed: %v", err)
	}
	if err := art.VerifyChain(proof, h0, cleaf, 2); err == nil {
		t.Error("verify accepted a wrong maxDepth")
	}
}

// A child whose ceiling exceeds its parent violates attenuation — proving must fail.
func TestChain_RejectsWidening(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840},
		{MaxAmount: 9000, Currency: 840}, // widens above parent — escalation
	}
	if _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops); err == nil {
		t.Error("prove accepted a widening (scope-escalating) chain")
	}
}

// Switching currency mid-chain violates the currency-equality constraint.
func TestChain_RejectsCurrencySwitch(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840},
		{MaxAmount: 5000, Currency: 978}, // currency changed
	}
	if _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops); err == nil {
		t.Error("prove accepted a currency switch mid-chain")
	}
}

// A chain longer than the declared delegation depth allows is rejected.
func TestChain_RejectsTooDeep(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840},
		{MaxAmount: 5000, Currency: 840},
		{MaxAmount: 3000, Currency: 840},
	}
	// 3 hops need depth >= 2; declaring maxDepth=1 must be refused.
	if _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 1, hops); err == nil {
		t.Error("prove accepted a chain deeper than maxDepth")
	}
}
