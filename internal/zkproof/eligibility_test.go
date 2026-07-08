package zkproof_test

// eligibility_test.go — RWA compliance-gate binding proofs (Tier 1 + Tier 2).
//
// Tier 1 (AddrThresholdCircuit): the attribute proof is bound to the holder's
// address as a public input, so it cannot be replayed by a different caller.
//
// Tier 2 (EligibilityCircuit): eligibility additionally requires a trusted
// issuer's Baby Jubjub EdDSA signature over H(DomainHolder, holderAddr,
// commitment), verified in-circuit. This makes eligibility non-transferable and
// issuer-gated: only the trusted issuer can authorise an address, and the
// attestation is bound to that exact address.
//
// These tests are the definitive check for the msg.sender-binding work: they
// assert the honest cases verify and that every replay / forgery path fails.

import (
	"crypto/rand"
	"testing"

	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

// addr returns a deterministic 20-byte Ethereum-style address filled with b.
func addr(b byte) []byte {
	a := make([]byte, 20)
	for i := range a {
		a[i] = b
	}
	return a
}

func newEdKey(t *testing.T) *eddsabn254.PrivateKey {
	t.Helper()
	p, err := eddsabn254.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return p
}

// ── Tier 1: address-bound attribute proof ────────────────────────────────────

// A valid address-bound threshold proof verifies for its own address and is
// REJECTED when replayed under a different address (the anti-replay property).
func TestAddrThreshold_BindsAddress(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitAddrThreshold)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	holder := addr(0xAB)
	proof, commit, err := art.ProveAddrThreshold(5000, []byte("blinding"), 1000, holder)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := art.VerifyAddrThreshold(proof, commit, 1000, holder); err != nil {
		t.Fatalf("verify (correct address) failed: %v", err)
	}
	if err := art.VerifyAddrThreshold(proof, commit, 1000, addr(0xCD)); err == nil {
		t.Error("verify accepted a proof replayed from a different address")
	}
}

// An amount below the threshold cannot be proved (the predicate is unsatisfiable).
func TestAddrThreshold_RejectsBelowThreshold(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitAddrThreshold)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, _, err := art.ProveAddrThreshold(500, []byte("b"), 1000, addr(0x01)); err == nil {
		t.Error("prove accepted an amount below threshold")
	}
}

// ── Tier 2: issuer-bound eligibility proof ───────────────────────────────────

// The full happy path: a trusted issuer attests an address, the holder proves in
// ZK, and the proof verifies. It is REJECTED for a different address (replay) and
// under a different issuer key (untrusted verifier context).
func TestEligibility_IssuerBound(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitEligibility)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	issuer := newEdKey(t)
	pub := issuer.PublicKey.Bytes()
	holder := addr(0xAB)

	sig, _, err := zkproof.AttestEligibility(issuer, holder, 5000, []byte("blinding"))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	proof, _, err := art.ProveEligibility(5000, []byte("blinding"), 1000, holder, pub, sig)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := art.VerifyEligibility(proof, 1000, holder, pub); err != nil {
		t.Fatalf("verify (valid eligibility) failed: %v", err)
	}
	if err := art.VerifyEligibility(proof, 1000, addr(0xCD), pub); err == nil {
		t.Error("verify accepted eligibility bound to a different address (replay)")
	}
	if err := art.VerifyEligibility(proof, 1000, holder, newEdKey(t).PublicKey.Bytes()); err == nil {
		t.Error("verify accepted eligibility under a different issuer key")
	}
}

// Naming the trusted issuer is not enough: a signature from a rogue key does not
// verify under the trusted issuer's public key, so the proof cannot be produced.
func TestEligibility_RejectsUntrustedSigner(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitEligibility)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	trusted := newEdKey(t)
	rogue := newEdKey(t)
	holder := addr(0xAB)

	sig, _, err := zkproof.AttestEligibility(rogue, holder, 5000, []byte("blinding"))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if _, _, err := art.ProveEligibility(5000, []byte("blinding"), 1000, holder, trusted.PublicKey.Bytes(), sig); err == nil {
		t.Error("prove accepted a signature from an untrusted signer under the trusted key")
	}
}

// The attestation is bound to one address: a holder cannot prove eligibility for
// a different address than the one the issuer signed (message mismatch).
func TestEligibility_RejectsAddressSwap(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitEligibility)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	issuer := newEdKey(t)
	pub := issuer.PublicKey.Bytes()

	sig, _, err := zkproof.AttestEligibility(issuer, addr(0xAB), 5000, []byte("blinding"))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if _, _, err := art.ProveEligibility(5000, []byte("blinding"), 1000, addr(0xCD), pub, sig); err == nil {
		t.Error("prove accepted an attestation bound to a different address")
	}
}

// The attribute predicate still holds under Tier 2: below-threshold cannot prove.
func TestEligibility_RejectsBelowThreshold(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitEligibility)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	issuer := newEdKey(t)
	holder := addr(0xAB)

	sig, _, err := zkproof.AttestEligibility(issuer, holder, 500, []byte("blinding"))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if _, _, err := art.ProveEligibility(500, []byte("blinding"), 1000, holder, issuer.PublicKey.Bytes(), sig); err == nil {
		t.Error("prove accepted an amount below threshold")
	}
}
