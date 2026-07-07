package zkproof

// Internal (white-box) circuit tests using gnark's test engine, which solves a
// circuit against a witness without a full trusted setup — cheap enough to run
// the negative cases that document CR-1 (domain separation) and CR-4 (threshold
// range-check) intent.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/rudizee007/spt-txn-poc/internal/zkhash"
)

var bn254 = ecc.BN254.ScalarField()

// TestThresholdCircuit_RangeChecksThreshold (CR-4): the Threshold operand is
// range-checked to 64 bits alongside Amount, so a Threshold value outside
// [0, 2^64) cannot be smuggled into the field comparison to forge an
// "amount >= threshold" result via modular wraparound.
func TestThresholdCircuit_RangeChecksThreshold(t *testing.T) {
	amount := uint64(5000)
	blinding := []byte("amount-blinding-cr4")
	amt := feFromUint64(amount)
	bl := feFromWide(blinding)
	commit := hashAmount(amt, bl)

	// A well-formed, in-range threshold solves the circuit.
	good := &ThresholdCircuit{
		Amount:     bigOf(amt),
		Blinding:   bigOf(bl),
		Commitment: bigOf(commit),
		Threshold:  big.NewInt(1000),
	}
	if err := test.IsSolved(&ThresholdCircuit{}, good, bn254); err != nil {
		t.Fatalf("a valid in-range threshold witness must solve: %v", err)
	}

	// An out-of-range threshold (>= 2^64) must be rejected by the added
	// api.ToBinary(c.Threshold, 64) constraint. Pick 2^64 itself, which still
	// satisfies Threshold <= Amount in the full field only because Amount here is
	// small — i.e. exactly the wraparound shape the range-check forbids.
	oob := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64, just outside the 64-bit domain
	bad := &ThresholdCircuit{
		Amount:     bigOf(amt),
		Blinding:   bigOf(bl),
		Commitment: bigOf(commit),
		Threshold:  oob,
	}
	if err := test.IsSolved(&ThresholdCircuit{}, bad, bn254); err == nil {
		t.Error("a threshold outside the 64-bit range must fail the circuit (CR-4)")
	}
}

// TestThresholdCircuit_RejectsSubThreshold confirms the core soundness property
// is preserved after the CR-4 change: a sub-threshold amount cannot be proven
// at/above the threshold.
func TestThresholdCircuit_RejectsSubThreshold(t *testing.T) {
	amt := feFromUint64(500)
	bl := feFromWide([]byte("blinding"))
	commit := hashAmount(amt, bl)
	w := &ThresholdCircuit{
		Amount:     bigOf(amt),
		Blinding:   bigOf(bl),
		Commitment: bigOf(commit),
		Threshold:  big.NewInt(1000), // 1000 > 500, so Threshold <= Amount is false
	}
	if err := test.IsSolved(&ThresholdCircuit{}, w, bn254); err == nil {
		t.Error("a sub-threshold amount must not satisfy the threshold circuit")
	}
}

// TestDomainSeparation_CircuitMatchesNative (CR-1): the in-circuit gadget absorbs
// the SAME domain tag first as the native zkhash helpers, so the native anchor /
// amount / node hashes equal what each circuit constrains. This both proves the
// native<->circuit consistency and that the three domains are distinct.
func TestDomainSeparation_CircuitMatchesNative(t *testing.T) {
	a := zkhash.FeFromUint64(111)
	b := zkhash.FeFromUint64(222)

	anchor := zkhash.HashAnchor(a, b)
	amount := zkhash.HashAmount(a, b)
	node := zkhash.HashNode(a, b)

	// Distinct domains => distinct digests for identical inputs.
	if anchor.Equal(&amount) || anchor.Equal(&node) || amount.Equal(&node) {
		t.Fatal("domain tags must make H(tag,a,b) distinct across anchor/amount/node")
	}

	// CommitmentCircuit (DomainAnchor) is solved by the native anchor digest.
	if err := test.IsSolved(&CommitmentCircuit{}, &CommitmentCircuit{
		ID:         bigOf(a),
		Randomness: bigOf(b),
		Anchor:     bigOf(anchor),
	}, bn254); err != nil {
		t.Errorf("commitment circuit must accept the native HashAnchor digest: %v", err)
	}
	// ...and must REJECT the amount-domain digest for the same inputs.
	if err := test.IsSolved(&CommitmentCircuit{}, &CommitmentCircuit{
		ID:         bigOf(a),
		Randomness: bigOf(b),
		Anchor:     bigOf(amount),
	}, bn254); err == nil {
		t.Error("commitment circuit must reject a wrong-domain (amount) digest")
	}

	// ThresholdCircuit (DomainAmount) is solved by the native amount digest.
	if err := test.IsSolved(&ThresholdCircuit{}, &ThresholdCircuit{
		Amount:     bigOf(a),
		Blinding:   bigOf(b),
		Commitment: bigOf(amount),
		Threshold:  big.NewInt(1), // a == 111 >= 1, in range
	}, bn254); err != nil {
		t.Errorf("threshold circuit must accept the native HashAmount digest: %v", err)
	}
}
