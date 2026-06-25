package zkhash

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// TestDomainSeparation: the three domain tags produce distinct digests for the
// same two inputs (CR-1), and each wrapper agrees with HashCommit(tag, ...).
func TestDomainSeparation(t *testing.T) {
	a := FeFromUint64(7)
	b := FeFromUint64(9)

	anchor := HashAnchor(a, b)
	amount := HashAmount(a, b)
	node := HashNode(a, b)

	if anchor.Equal(&amount) || anchor.Equal(&node) || amount.Equal(&node) {
		t.Fatal("distinct domains must yield distinct digests for identical inputs")
	}
	if c := HashCommit(DomainAnchor, a, b); !c.Equal(&anchor) {
		t.Error("HashAnchor must equal HashCommit(DomainAnchor, ...)")
	}
	if c := HashCommit(DomainAmount, a, b); !c.Equal(&amount) {
		t.Error("HashAmount must equal HashCommit(DomainAmount, ...)")
	}
	if c := HashCommit(DomainMerkleNode, a, b); !c.Equal(&node) {
		t.Error("HashNode must equal HashCommit(DomainMerkleNode, ...)")
	}
}

// TestFeFromCanonical_RejectsNonCanonical (CR-3): a fixed-width input that
// encodes an integer >= r is rejected rather than silently aliased to its
// reduced value (which FeFromBytes would do).
func TestFeFromCanonical_RejectsNonCanonical(t *testing.T) {
	// r itself, big-endian, in exactly fr.Bytes bytes: not a canonical element.
	rBytes := make([]byte, fr.Bytes)
	fr.Modulus().FillBytes(rBytes)
	if _, err := FeFromCanonical(rBytes); err == nil {
		t.Error("FeFromCanonical must reject an input >= r")
	}

	// A small canonical value round-trips.
	small := []byte{0x2a} // 42
	e, err := FeFromCanonical(small)
	if err != nil {
		t.Fatalf("canonical input must be accepted: %v", err)
	}
	if got := BigOf(e); got.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("FeFromCanonical(42) = %s, want 42", got)
	}

	// Oversized input is rejected (route to FeFromWide instead).
	if _, err := FeFromCanonical(make([]byte, fr.Bytes+1)); err == nil {
		t.Error("FeFromCanonical must reject inputs wider than the field")
	}
}

// TestFeFromWide_Deterministic: the wide reduction of a >32-byte (e.g. SHA-512)
// digest is stable and equal to interpreting the bytes big-endian mod r.
func TestFeFromWide_Deterministic(t *testing.T) {
	wide := bytes.Repeat([]byte{0xAB}, 64) // 64-byte SHA-512 stand-in
	got := FeFromWide(wide)

	want := new(big.Int).SetBytes(wide)
	want.Mod(want, fr.Modulus())
	var wantFE fr.Element
	wantFE.SetBigInt(want)
	if !got.Equal(&wantFE) {
		t.Error("FeFromWide must equal big-endian(bytes) mod r")
	}
}
