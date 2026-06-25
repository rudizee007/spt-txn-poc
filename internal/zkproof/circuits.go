// Package zkproof provides the real Groth16 zero-knowledge circuits for the
// SPT-Txn privacy-preserving Travel Rule layer, validated on the OpenBSD host.
//
// Three predicates, each proving a compliance fact while revealing nothing
// about the underlying private data:
//
//   - Commitment: the holder knows the identity material behind a humanAnchor.
//   - Threshold:  a committed transfer amount is at/above the FATF reporting
//     threshold, without revealing the amount.
//   - VASP:       a counterparty is in the registered-VASP set, without
//     revealing which member.
//
// Poseidon2 is the ZK-friendly hash (gnark's native MerkleDamgard hasher and the
// in-circuit gadget are matched by construction); it replaced MiMC in v2 for a
// large proving speedup. This package depends on gnark but the M0-M2 services do
// not import it, so only the prover/verifier binaries pull in the proving backend.
//
// Domain separation (CR-1): each predicate hashes under a distinct domain tag,
// absorbed as the FIRST input — H(tag, a, b) — exactly mirroring the native
// helpers in internal/zkhash (HashAnchor/HashAmount/HashNode). The tag constants
// are imported from zkhash so the native and in-circuit absorption sequences can
// never drift apart. The Poseidon2 Merkle-Damgard hasher absorbs one field
// element per Write argument with initial state 0, so h.Write(tag, a, b) computes
// Compress(Compress(Compress(0, tag), a), b) — identical to the native side,
// which writes the same three 32-byte canonical blocks in the same order.
package zkproof

import (
	"github.com/consensys/gnark/frontend"
	circuitposeidon2 "github.com/consensys/gnark/std/hash/poseidon2"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkhash"
)

// VASPTreeDepth fixes the registered-VASP Merkle tree depth (2^depth members).
const VASPTreeDepth = 8

// CommitmentCircuit constrains Anchor == Poseidon2(DomainAnchor, ID, Randomness).
type CommitmentCircuit struct {
	ID         frontend.Variable `gnark:",secret"`
	Randomness frontend.Variable `gnark:",secret"`
	Anchor     frontend.Variable `gnark:",public"`
}

func (c *CommitmentCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAnchor.
	h.Write(zkhash.DomainAnchor, c.ID, c.Randomness)
	api.AssertIsEqual(c.Anchor, h.Sum())
	return nil
}

// ThresholdCircuit constrains a committed amount to be >= a public threshold,
// with the amount range-checked to 64 bits to prevent field wraparound.
type ThresholdCircuit struct {
	Amount     frontend.Variable `gnark:",secret"`
	Blinding   frontend.Variable `gnark:",secret"`
	Commitment frontend.Variable `gnark:",public"`
	Threshold  frontend.Variable `gnark:",public"`
}

func (c *ThresholdCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAmount.
	h.Write(zkhash.DomainAmount, c.Amount, c.Blinding)
	api.AssertIsEqual(c.Commitment, h.Sum())

	// Range-check BOTH operands of the comparison to a shared 64-bit domain
	// (CR-4). Without constraining Threshold, the public input could be a field
	// element outside [0, 2^64) and AssertIsLessOrEqual would compare in the full
	// field, allowing a spurious "amount >= threshold" via modular wraparound.
	api.ToBinary(c.Amount, 64)
	api.ToBinary(c.Threshold, 64)
	api.AssertIsLessOrEqual(c.Threshold, c.Amount)
	return nil
}

// VASPCircuit verifies a Merkle authentication path from a secret leaf to the
// public registered-VASP root.
type VASPCircuit struct {
	Leaf     frontend.Variable                `gnark:",secret"`
	Siblings [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	PathBits [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	Root     frontend.Variable                `gnark:",public"`
}

func (c *VASPCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	cur := c.Leaf
	for i := 0; i < VASPTreeDepth; i++ {
		api.AssertIsBoolean(c.PathBits[i])
		left := api.Select(c.PathBits[i], c.Siblings[i], cur)
		right := api.Select(c.PathBits[i], cur, c.Siblings[i])
		h.Reset()
		// Inner-node domain tag absorbed first; mirrors zkhash.HashNode and is
		// distinct from the commitment domains so a commitment value can never be
		// passed off as a Merkle node (or vice versa).
		h.Write(zkhash.DomainMerkleNode, left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}
