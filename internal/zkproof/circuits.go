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
package zkproof

import (
	"github.com/consensys/gnark/frontend"
	circuitposeidon2 "github.com/consensys/gnark/std/hash/poseidon2"
)

// VASPTreeDepth fixes the registered-VASP Merkle tree depth (2^depth members).
const VASPTreeDepth = 8

// CommitmentCircuit constrains Anchor == Poseidon2(ID, Randomness).
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
	h.Write(c.ID, c.Randomness)
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
	h.Write(c.Amount, c.Blinding)
	api.AssertIsEqual(c.Commitment, h.Sum())

	api.ToBinary(c.Amount, 64)
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
		h.Write(left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}
