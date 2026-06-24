// Package zkhash is the single source of truth for the SPT-Txn ZK-friendly hash
// over BN254. It is used both NATIVELY (the zkDID humanAnchor commitment in
// internal/zkdid, the amount commitment and Merkle tree in internal/zkproof) and
// is matched IN-CIRCUIT by gnark's std hash gadget. Keeping it in one place
// means the token's humanAnchor and the ZK-proven commitment are the same value,
// and swapping the hash (MiMC -> Poseidon, Section 5) is a one-file change here
// plus the circuit gadget.
//
// Importing this package pulls only gnark-crypto field arithmetic + the hash —
// NOT the gnark prover — so key-holding services (catsvc) stay lean.
//
// Current hash: Poseidon2 over BN254 (gnark-crypto native MerkleDamgardHasher <->
// gnark/std/hash/poseidon2 in-circuit, matched by construction). Migrated from
// MiMC in v2 (gnark v0.15 / gnark-crypto v0.20) for a large proving speedup. The
// hash is defined in exactly two matched places — HashTwo here and the gadget in
// internal/zkproof/circuits.go — so the token humanAnchor == the proven
// commitment. Changing the hash changes the serialized circuit/key format, so
// re-run cmd/zk-setup after any change here.
package zkhash

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// FeFromBytes reduces arbitrary bytes to a field element (big-endian mod r).
func FeFromBytes(b []byte) fr.Element {
	var e fr.Element
	e.SetBytes(b)
	return e
}

// FeFromUint64 lifts a uint64 into a field element.
func FeFromUint64(u uint64) fr.Element {
	var e fr.Element
	e.SetUint64(u)
	return e
}

// BigOf converts a field element to a *big.Int (for gnark witness values).
func BigOf(e fr.Element) *big.Int {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

// HashTwo computes the two-input hash H(a, b) over field elements — the pairing
// used for the identity/amount commitment and each Merkle level. MUST match the
// in-circuit gadget (gnark hashes field elements written as canonical 32-byte
// Marshal blocks).
func HashTwo(a, b fr.Element) fr.Element {
	h := poseidon2.NewMerkleDamgardHasher()
	h.Write(a.Marshal())
	h.Write(b.Marshal())
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

// Commit is H(FeFromBytes(secret), FeFromBytes(blinding)) — the canonical
// commitment used for the humanAnchor and amount commitments.
func Commit(secret, blinding []byte) fr.Element {
	return HashTwo(FeFromBytes(secret), FeFromBytes(blinding))
}
