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
// Current hash: MiMC over BN254 (gnark-crypto native <-> gnark/std/hash/mimc
// in-circuit, matched by construction).
//
// Poseidon (the Section-5 target) is NOT available in the pinned gnark v0.11.0 /
// gnark-crypto v0.14.0 — those ship only mimc/sha2/sha3. Adopting Poseidon2
// requires upgrading to a newer gnark (which adds std/hash/poseidon2 + the native
// poseidon2 package); that upgrade also changes the serialized circuit/key format
// (re-run cmd/zk-setup) and may shift the frontend/backend APIs, so it is a
// deliberate, isolated v2 task. MiMC is the working interim that keeps the native
// and in-circuit hashes matched today and the token humanAnchor == the proven
// commitment. To swap later: change HashTwo here AND the gadget in
// internal/zkproof/circuits.go together, then re-run setup and the tests.
package zkhash

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
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
	h := mimc.NewMiMC()
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
