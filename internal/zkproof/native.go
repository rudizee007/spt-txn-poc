package zkproof

// native.go — native (out-of-circuit) hashing and Merkle helpers. The hash is
// the shared internal/zkhash function (so the token's humanAnchor and this
// commitment are the same value), and it MUST stay byte-for-byte consistent with
// the in-circuit gadget in circuits.go (gnark hashes field elements written as
// canonical 32-byte Marshal blocks). These thin wrappers keep the call sites
// below unchanged.

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkhash"
)

func feFromBytes(b []byte) fr.Element   { return zkhash.FeFromBytes(b) }
func feFromUint64(u uint64) fr.Element  { return zkhash.FeFromUint64(u) }
func bigOf(e fr.Element) *big.Int       { return zkhash.BigOf(e) }
func hashTwo(a, b fr.Element) fr.Element { return zkhash.HashTwo(a, b) }

// Commit is the public commitment for a pair of secret inputs, used for both
// the humanAnchor (ID, Randomness) and the amount commitment (Amount, Blinding).
func Commit(secret, blinding []byte) *big.Int {
	return bigOf(hashTwo(feFromBytes(secret), feFromBytes(blinding)))
}

// ── registered-VASP Merkle tree ──────────────────────────────────────────────

// MerkleTree is a MiMC Merkle tree over the registered-VASP set.
type MerkleTree struct {
	levels [][]fr.Element // levels[0] = leaves, last = [root]
	index  map[string]int // member-id hex -> leaf index
}

// BuildVASPRegistry builds a depth-VASPTreeDepth tree from member identifiers.
// It requires exactly 2^VASPTreeDepth members for the fixed-depth circuit;
// pad the input with sentinel members if the real registry is smaller.
func BuildVASPRegistry(memberIDs [][]byte) (*MerkleTree, error) {
	want := 1 << VASPTreeDepth
	if len(memberIDs) != want {
		return nil, fmt.Errorf("registry needs exactly %d members for depth %d, got %d", want, VASPTreeDepth, len(memberIDs))
	}
	leaves := make([]fr.Element, want)
	index := make(map[string]int, want)
	for i, id := range memberIDs {
		leaves[i] = feFromBytes(id)
		index[bigOf(leaves[i]).Text(16)] = i
	}
	levels := [][]fr.Element{leaves}
	cur := leaves
	for len(cur) > 1 {
		next := make([]fr.Element, len(cur)/2)
		for i := 0; i < len(cur); i += 2 {
			next[i/2] = hashTwo(cur[i], cur[i+1])
		}
		levels = append(levels, next)
		cur = next
	}
	return &MerkleTree{levels: levels, index: index}, nil
}

// Root returns the public Merkle root of the registry.
func (t *MerkleTree) Root() *big.Int {
	return bigOf(t.levels[len(t.levels)-1][0])
}

// ProofForMember returns the leaf, authentication path (siblings + path bits),
// and root for a member identifier, or ok=false if it is not registered.
func (t *MerkleTree) ProofForMember(id []byte) (leaf *big.Int, sibs []*big.Int, bits []int, root *big.Int, ok bool) {
	leafFE := feFromBytes(id)
	idx, found := t.index[bigOf(leafFE).Text(16)]
	if !found {
		return nil, nil, nil, nil, false
	}
	cur := idx
	for d := 0; d < len(t.levels)-1; d++ {
		sibs = append(sibs, bigOf(t.levels[d][cur^1]))
		bits = append(bits, cur&1)
		cur /= 2
	}
	return bigOf(leafFE), sibs, bits, t.Root(), true
}
