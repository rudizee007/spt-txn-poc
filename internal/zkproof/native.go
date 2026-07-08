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
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"

	"github.com/rudizee007/spt-txn-poc/internal/zkhash"
)

func feFromBytes(b []byte) fr.Element  { return zkhash.FeFromBytes(b) }
func feFromWide(b []byte) fr.Element   { return zkhash.FeFromWide(b) }
func feFromUint64(u uint64) fr.Element { return zkhash.FeFromUint64(u) }
func bigOf(e fr.Element) *big.Int      { return zkhash.BigOf(e) }

// Domain-separated hash helpers (CR-1): each mirrors a distinct in-circuit
// gadget that absorbs the same domain tag first. hashAnchor backs the identity
// humanAnchor, hashAmount the amount commitment, and hashNode the Merkle inner
// nodes — so a value computed for one purpose cannot be replayed as another.
func hashAnchor(id, r fr.Element) fr.Element     { return zkhash.HashAnchor(id, r) }
func hashAmount(amt, bl fr.Element) fr.Element   { return zkhash.HashAmount(amt, bl) }
func hashNode(left, right fr.Element) fr.Element { return zkhash.HashNode(left, right) }

// Commit is the public identity humanAnchor commitment for a pair of secret
// inputs (ID, Randomness): H(DomainAnchor, FeFromWide(ID), FeFromWide(r)). It is
// domain-separated from the amount commitment (which goes through hashAmount in
// ProveThreshold) and uses the safe wide field reduction (CR-3).
func Commit(secret, blinding []byte) *big.Int {
	return bigOf(hashAnchor(feFromWide(secret), feFromWide(blinding)))
}

// IssuerLeaf computes the registered-CT-issuer Merkle leaf for a marshaled Baby
// Jubjub public key: H(DomainIssuer, A.X, A.Y). It is the single source of truth
// for what a CT-issuer's registry entry is, matched in-circuit by ChainCircuit
// step 6 (which hashes the in-circuit PubKey.A.X / .A.Y identically). Build the
// registry over IssuerLeaf(pub).Bytes() values; the chain proof binds each hop's
// signing key to its leaf, so a valid signature from an UNREGISTERED key cannot
// pass (F1, phase 2).
func IssuerLeaf(pubBytes []byte) (*big.Int, error) {
	var pk eddsabn254.PublicKey
	if _, err := pk.SetBytes(pubBytes); err != nil {
		return nil, fmt.Errorf("zkproof: parse Baby Jubjub public key: %w", err)
	}
	return bigOf(zkhash.HashCommit(zkhash.DomainIssuer, pk.A.X, pk.A.Y)), nil
}

// ── RWA eligibility: issuer attestation (Tier 2) ─────────────────────────────

// AttestEligibility is the TRUSTED ISSUER side of the Tier-2 RWA eligibility
// gate. Off-chain, after vetting the holder, the issuer signs an attestation
// bound to the holder's exact on-chain address:
//
//	commitment = H(DomainAmount, amount, blinding)
//	message    = H(DomainHolder, holderAddr, commitment)
//	sig        = EdDSA_BabyJubjub(issuerPriv, message)   (MiMC_BN254 challenge)
//
// It returns the signature and the amount commitment. The holder later feeds
// these to ProveEligibility to produce the ZK proof the RWA contract verifies.
// Because the address is inside the signed message, the attestation is
// non-transferable: it authorises exactly one address and no other.
func AttestEligibility(issuerPriv *eddsabn254.PrivateKey, holderAddr []byte, amount uint64, blinding []byte) (sig []byte, commitment *big.Int, err error) {
	commit := hashAmount(feFromUint64(amount), feFromWide(blinding))
	msg := zkhash.HashHolder(feFromBytes(holderAddr), commit)
	sig, err = issuerPriv.Sign(msg.Marshal(), gchash.MIMC_BN254.New())
	if err != nil {
		return nil, nil, fmt.Errorf("zkproof: issuer sign eligibility attestation: %w", err)
	}
	return sig, bigOf(commit), nil
}

// issuerXY parses a marshaled Baby Jubjub public key into its affine (X, Y)
// field-element coordinates as *big.Int — the values the EligibilityCircuit takes
// as its public issuer-key inputs and that the RWA token pins on-chain.
func issuerXY(pubBytes []byte) (x, y *big.Int, err error) {
	var pk eddsabn254.PublicKey
	if _, err := pk.SetBytes(pubBytes); err != nil {
		return nil, nil, fmt.Errorf("zkproof: parse issuer public key: %w", err)
	}
	return bigOf(pk.A.X), bigOf(pk.A.Y), nil
}

// IssuerPubXY exposes the issuer public key's (X, Y) coordinates for tooling that
// must pin the trusted issuer on-chain (the RWA token constructor / setIssuer).
func IssuerPubXY(pubBytes []byte) (x, y *big.Int, err error) { return issuerXY(pubBytes) }

// ── registered-VASP Merkle tree ──────────────────────────────────────────────

// MerkleTree is a Poseidon2 Merkle tree over the registered-VASP set. Inner
// nodes are domain-separated under DomainMerkleNode (hashNode), distinct from
// the identity/amount commitment domains. Leaves are the raw member field
// elements (feFromBytes) and are not themselves hashed.
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
			next[i/2] = hashNode(cur[i], cur[i+1])
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
