// Package vaspregistry is the registered-VASP set: a config-loaded list of VASP
// identifiers committed to a MiMC Merkle tree (internal/zkproof), with a signed
// root so the originator and beneficiary can confirm they share the same
// registry. Membership in this set is what the VASP-membership ZK circuit proves
// (a counterparty is registered) without revealing which member.
//
// The tree is fixed-depth (zkproof.VASPTreeDepth); a registry with fewer members
// is padded with deterministic non-member sentinels, and one with more is an
// error (raise the depth for real capacity).
package vaspregistry

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

// Config is the on-disk registry file: a list of VASP identifiers.
type Config struct {
	VASPs []string `json:"vasps"`
}

// Registry is a loaded registered-VASP set.
type Registry struct {
	tree    *zkproof.MerkleTree
	members map[string]bool
	count   int
}

// Load reads a registry config file and builds the committed tree.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vaspregistry: read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("vaspregistry: parse %s: %w", path, err)
	}
	return FromMembers(cfg.VASPs)
}

// FromMembers builds a registry from an in-memory member list (padding to the
// fixed tree size). Useful for tests and a built-in default.
func FromMembers(vasps []string) (*Registry, error) {
	capacity := 1 << zkproof.VASPTreeDepth
	if len(vasps) > capacity {
		return nil, fmt.Errorf("vaspregistry: %d members exceeds capacity %d (raise VASPTreeDepth)", len(vasps), capacity)
	}
	leaves := make([][]byte, capacity)
	members := make(map[string]bool, len(vasps))
	for i := 0; i < capacity; i++ {
		if i < len(vasps) {
			leaves[i] = []byte(vasps[i])
			members[vasps[i]] = true
		} else {
			leaves[i] = []byte(fmt.Sprintf("vasp:_unused_slot_%d", i)) // non-member filler
		}
	}
	tree, err := zkproof.BuildVASPRegistry(leaves)
	if err != nil {
		return nil, err
	}
	return &Registry{tree: tree, members: members, count: len(vasps)}, nil
}

// Tree exposes the underlying Merkle tree for proof generation.
func (r *Registry) Tree() *zkproof.MerkleTree { return r.tree }

// Root is the registry's Merkle root (public input to the membership proof).
func (r *Registry) Root() *big.Int { return r.tree.Root() }

// Has reports whether a VASP identifier is registered.
func (r *Registry) Has(vasp string) bool { return r.members[vasp] }

// Count is the number of real (non-filler) members.
func (r *Registry) Count() int { return r.count }

// ── signed root publication ──────────────────────────────────────────────────

// SignedRoot is a published, signed commitment to the registry root so parties
// can confirm they are evaluating membership against the same registry.
type SignedRoot struct {
	Root  string `json:"root"`  // decimal Merkle root
	Count int    `json:"count"` // number of real members
	Sig   []byte `json:"sig"`   // Ed25519 over signingBytes()
}

func signingBytes(root string, count int) []byte {
	return []byte(fmt.Sprintf("spt-txn-vasp-registry-v1|%s|%d", root, count))
}

// Publish signs the registry root with the registry authority's key.
func (r *Registry) Publish(key ed25519.PrivateKey) SignedRoot {
	root := r.Root().Text(10)
	sr := SignedRoot{Root: root, Count: r.count}
	sr.Sig = ed25519.Sign(key, signingBytes(root, r.count))
	return sr
}

// VerifyRoot checks a published root's signature against the authority key.
func VerifyRoot(sr SignedRoot, pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, signingBytes(sr.Root, sr.Count), sr.Sig)
}
