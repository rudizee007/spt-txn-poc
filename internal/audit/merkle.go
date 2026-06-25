package audit

// merkle.go — Merkle root over audit entries with Ed25519-signed publication.
//
// Each domain periodically computes a Merkle root over its audit entries and
// signs it with its registered audit key (trustregistry role "audit"). The
// signed root is a small, publishable commitment to the entire log at a point
// in time: an auditor who later receives the full log can recompute the root
// and confirm it matches a previously published, signed value — proving no
// entry was altered or removed after publication.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// Merkle domain-separation tags (RFC 6962 style): leaves and interior nodes are
// hashed under distinct prefixes so no interior node can be reinterpreted as a
// leaf (or vice versa), and the duplicate-last-node second-preimage ambiguity
// (CVE-2012-2459) is removed by promoting an unpaired node unchanged instead of
// hashing it with itself.
const (
	leafPrefix     = 0x00
	interiorPrefix = 0x01
)

// MerkleRoot returns the SHA-256 Merkle root over the entries' hashes, using
// RFC 6962 leaf/interior domain separation. An odd node at a level is promoted
// to the next level unchanged (no self-duplication). Empty input yields nil.
func MerkleRoot(entries []Entry) []byte {
	if len(entries) == 0 {
		return nil
	}
	layer := make([][]byte, len(entries))
	for i, e := range entries {
		layer[i] = hashLeaf(e.Hash)
	}
	for len(layer) > 1 {
		next := make([][]byte, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			if i+1 < len(layer) {
				next = append(next, hashInterior(layer[i], layer[i+1]))
			} else {
				next = append(next, layer[i]) // promote unpaired node unchanged
			}
		}
		layer = next
	}
	return layer[0]
}

// hashLeaf computes SHA-256(0x00 || entryHash).
func hashLeaf(entryHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entryHash)
	return h.Sum(nil)
}

// hashInterior computes SHA-256(0x01 || left || right).
func hashInterior(a, b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{interiorPrefix})
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// SignedRoot is a published, signed commitment to the log at a point in time.
type SignedRoot struct {
	Root  []byte // Merkle root
	Count int    // number of entries covered
	Time  int64  // publication time (unix seconds)
	Sig   []byte // Ed25519 signature over (Root || Count || Time)
}

// signingBytes is the deterministic preimage that is signed and verified.
func (sr SignedRoot) signingBytes() []byte {
	buf := make([]byte, 0, len(sr.Root)+16)
	buf = append(buf, sr.Root...)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(sr.Count))
	buf = append(buf, n[:]...)
	binary.BigEndian.PutUint64(n[:], uint64(sr.Time))
	buf = append(buf, n[:]...)
	return buf
}

// PublishRoot computes the Merkle root over entries and signs it with the
// domain's audit key.
func PublishRoot(entries []Entry, auditKey ed25519.PrivateKey) SignedRoot {
	sr := SignedRoot{
		Root:  MerkleRoot(entries),
		Count: len(entries),
		Time:  time.Now().UTC().Unix(),
	}
	sr.Sig = ed25519.Sign(auditKey, sr.signingBytes())
	return sr
}

// VerifyRoot checks the signature on a published root against the audit public
// key. It does not recompute the root from a log; pair it with MerkleRoot over
// a presented log to confirm the log matches the published commitment.
func VerifyRoot(sr SignedRoot, auditPub ed25519.PublicKey) bool {
	return ed25519.Verify(auditPub, sr.signingBytes(), sr.Sig)
}

// RootHex is the hex encoding of the root, convenient for publishing to a file.
func (sr SignedRoot) RootHex() string { return hex.EncodeToString(sr.Root) }
