package zkproof_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

// TestUnifiedAnchor: the token's humanAnchor (zkdid.Compute) is exactly the
// value the commitment circuit proves — so a commitment proof verifies directly
// against the anchor carried in a token.
func TestUnifiedAnchor(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitCommitment)
	if err != nil {
		t.Fatal(err)
	}
	id := zkdid.TestPrincipal("alice")
	rnd := []byte("anchor-randomness-1")

	anchor := zkdid.Compute(id, rnd) // the token's humanAnchor
	proof, proved, err := art.ProveCommitment(id, rnd)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if proved.Cmp(anchor.BigInt()) != 0 {
		t.Fatalf("proven commitment %s != token humanAnchor %s", proved, anchor.BigInt())
	}
	if err := art.VerifyCommitment(proof, anchor.BigInt()); err != nil {
		t.Errorf("commitment proof must verify against the token humanAnchor: %v", err)
	}
}

func TestCommitment_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitCommitment)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	proof, anchor, err := art.ProveCommitment([]byte("alice-biometric-template"), []byte("randomness-0001"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := art.VerifyCommitment(proof, anchor); err != nil {
		t.Errorf("valid commitment proof must verify: %v", err)
	}
	// Wrong anchor must fail.
	wrong := new(big.Int).Add(anchor, big.NewInt(1))
	if err := art.VerifyCommitment(proof, wrong); err == nil {
		t.Error("commitment proof must fail against a tampered anchor")
	}
}

// TestSaveLoad_CrossInstanceVerify proves the key property for a two-party
// service: a proof made by the prover verifies against a vk that a separate
// (verifier-only) instance loaded from disk — i.e. setup is shared, not redone.
func TestSaveLoad_CrossInstanceVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitCommitment)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := art.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	proof, anchor, err := art.ProveCommitment([]byte("alice-template"), []byte("rand-1"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	ver, err := zkproof.LoadVerifier(zkproof.CircuitCommitment, dir)
	if err != nil {
		t.Fatalf("load verifier: %v", err)
	}
	if err := ver.VerifyCommitment(proof, anchor); err != nil {
		t.Errorf("proof must verify against vk loaded from disk: %v", err)
	}
	if err := ver.VerifyCommitment(proof, new(big.Int).Add(anchor, big.NewInt(1))); err == nil {
		t.Error("tampered anchor must fail even with the disk-loaded vk")
	}
}

func TestThreshold_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitThreshold)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	const threshold = uint64(1000)
	proof, commitment, err := art.ProveThreshold(5000, []byte("amount-blinding-1"), threshold)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := art.VerifyThreshold(proof, commitment, threshold); err != nil {
		t.Errorf("valid threshold proof must verify: %v", err)
	}
	// Soundness: a sub-threshold amount cannot be proven reportable.
	if _, _, err := art.ProveThreshold(500, []byte("amount-blinding-2"), threshold); err == nil {
		t.Error("proving a sub-threshold amount as reportable must fail")
	}
}

func TestVASPMembership_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitVASP)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Build a full registry (2^depth members).
	n := 1 << zkproof.VASPTreeDepth
	members := make([][]byte, n)
	for i := range members {
		members[i] = []byte(fmt.Sprintf("vasp:member:%d", i))
	}
	tree, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}

	leaf, sibs, bits, root, ok := tree.ProofForMember([]byte("vasp:member:42"))
	if !ok {
		t.Fatal("member 42 should be in the registry")
	}
	proof, err := art.ProveVASPMembership(leaf, sibs, bits, root)
	if err != nil {
		t.Fatalf("prove membership: %v", err)
	}
	if err := art.VerifyVASPMembership(proof, root); err != nil {
		t.Errorf("valid membership proof must verify: %v", err)
	}
	// Wrong root must fail verification.
	if err := art.VerifyVASPMembership(proof, new(big.Int).Add(root, big.NewInt(1))); err == nil {
		t.Error("membership proof must fail against a wrong registry root")
	}
	// A non-member is not in the index.
	if _, _, _, _, ok := tree.ProofForMember([]byte("vasp:UNREGISTERED")); ok {
		t.Error("unregistered VASP must not produce an authentication path")
	}
}
