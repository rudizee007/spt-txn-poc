// Command rwa-membership-calldata generates the calldata for the
// CompliantRWAToken *membership gate*. It builds the approved-holder Merkle tree,
// proves a chosen holder's membership in ZERO KNOWLEDGE (which holder is hidden),
// and prints the tree ROOT (the token's `eligibleHoldersRoot`), the Solidity-encoded
// proof bytes, and a ready-to-run `register(...)` cast snippet.
//
// Run from the repo root with the pinned keys produced by zk-setup:
//
//	go run ./cmd/rwa-membership-calldata -dir ./zk -member alice@rwa -addr 0xYourRWAToken
//
// The VASP circuit's single public input is the Merkle root, so the token's
// `eligibleHoldersRoot` MUST equal the printed root for the on-chain verify to pass.
// Flip a byte in the proof and register() reverts — membership is genuinely checked.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

func main() {
	dir := flag.String("dir", "./zk", "directory with pinned setup keys (from zk-setup)")
	member := flag.String("member", "alice@rwa", "holder id to prove membership for (must be in the set)")
	addr := flag.String("addr", "<RWA_TOKEN>", "deployed CompliantRWAToken address (for the register snippet)")
	account := flag.String("account", "holderB", "cast keystore account name for the register snippet")
	flag.Parse()

	log.SetPrefix("rwa-membership-calldata: ")
	log.SetFlags(0)

	art, err := zkproof.Load(zkproof.CircuitVASP, *dir)
	if err != nil {
		log.Fatalf("load vasp keys from %s: %v (run: go run ./cmd/zk-setup -dir %s)", *dir, err, *dir)
	}

	// The approved-holder set is exactly 2^VASPTreeDepth members. Slot 0 is the
	// holder we prove; the rest are deterministic padding members so the tree is
	// full and reproducible. In production these are the real approved-holder ids.
	const n = 1 << 8 // VASPTreeDepth = 8 -> 256
	members := make([][]byte, n)
	members[0] = []byte(*member)
	for i := 1; i < n; i++ {
		members[i] = []byte(fmt.Sprintf("spt-rwa-holder-%03d", i))
	}
	tree, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		log.Fatalf("build registry: %v", err)
	}

	leaf, sibs, bits, root, ok := tree.ProofForMember([]byte(*member))
	if !ok {
		log.Fatalf("member %q not found in the built set", *member)
	}
	proof, err := art.ProveVASPMembership(leaf, sibs, bits, root)
	if err != nil {
		log.Fatalf("prove membership: %v", err)
	}
	if err := art.VerifyVASPMembership(proof, root); err != nil {
		log.Fatalf("native self-verify failed (proof would revert on-chain): %v", err)
	}
	solProof, err := zkproof.MarshalProofSolidity(proof)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	fmt.Println("CompliantRWAToken membership gate — VASP circuit")
	fmt.Println("============================================================")
	fmt.Printf("  member (secret) : %s\n", *member)
	fmt.Printf("  holders root    : %s\n", root.String())
	fmt.Printf("    → set the token's eligibleHoldersRoot to this exact value\n")
	fmt.Printf("  proof (bytes)   : %s\n\n", solProof)
	fmt.Println("  register (membership-only) cast snippet:")
	fmt.Printf("    cast send %s \"register(bytes,bytes,uint256)\" \\\n", *addr)
	fmt.Printf("      %s 0x 0 \\\n", solProof)
	fmt.Printf("      --rpc-url \"$SEPOLIA\" --account %s\n", *account)
	fmt.Println("\n  (dual gate: put the attribute proof in arg 2 and its commitment in arg 3)")
}
