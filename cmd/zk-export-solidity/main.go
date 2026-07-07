// Command zk-export-solidity generates a Solidity Groth16 verifier for one of
// the SPT-Txn ZK circuits, so an Ethereum / EVM L2 contract can verify an
// SPT-Txn selective-disclosure proof on-chain.
//
// It exports from a PINNED verifying key produced by `zk-setup` (not a fresh
// random setup), so the on-chain verifier matches the key the prover uses.
//
//	zk-setup -dir /var/spt-txn/zk                      # once, if not already done
//	zk-export-solidity -circuit threshold -dir /var/spt-txn/zk -o solidity/src/Groth16Verifier.sol
//
// Circuits: commitment (identity), threshold (amount-over-threshold, amount
// hidden), vasp (counterparty-VASP membership). `threshold` is the cleanest
// single-predicate starting point for an on-chain demo.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

func main() {
	circuit := flag.String("circuit", "threshold", "circuit: commitment | threshold | vasp")
	dir := flag.String("dir", "/var/spt-txn/zk", "directory holding the pinned setup keys (from zk-setup)")
	out := flag.String("o", "solidity/src/Groth16Verifier.sol", "output Solidity file")
	flag.Parse()

	log.SetPrefix("zk-export-solidity: ")
	log.SetFlags(0)

	art, err := zkproof.LoadVerifier(zkproof.CircuitID(*circuit), *dir)
	if err != nil {
		log.Fatalf("load verifying key for %q from %s: %v (run zk-setup first)", *circuit, *dir, err)
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("create %s: %v", *out, err)
	}
	defer f.Close()

	if err := art.ExportSolidity(f); err != nil {
		log.Fatalf("export solidity: %v", err)
	}
	log.Printf("wrote %s verifier -> %s", *circuit, *out)
	log.Printf("next: deploy it, then have AttestationAnchor call its verifyProof(...) before recording a root")
}
