// cmd/zk-setup — one-time trusted setup for the SPT-Txn ZK Travel Rule circuits.
//
// groth16.Setup is randomized, so the originator (prover) and beneficiary
// (verifier) services must share keys from a SINGLE setup. Run this once to
// generate and persist the proving/verifying keys; the services then load them.
//
//	zk-setup [-dir /var/spt-txn/zk]
//
// Security note: the verifying keys (.vk) are the trust anchor for proof
// verification — distribute them with integrity. The proving keys (.pk) only
// need to reach the prover. Treat the whole directory as setup output to be
// generated once and pinned (see SECURITY-REVIEW.md, ZK trusted setup).
package main

import (
	"flag"
	"log"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

func main() {
	dir := flag.String("dir", "/var/spt-txn/zk", "output directory for circuit keys")
	flag.Parse()

	log.SetPrefix("zk-setup: ")
	log.SetFlags(log.Ltime)

	circuits := []zkproof.CircuitID{
		zkproof.CircuitCommitment,
		zkproof.CircuitThreshold,
		zkproof.CircuitVASP,
	}
	for _, id := range circuits {
		t0 := time.Now()
		art, err := zkproof.Setup(id)
		if err != nil {
			log.Fatalf("setup %s: %v", id, err)
		}
		if err := art.Save(*dir); err != nil {
			log.Fatalf("save %s: %v", id, err)
		}
		log.Printf("%-10s ready in %-7v (%d constraints) -> %s/%s.{ccs,pk,vk}",
			id, time.Since(t0).Round(time.Millisecond), art.NbConstraints(), *dir, id)
	}
	log.Printf("trusted setup complete in %s", *dir)
}
