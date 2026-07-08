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
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

func main() {
	dir := flag.String("dir", "/var/spt-txn/zk", "output directory for circuit keys")
	only := flag.String("only", "", "comma-separated subset to (re)generate, e.g. addrthreshold,eligibility; empty = all. Use this to add the RWA circuits WITHOUT regenerating already-pinned/deployed keys.")
	flag.Parse()

	log.SetPrefix("zk-setup: ")
	log.SetFlags(log.Ltime)

	all := []zkproof.CircuitID{
		zkproof.CircuitCommitment,
		zkproof.CircuitThreshold,
		zkproof.CircuitVASP,
		zkproof.CircuitChain,
		zkproof.CircuitAddrThreshold, // RWA Tier 1 (address-bound attribute)
		zkproof.CircuitEligibility,   // RWA Tier 2 (issuer-bound eligibility)
	}

	var circuits []zkproof.CircuitID
	if strings.TrimSpace(*only) == "" {
		circuits = all
	} else {
		want := map[string]bool{}
		for _, s := range strings.Split(*only, ",") {
			want[strings.TrimSpace(s)] = true
		}
		for _, id := range all {
			if want[string(id)] {
				circuits = append(circuits, id)
			}
		}
		if len(circuits) == 0 {
			log.Fatalf("no known circuits matched -only=%q (known: commitment,threshold,vasp,chain,addrthreshold,eligibility)", *only)
		}
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
