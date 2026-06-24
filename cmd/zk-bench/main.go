// cmd/zk-bench — isolated ZK primitive benchmark for the SPT-Txn v2 crypto choice.
//
// Measures constraints / compile / setup / prove / verify / proof-size for a
// representative circuit (N sequential 2-input field hashes) across the two
// decision axes:
//
//   hash:  MiMC      vs  Poseidon2
//   curve: BN254     vs  BLS12-381
//
// It deliberately uses a throwaway circuit (not the production circuits) so the
// benchmark cannot affect deployed code. The output is the empirical basis for
// the -02 "we measured and chose" table and the CBOM "measured" column.
//
// Run:  go run ./cmd/zk-bench            (default 200 hashes)
//       go run ./cmd/zk-bench -iters 500
package main

import (
	"bytes"
	"flag"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// hashBench computes a chain of Iters two-input hashes and constrains the result
// to be non-zero. Iters/UseP2 are plain config fields (not gnark Variables) and
// are ignored by the witness schema.
type hashBench struct {
	Pre   frontend.Variable `gnark:",secret"`
	Iters int
	UseP2 bool
}

func (c *hashBench) Define(api frontend.API) error {
	cur := c.Pre
	if c.UseP2 {
		h, err := poseidon2.New(api)
		if err != nil {
			return err
		}
		for i := 0; i < c.Iters; i++ {
			h.Reset()
			h.Write(cur, cur)
			cur = h.Sum()
		}
	} else {
		h, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		for i := 0; i < c.Iters; i++ {
			h.Reset()
			h.Write(cur, cur)
			cur = h.Sum()
		}
	}
	api.AssertIsDifferent(cur, 0)
	return nil
}

func run(curveName string, curve ecc.ID, useP2 bool, iters int) {
	hashName := "MiMC"
	if useP2 {
		hashName = "Poseidon2"
	}
	circ := &hashBench{Iters: iters, UseP2: useP2}

	t := time.Now()
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circ)
	if err != nil {
		fmt.Printf("%-10s %-10s  compile FAILED: %v\n", hashName, curveName, err)
		return
	}
	compileT := time.Since(t)
	nc := ccs.GetNbConstraints()

	t = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("%-10s %-10s  setup FAILED: %v\n", hashName, curveName, err)
		return
	}
	setupT := time.Since(t)

	w := &hashBench{Pre: 12345, Iters: iters, UseP2: useP2}
	full, err := frontend.NewWitness(w, curve.ScalarField())
	if err != nil {
		fmt.Printf("%-10s %-10s  witness FAILED: %v\n", hashName, curveName, err)
		return
	}
	pub, _ := full.Public()

	t = time.Now()
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		fmt.Printf("%-10s %-10s  prove FAILED: %v\n", hashName, curveName, err)
		return
	}
	proveT := time.Since(t)

	var buf bytes.Buffer
	_, _ = proof.WriteTo(&buf)
	proofSize := buf.Len()

	t = time.Now()
	verr := groth16.Verify(proof, vk, pub)
	verifyT := time.Since(t)
	ok := "ok"
	if verr != nil {
		ok = "VERIFY-FAIL"
	}

	fmt.Printf("%-10s %-10s  cons=%-7d  compile=%-9s setup=%-9s prove=%-9s verify=%-9s proof=%dB  %s\n",
		hashName, curveName, nc,
		compileT.Round(time.Millisecond), setupT.Round(time.Millisecond),
		proveT.Round(time.Millisecond), verifyT.Round(time.Microsecond),
		proofSize, ok)
}

func main() {
	iters := flag.Int("iters", 200, "number of sequential 2-input hashes in the bench circuit")
	flag.Parse()

	fmt.Printf("=== zk-bench: %d sequential 2-input hashes · Groth16 ===\n", *iters)
	for _, useP2 := range []bool{false, true} {
		run("BN254", ecc.BN254, useP2, *iters)
		run("BLS12-381", ecc.BLS12_381, useP2, *iters)
	}
}
