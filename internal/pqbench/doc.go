// Package pqbench holds benchmarks that quantify the cost of post-quantum
// migration for SPT-Txn: token sign/verify/size on the classical (Ed25519) hot
// path versus the hybrid X25519 + ML-KEM-768 KEM used by the escrow, plus keygen
// measured separately (it is NOT on the per-transaction hot path — the holder key
// is long-lived; see pqbench_test.go).
//
// Run:
//
//	go test -bench=. -benchmem ./internal/pqbench/          # latency + allocs
//	go test -run TestWireSizes -v ./internal/pqbench/       # token / envelope bytes
//
// PQ-signature (ML-DSA) impact is a PROJECTION, not benchmarked here: token
// signatures are still classical Ed25519 (ML-DSA is not yet wired). See
// docs/PQ-BENCH-RESULTS.md for the ML-DSA-65 size projection to layer on top.
//
// For stable percentiles across runs, use benchstat:
//
//	go test -bench=. -count=10 ./internal/pqbench/ | tee bench.txt && benchstat bench.txt
package pqbench
