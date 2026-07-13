package wlapi

// The production Source backed by the SPIFFE Workload API (go-spiffe) lives in a
// SEPARATE nested Go module at ./spire — see internal/wlapi/spire.
//
// It is isolated on purpose: go-spiffe pulls in grpc/protobuf/go-jose, and this
// module (spt-txn-poc) must not carry those in its dependency graph for code
// that only runs against a live SPIRE agent. This module stays standard-library
// only; the SPIRE integration is opt-in by building the ./spire submodule.
