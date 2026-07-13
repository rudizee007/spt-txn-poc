# wlapi/spire — SPIFFE Workload API adapter (isolated module)

Production `wlapi.Source` backed by the SPIFFE Workload API (`go-spiffe`).

**This is a separate Go module on purpose.** `go-spiffe` pulls in
`grpc`/`protobuf`/`go-jose`; keeping the adapter here means those dependencies
never enter the parent `spt-txn-poc` module's graph, SBOM, or `govulncheck`
surface. The parent module stays standard-library-only; the verifier core
(`internal/attest`) is untouched. Dependency direction is one-way:
`spire → parent`, never the reverse.

## Build & use (needs a running SPIRE agent)

```sh
cd internal/wlapi/spire
go mod tidy          # resolves go-spiffe + transitive deps into this module's go.sum
go build ./...

# then, with a SPIRE agent reachable via the Workload API socket:
export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
```

```go
id, err := spire.VerifiedIdentity(ctx, []string{"spt-txn-exchange"})
// id is a verified attest.Identity; all crypto is done by internal/attest.
```

All signature, trust-domain, audience, and temporal checks are delegated to the
parent's `wlapi` + `attest`. This module only performs SPIFFE I/O.
