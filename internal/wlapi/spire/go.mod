// Nested module: the SPIFFE Workload API adapter. Kept separate so its
// grpc/protobuf/go-jose/go-spiffe dependencies stay OUT of the parent
// spt-txn-poc module's graph. Build/use it only when integrating a live SPIRE
// agent. It depends on the parent (via a local replace) for the wlapi.Source
// interface and attest.Identity; the parent never depends on this module.
module github.com/rudizee007/spt-txn-poc/internal/wlapi/spire

go 1.25.7

require (
	github.com/rudizee007/spt-txn-poc v0.0.0
	github.com/spiffe/go-spiffe/v2 v2.8.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/rudizee007/spt-txn-poc => ../../..
