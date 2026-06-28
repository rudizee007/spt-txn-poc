// Module spt-txn-trisa-transport is the TRISA Secure Envelope transport for
// SPT-Txn Travel Rule payloads. It is a SEPARATE module on purpose: the sealing
// core below is pure standard library (no external deps), and the gRPC/GDS/mTLS
// wire — when added — pulls in the TRISA Go SDK + grpc + protobuf, which must not
// pollute the dependency-light core module.
//
//	go test ./...   # sealing core, fully offline
module github.com/violetskysecurity/spt-txn-trisa-transport

go 1.25.7
