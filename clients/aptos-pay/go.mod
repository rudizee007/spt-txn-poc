// Separate module: the Aptos SDK is chain-specific, so it stays out of the
// offline core (blockchain-agnostic invariant) — same quarantine as
// clients/hcs-anchor and clients/hedera-pay.
//
// First build on the Mac:
//   cd clients/aptos-pay
//   go get github.com/aptos-labs/aptos-go-sdk@latest
//   go mod tidy && go build -o aptos-pay .
module github.com/rudizee007/spt-txn-poc/clients/aptos-pay

go 1.26.0

require github.com/aptos-labs/aptos-go-sdk v1.14.0

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hasura/go-graphql-client v0.16.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)
