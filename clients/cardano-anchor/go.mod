// Separate module: the Cardano SDK is heavy and chain-specific, so it stays out
// of the offline core (blockchain-agnostic invariant) — same quarantine as the
// other chain clients. Cardano = anchor pattern (native tx metadata, no Plutus),
// mirroring the Sui/Aptos/Starknet anchors.
//
// First build on the Mac (echovl/cardano-go is WIP — expect a couple of API
// tweaks; see LIB-CHECK markers in main.go):
//   cd clients/cardano-anchor
//   go get github.com/echovl/cardano-go@latest
//   go mod tidy && go build -o cardano-anchor .
module github.com/violetskysecurity/spt-txn-poc/clients/cardano-anchor

go 1.24.0

require github.com/echovl/cardano-go v0.1.13
