# SPT-Txn Attestation Anchor — Sui / Move

An append-only attestation anchor for Sui, mirroring the Aptos/Cairo/Solidity
anchors in Sui's object model: a single **shared** `AnchorBook` object (created by
the module initializer at publish) that anyone can append a 32-byte root to.
`anchor` records the root, the `tx_context::sender`, and the epoch timestamp, and
emits an `Anchored` event. Pairs with the off-chain `internal/ledger/sui.go`
adapter and Sui grant milestone 1.

## Build & test (needs the Sui CLI — `sui --version`)

```
cd sui/attestation_anchor
sui move build
sui move test
```

If `build` complains about the edition or framework API, bump `edition` and the
Sui dependency `rev` in `Move.toml` to match your CLI.

## Publish + anchor a real token-derived hash (testnet; your action)

```
sui client publish --gas-budget 100000000
# note the published Package ID and the shared AnchorBook object ID from the output

# real spt_txn_context_hash from the main module:
HASH=$(cd ../.. && go run ./cmd/anchor -chain sui | awk '/spt_txn_context_hash/{print $3}')

sui client call --package <PACKAGE_ID> --module attestation_anchor --function anchor \
  --args <ANCHORBOOK_OBJECT_ID> 0x$HASH --gas-budget 100000000
```

The `root` argument is a `vector<u8>`; the Sui CLI accepts the 32-byte value as a
`0x`-prefixed hex string. If your CLI version wants a byte array instead, pass it
as `"[<comma-separated bytes>]"`.

Read it back (free): inspect the `AnchorBook` object or the `Anchored` events on a
Sui explorer (e.g. suiscan / suivision testnet), or `sui client object <ID>`.

## Notes

- Anchoring is your action (it spends testnet SUI from a funded address) — Claude
  cannot publish contracts or move funds.
- The anchor is open by design (an append-only public log); for a mainnet
  deployment add access control or an anti-spam fee first.
- Only a 32-byte hash is published — no PII, no token contents.
