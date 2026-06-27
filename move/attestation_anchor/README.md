# SPT-Txn Attestation Anchor (Aptos / Move)

A minimal Move module that anchors SPT-Txn attestation roots (32-byte SHA-256
values) on Aptos. It's the on-chain half of the Aptos integration — the off-chain
transaction-binding lives in `internal/ledger/aptos.go`. Publishing this to
**Aptos testnet** gives the grant application a real module address + an on-chain
footprint (mirrors the Starknet Cairo `attestation_anchor` and the Solana memo
anchors).

> Aptos framework versions move fast. If `aptos move compile` errors on a
> framework API, bump the `rev` in `Move.toml` to match your `aptos --version`.

## Prerequisites
- **Aptos CLI** — `brew install aptos` (or https://aptos.dev/tools/aptos-cli/).
- A **testnet account** with a little testnet APT (the faucet is wired into
  `aptos init` below).

## One-time: create + fund a testnet account
```
cd move/attestation_anchor
aptos init --network testnet     # creates ./.aptos/config.yaml (holds your key — GITIGNORED), funds from faucet
```
`aptos init` writes the active profile's account address into `.aptos/config.yaml`.
Note that address — it's your `spt_txn` named address and the AnchorBook owner.
**Never commit `.aptos/` — it contains your private key.**

## Compile + test
```
# compile against your account (use the address aptos init printed, or `default`)
aptos move compile --named-addresses spt_txn=default

# run the Move unit tests
aptos move test --named-addresses spt_txn=default
```

## Publish to testnet
```
aptos move publish --named-addresses spt_txn=default --assume-yes
# → prints the published module/account address  ← list this in the grant form
```

## Initialize the anchor book + anchor a root
```
# 1. create the AnchorBook once under your account
aptos move run --function-id default::attestation_anchor::init_book --assume-yes

# 2. anchor a 32-byte SHA-256 root. Pass book_owner (your address) + the root as hex.
#    Use a REAL SPT-Txn ContextHash so the on-chain anchor ties to an actual token.
aptos move run \
  --function-id default::attestation_anchor::anchor \
  --args address:default hex:0x4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9 \
  --assume-yes
```

## Read it back (view functions — no gas)
```
aptos move view --function-id default::attestation_anchor::get_count   --args address:default
aptos move view --function-id default::attestation_anchor::get_anchor  --args address:default u64:0
```
View on an Aptos explorer: `https://explorer.aptoslabs.com/account/<ADDR>?network=testnet`.

## For the grant
- **On-chain footprint:** the published module address + the `anchor` tx(s).
- **Pitch the next steps:** (1) a **Confidential-Asset-complementary** flow — a CA
  transfer carrying an SPT-Txn ZK Travel Rule attestation (counterparty gets only
  the FATF-required fields, amount hidden); (2) a **Move account-abstraction
  capability account** that enforces a Capability Token's scope + delegation depth
  on-chain. This anchor module is M1; those are the funded milestones.
- **Honest framing:** testnet footprint demonstrates anchoring; mainnet + the
  CA-complementary Travel Rule + the AA capability account are the funded work.
  Complement Aptos's Confidential Asset standard; never duplicate its auditor key.
