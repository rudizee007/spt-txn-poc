# SPT-Txn Attestation Anchor (Starknet / Cairo)

A minimal Cairo contract that anchors SPT-Txn attestation roots (32-byte SHA-256
values, as `u256`) on Starknet. It's the on-chain half of the Starknet
integration — the off-chain transaction-binding lives in
`internal/ledger/starknet.go`. Deploying this to **Starknet Sepolia testnet**
gives the Seed-grant application a real contract address and an on-chain footprint
(mirrors the Solana/Stellar memo-anchor footprints).

> Cairo/Scarb versions move fast. This is scaffolded against Cairo/Scarb 2.x. If
> `scarb build` errors on the edition or the storage API, adjust `Scarb.toml` and
> the `starknet::storage` imports in `src/lib.cairo` to match `scarb --version`.

## Prerequisites
- **Scarb** (Cairo toolchain) — https://docs.swmansion.com/scarb/ (asdf or the installer).
- **Starkli** (deploy CLI) — https://github.com/xJonathanLEI/starkli, or use `sncast` (starknet-foundry).
- A **Sepolia testnet account** with a little testnet ETH/STRK (faucet:
  https://starknet-faucet.vercel.app or the Starknet Sepolia faucet).

## Build
```
cd cairo/attestation_anchor
scarb build
# → target/dev/spt_attestation_anchor_AttestationAnchor.contract_class.json
```

## One-time: create + fund a Sepolia account (starkli)
```
starkli signer keystore new spt-sepolia-key.json          # encrypted keystore (set a password)
export STARKNET_RPC=https://starknet-sepolia.public.blastapi.io/rpc/v0_8
export STARKNET_KEYSTORE=spt-sepolia-key.json
starkli account oz init spt-sepolia-account.json           # prints the precomputed ADDRESS
# Fund that ADDRESS with Sepolia ETH/STRK from a faucet (https://starknet-faucet.vercel.app),
# then deploy the account (one-time):
starkli account deploy spt-sepolia-account.json
export STARKNET_ACCOUNT=spt-sepolia-account.json
```
(Key/account JSON files are gitignored — never commit them.)

## Deployed (Sepolia, 2026-06-27)
- **Contract:** `0x0620fe8ccb9c19fe9acce44dccc6a6a3d851974dcd97f05949982453de853de1`
- **Class hash:** `0x00ecd8662aa1415da28b4a9df42752d5d8c46479200c9141ec57283f1439f318`
- **Explorer:** https://sepolia.voyager.online/contract/0x0620fe8ccb9c19fe9acce44dccc6a6a3d851974dcd97f05949982453de853de1
- **Toolchain that worked:** Cairo/scarb **2.18** (Sierra 1.8) + **sncast 0.62** (starknet-foundry), `--network sepolia`.
- **What did NOT work:** **starkli 0.4.2** — too old for current Sepolia. It rejects Sierra 1.8 ("unsupported Sierra version"), and on a downgraded Sierra 1.6 it computes a stale CASM compiled-class-hash the network rejects ("Mismatch compiled class hash"). Account *deploy* worked under starkli (no CASM in that tx type), but *declare* does not. Use sncast.

## Declare + deploy with sncast (starknet-foundry) — recommended
```
cd cairo/attestation_anchor
scarb clean && scarb build

# import an existing OZ account (private key from a starkli keystore: starkli signer keystore inspect-private <key>.json)
sncast account import --name spt --address <ACCOUNT_ADDR> --type oz --private-key <PK> --network sepolia

sncast --account spt declare --contract-name AttestationAnchor --network sepolia   # → CLASS_HASH
sncast --account spt deploy --class-hash <CLASS_HASH> --network sepolia            # → CONTRACT_ADDRESS

# anchor a u256 root (serialized low, high) and read back:
sncast --account spt invoke --contract-address <ADDR> --function anchor --calldata <LOW> <HIGH> --network sepolia
sncast call --contract-address <ADDR> --function get_count --network sepolia
sncast call --contract-address <ADDR> --function get_anchor --calldata 0x0 --network sepolia
```
`--network sepolia` lets sncast pick a public RPC matching its expected spec (0.10); a hardcoded v0_8 URL fails with "Invalid block id". Public nodes can flake with a transient "Internal error" — just retry.

## Declare + deploy to Sepolia (starkli) — DEPRECATED, fails on current Sepolia
```
# with STARKNET_RPC / STARKNET_KEYSTORE / STARKNET_ACCOUNT exported above

# 1. declare the class
starkli declare target/dev/spt_attestation_anchor_AttestationAnchor.contract_class.json \
  --account <your-account.json> --keystore <your-key.json>
# → prints a CLASS_HASH

# 2. deploy an instance (no constructor args)
starkli deploy <CLASS_HASH> --account <your-account.json> --keystore <your-key.json>
# → prints the CONTRACT_ADDRESS  ← this is what you list in the grant form
```

## Anchor a root + read it back
```
# anchor a 32-byte SHA-256 root (u256 = two felts: low, high). With starkli you can
# pass a 0x value and let it split, or pass low/high explicitly. Example:
starkli invoke <CONTRACT_ADDRESS> anchor u256:0x4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9 \
  --account <your-account.json> --keystore <your-key.json>

starkli call <CONTRACT_ADDRESS> get_count
starkli call <CONTRACT_ADDRESS> get_anchor u64:0
```
Use a **real** SPT-Txn attestation root (the `ContextHash` the POC produces) so the
on-chain anchor ties to an actual token. View on a Sepolia explorer:
`https://sepolia.starkscan.co/contract/<CONTRACT_ADDRESS>`.

## For the Seed grant
- **On-chain footprint:** the deployed `CONTRACT_ADDRESS` + the `anchor` tx(s).
- **Pitch the next step:** a **capability smart-account** (native account abstraction)
  that enforces an SPT-Txn Capability Token's scope + delegation depth on-chain —
  the agentic deliverable. This anchor contract is M1; the AA capability account is M2.
- **Honest framing:** testnet footprint demonstrates anchoring; mainnet + the AA
  capability account + STRK20-complementary Travel Rule are the funded milestones.
