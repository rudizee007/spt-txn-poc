# Plan — agentic x402 demo on Aptos (P0-A → P4-A)

> The third chain, same blockchain-agnostic payoff as Hedera. The gate, verifier,
> escrow, merchant, and agent are unchanged; the Aptos ledger adapter
> (`internal/ledger/aptos.go`) already exists. Only the ~200-line submitter is new.

## What already works, unchanged

- **`internal/gate`** (chain-parameterized already: `gatesvc -chain aptos`).
- **`internal/ledger/aptos.go`** — Validate + Canonicalize for an Aptos transfer:
  sender/receiver as `0x…` (up to 64 hex), amount, asset `APT` (or a Move coin
  type / Fungible Asset object address). Context-hash (verifier step 8) binds to
  these fields.
- **Merchant / agent / escrow / deanon** — chain-agnostic; verify + accountability
  work as on XRPL and Hedera.

## The one new piece — `clients/aptos-pay` (built)

Submits a real APT transfer via `aptos_account::transfer(recipient, amount)` using
`aptos-go-sdk`'s `BuildSignAndSubmitTransaction`. Separate module (SDK stays out of
the core). Flags mirror the other submitters: `-to` (0x…), `-amount` (OCTAS; 1 APT =
1e8), `-currency APT`, `-memo`, `-json/-whoami/-yes/-dry-run/-network`, plus
`-sourcetag`/`-context-hash` accepted-and-ignored for agent compatibility. Reads
`APTOS_OPERATOR_KEY` (+ optional `APTOS_OPERATOR_ADDRESS`) from the env.

## The honest Aptos difference

Aptos has **no transaction memo field**. So unlike XRPL (Memo) and Hedera (tx memo),
the humanAnchor is NOT written on the Aptos transaction. It is still bound
cryptographically into the SPT-Txn attestation via the context hash — which the
merchant verifies (P2) exactly as on the other chains. To *also* surface the anchor
on-chain: you ALREADY deployed a Move anchor module on Aptos testnet
(`move/attestation_anchor` at `0x0b1f35b54e92d49d21d1badca271b9ab5686f22f82d6f88c6731cac20cbe0aa2`,
entry fn `anchor(root: vector<u8>)` taking a 32-byte root). The humanAnchor is exactly
32 bytes, so `aptos-pay` can call that module's `anchor` after the transfer to record
it on-chain — same visibility as XRPL/Hedera, and a quick add (NOT grant work). Left
out of the P0-A build to keep it minimal; wire it in as P0-A+ if you want the on-chain
anchor in the Aptos demo.

## Getting an Aptos testnet account

Simplest is the Aptos CLI (`brew install aptos`):

```
aptos init --network testnet     # generates an account, funds it from the faucet,
                                 # writes the private key to .aptos/config.yaml
```

Take the `private_key` (0x… ed25519) from `.aptos/config.yaml` → `APTOS_OPERATOR_KEY`.
Run `aptos init` a second time (a new profile) for the **destination** account, or
send to any funded 0x address. Aptos testnet has **no account reserve** and fees are
fractions of a cent (faucet gives ~1 APT, plenty).

## Run (once accounts exist)

```
export APTOS_OPERATOR_KEY='0x…'          # payer ed25519 private key
export MERCHANT_ADDR='0x…'               # destination account address

# P0-A sanity: a raw transfer, dry-run then real
clients/aptos-pay/aptos-pay -to $MERCHANT_ADDR -amount 1000 -dry-run
clients/aptos-pay/aptos-pay -to $MERCHANT_ADDR -amount 1000

# P1-A + P2-A: the full loop (gate authorize → settle → merchant verify)
CHAIN=aptos ./scripts/x402-demo.sh deny
CHAIN=aptos ./scripts/x402-demo.sh allow
CHAIN=aptos ./scripts/x402-demo.sh real
```

## Phases

- **P0-A** — build `aptos-pay`; one real testnet APT transfer. (Done building; needs
  a testnet account + Mac build. First build may need 1–2 SDK-API tweaks on the
  account-from-key path — the transfer flow is verified against the SDK example.)
- **P1-A / P2-A** — the loop + merchant verify, free via `CHAIN=aptos`.
- **P3-A** — escrow + lawful deanon, already chain-agnostic (`cmd/deanondemo`).
- **P4-A** — one Aptos **mainnet** transfer (tiny APT, `-yes` gate) — the on-chain
  footprint for the grant.

## Grant tie-in

The Aptos **Payments Grant** explicitly funds compliance layers; a live agentic
Travel-Rule/authorization demo on Aptos (complementing the Confidential Asset
standard, with Move account-abstraction as the agentic angle) is the direct
deliverable. This is a rolling/merit grant — the best-fit open door of the three.
