# Hedera Consensus Service anchoring (grant milestone A1)

This document specifies how SPT-Txn anchors its attestations to the **Hedera
Consensus Service (HCS)** — Hedera grant milestone A1 — and why the design keeps
the ledger entirely outside the authorization core.

## What is anchored, and why

SPT-Txn binds each authorization to a transaction by a deterministic
`spt_txn_context_hash` (the canonical preimage produced by the `hedera` ledger
adapter), and it maintains a hash-chained audit log whose state is summarized by a
signed Merkle root. Two things are worth anchoring publicly:

- the **`spt_txn_context_hash`** of a transaction (`type: ctx`), tying a specific
  authorization to an immutable, independently-timestamped record; and
- the **audit-log Merkle root** (`type: audit`), giving the whole log a periodic,
  tamper-evident public checkpoint.

HCS is a good fit because it provides exactly what an anchor needs and nothing it
doesn't: an ordered stream of messages, each assigned a network **consensus
timestamp** and a monotonic **sequence number**, at a fixed low cost per message,
with no smart-contract surface. We anchor a hash — never PII, never token
contents — so the public record reveals nothing about the parties or the amount.

## Architecture: ledger strictly outside the core

The anchoring client lives in its **own Go module**, `clients/hcs-anchor/`, with
its own `go.mod` that requires the Hedera SDK (`github.com/hiero-ledger/hiero-sdk-go/v2`).
The main `spt-poc` module does **not** depend on it. This makes the
blockchain-agnostic invariant structural, not aspirational: the verifier and token
packages *cannot* import a ledger SDK, because it is not in their module graph. It
mirrors how the other chains are handled — the core computes the hash; a chain-side
tool submits it.

The design has a deliberate **write/verify asymmetry**:

- **Write (anchor)** needs the operator key, HBAR, and the SDK → the separate
  module's `create-topic` and `anchor` subcommands. This is an operator action.
- **Verify** needs none of that → the `verify` subcommand (and a plain `curl`)
  read the **public mirror-node REST API**
  (`/api/v1/topics/{id}/messages`), decode each message envelope, and confirm a
  matching hash with its consensus timestamp + sequence number. Trust-minimized,
  free, and runnable by anyone — including, in JavaScript, the public website.

This is the same shape as the on-chain EVM/Cairo/Move anchors: anchoring is the
operator's funded action; verification is open and keyless.

## Message envelope

A tiny, versioned, self-describing JSON body, with canonical field order:

```json
{"v":1,"t":"ctx","h":"<64-hex>","ts":1750000000}
```

`v` is the format version; `t` ∈ {`ctx`, `audit`}; `h` is the lowercase hex of the
32-byte hash/root; `ts` is the submitter's wall clock and is **informational
only** — the authoritative anchoring time is the HCS consensus timestamp the
network assigns. The encoder rejects any `h` that is not exactly 32 bytes, so a
malformed hash is never anchored. The format is small enough to fit one HCS
message (no chunking) and readable by a mirror-node consumer without the SDK.

## Security

- **Credentials**: the operator account id and private key come from the
  environment (`HEDERA_OPERATOR_ID`, `HEDERA_OPERATOR_KEY`), never command-line
  flags — flags leak through the process list and shell history. On the OpenBSD
  host the client would run privilege-separated under its own `_spt*` user with
  `pledge`/`unveil` limited to network + the key file, consistent with the other
  services.
- **No secrets on the wire or the ledger**: only a hash is published. The anchor
  is public by design; it discloses nothing about parties, amounts, or identity.
- **Testnet by default.** A mainnet anchor is permanent and public; it is a
  deliberate, funded step, not the default.
- **Key custody**: treat `HEDERA_OPERATOR_KEY` like any signing key; prefer a
  throwaway testnet key for the POC, and never reuse a testnet key on mainnet.

## Status

Built (2026-06-28): the `hedera` ledger adapter (canonical preimage,
`go test`-green); the `clients/hcs-anchor` module — envelope encode/decode with
validation (unit-tested, no network), the keyless mirror-node verifier
(standard-library HTTP), and the `create-topic` / `anchor` / `verify` CLI against
the Hiero Go SDK.

Operator-side (your action, needs a funded testnet account): `go get` the SDK +
`go build`, create a topic, anchor a real `cmd/anchor -chain hedera` hash, and
`verify` it on the mirror node — producing a live Hedera testnet footprint
comparable to the Ethereum/Starknet/Aptos/Arbitrum ones. Optional follow-ups:
schedule periodic audit-root anchoring; surface the mirror-node verify on the
public site (it is pure client-side REST).
