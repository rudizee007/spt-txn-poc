# SPT-Txn Proof of Concept

A reference implementation of `draft-coetzee-oauth-spt-txn-tokens-01` for
`foss.violetskysecurity.com`, demonstrating cross-domain SPT-Txn token issuance
and verification with a combined human-plus-agent holder flow.

## Scope of this POC

- **Two trust domains** (Domain A: AuthOrg, Domain B: ExecOrg), both running on
  the same OpenBSD host, separated by services / users / keys / audit logs.
- **Combined holder flow**: a human user authenticates and obtains an SD-JWT
  in their wallet, then delegates a Capability Acquisition Token to an AI
  agent which executes the cross-domain transaction.
- **Mock Trust Registry first** (SQLite-backed), with the same interface
  used later by an EVM testnet Trust Registry implementation.
- **Reference verifier** implementing the eight-step enforcement engine from
  Section 3.3 of the draft.
- **Audit log** with Merkle-root publication.

## What this POC is NOT

- Not a production-ready implementation.
- Not a complete ZK circuit implementation. The Groth16 over BN254 circuits
  from Section 5 are stubbed (commitment is correct shape, proof is a
  fixed-size placeholder). Real ZK is a v2 task.
- Not a complete threshold escrow implementation. The Section 9.6 escrow is
  implemented with single-party ECIES for the POC; FROST-based threshold
  decryption is a v2 task documented in
  [`docs/ESCROW-FUTURE-WORK.md`](docs/ESCROW-FUTURE-WORK.md).
- Not a chain integration. The Trust Registry interface is identical for both
  mock and chain backends, so the swap is mechanical once the mock POC is
  validated. Chain backend is a v2 task.

## Read in this order

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — what gets built, how it
   fits together, how Domain A and Domain B interact.
2. [`docs/OPENBSD-SETUP.md`](docs/OPENBSD-SETUP.md) — concrete provisioning
   steps for `foss.violetskysecurity.com`. Do this first if you're
   provisioning today.
3. [`docs/DEMO-FLOW.md`](docs/DEMO-FLOW.md) — the end-to-end demonstration
   scenario the POC executes successfully.
4. [`docs/TEST-PLAN.md`](docs/TEST-PLAN.md) — what gets tested, at what level,
   with what tools.
5. [`docs/BUILD-ORDER.md`](docs/BUILD-ORDER.md) — the order to build things in
   so the POC works end-to-end at each milestone.

## Status

This is the initial skeleton. The Trust Registry interface and mock
implementation are in place; the rest is documented but not yet implemented.

See [`docs/BUILD-ORDER.md`](docs/BUILD-ORDER.md) for milestone tracking.
