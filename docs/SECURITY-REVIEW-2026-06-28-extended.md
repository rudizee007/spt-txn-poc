# Security review — extended surface (2026-06-28, addendum)

Source-level review of everything added **after** `SECURITY-REVIEW-2026-06-28.md`
(which covered the F1 ZK work, the on-chain contracts, and the first adapters).
This addendum covers: the Sui Move anchor, the Hedera HCS client + `did:hedera`
binding (A1/A2), the new ledger adapters (`sui`, `polkadot`, `avalanche`,
`optimism`, `base`), and the x402 payer-gate. Run the host script for environment
checks — none of this changes the deployed host (it is new-module / Mac-side code):

```
doas sh scripts/security-audit.sh     # host unchanged; target FAIL=0
go test ./...                          # full suite incl. the new adapters
cd clients/hcs-anchor && go test .     # envelope + DID assembly/fold (no network)
cd sui/attestation_anchor && sui move test
```

## Scope reviewed

`sui/attestation_anchor` (Move); `clients/hcs-anchor` (envelope, mirror, DID,
SDK submit); `internal/ledger/{sui,polkadot,avalanche,optimism,base}.go`;
`cmd/x402gate`.

## Findings

| # | Severity | Finding |
|---|---|---|
| E1 | Low (by-design) | Open append-only anchors on Sui + Hedera (anyone can append) — spam/storage growth on **mainnet** only |
| E2 | Low | Shape-only address validation extended to the new adapters; Polkadot SS58 is **not** blake2b-checksum-validated |
| E3 | Low (process) | The Hedera client holds an operator key; key custody is env-based, testnet only |
| E4 | Info | Sui `did:hedera` are POC interpretations, not certified did-sdk; only create/generic-update fold |
| E5 | Info | x402 gate is an offline demo harness over the proven engine; no network, no new trust surface |

### E1 — open append-only anchors (Low, by-design)
The Sui `AnchorBook` (shared object) and the Hedera HCS topic both accept appends
from anyone — intentional public append-only logs, consistent with the
Solidity/Cairo/Move(Aptos) anchors (finding F2 in the prior review). They hold no
funds and only store a 32-byte hash; the submitter is recorded (`tx_context::sender`
/ HCS payer). On a public **mainnet** this allows spam / unbounded growth.
*Mitigation (mainnet only):* access control or an anti-spam fee. Not a testnet
concern.

### E2 — shape-only address validation (Low)
`sui` (0x + ≤64 hex, Move coin-type tags), `avalanche`/`optimism`/`base` (reuse
`looksLikeEVMAddress`, distinct chain tags), and `polkadot` (SS58 base58 length
window **or** 0x AccountId32) validate *shape*, not on-chain existence or
checksums — consistent with the documented POC stance for every adapter. The chain
tag in each canonical preimage prevents cross-chain hash collision (covered by
`opstack_test.go` for the four EVM chains, and the per-adapter no-collision tests).
`canonicalEncode` still rejects the reserved separator bytes, so no field
injection. *Honest gap carried forward:* Polkadot SS58 is not blake2b-checksum
verified; the EVM aliases are not EIP-55 checksum verified. Documented per adapter.

### E3 — Hedera client operator key (Low, process)
`clients/hcs-anchor` reads `HEDERA_OPERATOR_ID`/`HEDERA_OPERATOR_KEY` from the
**environment, never flags** (flags leak via process list / shell history). It is a
separate Go module, so the Hedera SDK never enters the authorization core. The key
is a throwaway testnet operator key. *Recommendation:* for mainnet, a hardware /
KMS-backed key never exported to the environment; rotate the testnet key out before
any mainnet use.

### E4 — `did:hedera` POC interpretation (Info)
The A2 binding implements the Hedera DID method's *mechanism* (DID document over
HCS, keyless mirror resolution) but is **not** the certified `did-sdk-js`/`-java`
envelope (no Go DID SDK exists), and folds only `create` + a generic `update`. It
publishes public keys + a *hiding* humanAnchor commitment — **never PII, never
private keys**. Documented as a POC interpretation in `docs/HEDERA-A2-DID-BINDING.md`.

### E5 — x402 gate (Info)
`cmd/x402gate` reuses the eight-step verifier; an over-scope payment is refused at
SPT-Txn mint (the gate denying), an in-scope one verifies ALLOW and emits the
humanAnchor as the XRPL Payment Memo. The Memo is a hiding ZK commitment — no PII
on-ledger. It does not contact the network or x402 facilitators; the Python
`x402-xrpl` wiring is the (fundable) integration step. No new trust surface — it is
a harness over already-reviewed code.

## Positives confirmed

- **No SDK in the core.** The Hedera SDK lives only in `clients/hcs-anchor`
  (separate module); the verifier/token packages still import no ledger SDK
  (blockchain-agnostic invariant, now structural).
- **No PII on any ledger.** Every anchor / DID / Memo carries only a hash or a
  hiding commitment.
- **No new collision surface.** Every new adapter chain-tags its preimage; the
  EVM-alias no-collision property is unit-tested.
- **Keyless verification everywhere.** Hedera (mirror node), Sui (object/event read),
  and the x402 gate (offline) all verify without keys or cost.

## Net

No new exploitable surface; the new code stays within the documented POC
boundaries. Highest-value follow-ups remain the same as the prior review: an
independent ZK-circuit audit, and mainnet hardening (anchor access control,
HSM/KMS keys) before any mainnet deploy.
