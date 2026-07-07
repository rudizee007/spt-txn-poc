# SPT-Txn — reviewer brief (one page)

**What it is.** A privacy-preserving compliance + FATF Travel Rule + agentic-
authorization layer. Verify compliance **once**, prove it **everywhere** in zero
knowledge — so regulated institutions and AI agents can transact on-chain without
exposing PII. Reference POC in Go on a hardened OpenBSD host. Apache-2.0.

**The model in one breath.** A KYC provider issues a **CAT** (W3C VC bound to a
zero-knowledge **humanAnchor**); a platform checks a ZK proof of the CAT and issues
a scope-bounded **Capability Token (CT)**; delegated CTs (to an AI agent) are strict
subsets with bounded depth; each action mints a transaction-bound **SPT-Txn token**
verified by an eight-step offline engine. For inter-VASP transfers it carries a
payload-level **Travel Rule** ZK attestation. The humanAnchor threads every hop
unchanged; scope can only narrow.

## What's real (lead with depth, not chain count)

- **Real zero-knowledge, not stubs.** Groth16/BN254, Poseidon2. Circuits: identity
  commitment, amount-over-threshold, VASP-membership, and an agentic
  **delegation-chain proof** that verifies, **in-circuit**, a registered issuer's
  Baby Jubjub signature over each hidden hop's scope (52k constraints, ~1 ms verify,
  164 B). That last item closed the one honest gap (F1) the project had.
- **On-chain ZK, live.** A gnark-exported Groth16 verifier verifies a
  selective-disclosure proof (amount ≥ threshold, amount hidden) **on Ethereum and
  Arbitrum Sepolia** and anchors only if it checks out; a tampered proof reverts.
- **Live Travel Rule.** IVMS101 + selective-disclosure SD-JWT + the ZK predicates,
  carried over OpenVASP TRP between **two separate VASP services** (originator
  proves; beneficiary verifies with the verifying key only). Cleartext refused.
- **Six live on-chain footprints**, each holding a real token-derived hash:
  Ethereum, Arbitrum, Starknet, Aptos, **Hedera** (HCS anchor + a `did:hedera`
  binding the humanAnchor), **Sui** (Move shared-object anchor) — plus a Solana
  devnet memo. Every one is independently, keylessly verifiable.
- **Agentic, tested.** Multi-hop CT→CT delegation, an offline N-hop verifier, a
  granular revocation cascade, and the ZK chain proof above. Live verify endpoint.
- **Security by design.** OpenBSD `pledge`/`unveil`, privilege separation, relayd
  TLS; a host-runnable audit at **FAIL=0**; signed-Merkle audit log; escrow for
  lawful deanonymization; a CycloneDX CBOM + PQ-hybrid migration plan.
- **Breadth, honestly labeled.** 15 ledger adapters behind one interface
  (transaction-binding, shape-validated) — the depth is the six live footprints,
  the ZK, and the Travel Rule, not the adapter count.

## Honest boundaries

POC, not production. Adapters are transaction-binding (shape-validated), not
on-chain existence/checksum. On-chain footprints are testnet. The opt-in ZK chain
mode reaches parity with the cleartext path on issuer trust; cleartext remains the
default. `.zkdid`/`.zkdns`, XRPL Credentials, Hedera DID, zkLogin, eERC are
*integrations that enhance*, not prerequisites. An independent ZK-circuit audit is
wanted. We state all of this plainly in `docs/STATUS.md` and the security reviews.

## Reproduce in minutes

See `docs/DEMO.md`. In short: `go test ./...` (full suite green) ·
`go run ./cmd/zk-bench -prod` (circuit metrics) · `go run ./cmd/agentdemo`
(agentic delegation + revocation) · `go run ./cmd/anchor -chain xrpl` (mint a real
token chain + the 8-step ALLOW + context hash) · `go run ./cmd/x402gate`
(authorize-before-pay for x402). Live: <https://foss.violetskysecurity.com>.

## Links

- Code: https://github.com/rudizee007/spt-txn-poc · Live: https://foss.violetskysecurity.com
- `docs/STATUS.md` (current-state map, live addresses, ZK metrics) ·
  `docs/RUNBOOK.md` (reproduce everything) · `docs/BUILD-JOURNAL.md` (decisions) ·
  `docs/SECURITY-REVIEW*.md` (FAIL=0 + honest findings).
- Papers: Zenodo 10.5281/zenodo.20870193 (framework v2); IETF
  draft-coetzee-oauth-spt-txn-tokens.
