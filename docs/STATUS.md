# SPT-Txn — project status (current-state map)

Snapshot as of 2026-09-09. What exists, where it lives, what's live on-chain, and
how to build and verify it. Pairs with [RUNBOOK.md](RUNBOOK.md) (how to reproduce)
and [BUILD-JOURNAL.md](BUILD-JOURNAL.md) (how we got here).

## Component map

| Area | Lives in | State |
|---|---|---|
| Token chain (CAT → CT → SPT-Txn) | `internal/cattoken`, `internal/cttoken`, `internal/txntoken` | tested |
| Eight-step enforcement engine | `internal/verifier` | tested |
| Agentic delegation (CT→CT, N-hop, revocation cascade) | `internal/cttoken`, `internal/verifier`, `cmd/agentdemo` | POC-tested |
| Agentic ZK chain proof (`ChainCircuit`) + verifier seam | `internal/zkproof`, `internal/verifier` (`step6ChainZK`) | built + tested + benchmarked + token-bound |
| ZK predicates (commitment, threshold, VASP) | `internal/zkproof`, `internal/zkhash` (Poseidon2/BN254) | tested |
| On-chain ZK verifier (Solidity) | `solidity/src/{Groth16Verifier,AttestationVerifier}.sol`, `cmd/zk-export-solidity`, `cmd/zk-solcalldata` | live on 2 L2s |
| Scoped-disclosure SDK + schema | `internal/disclosure`, `docs/DISCLOSURE-SCHEMA.md` | built + tested |
| Travel Rule (IVMS101 + SD-JWT + ZK) | `internal/travelrule`, `internal/sdjwt`, `internal/trp`, `internal/ivms101`, `cmd/tr-svc` | live (2-party) |
| Ledger adapters (15 chains) | `internal/ledger` | tested |
| On-chain anchor contracts | `cairo/attestation_anchor`, `move/attestation_anchor`, `solidity/src/AttestationAnchor.sol`, `sui/attestation_anchor` | live on 5 chains (ETH, Arbitrum, Starknet, Aptos, Sui) |
| End-to-end anchoring tool | `cmd/anchor` | tested |
| Hedera HCS anchoring client (A1) | `clients/hcs-anchor` (separate module) | built; keyless mirror-node verify; anchoring is an operator action |
| Services (verify-role, Travel Rule) | `cmd/agentsvc` (:4446), `cmd/tr-svc` (:4445) | deployed (OpenBSD) |
| CI | `.github/workflows/ci.yml` | build + vet + test on push/PR |
| Site | `web/` → foss.violetskysecurity.com | live |

## Ledger adapters (15)

`xrpl`, `hedera`, `solana`, `stellar`, `starknet`, `aptos`, `sui`, `ethereum`
(covers all EVM L2s), `xdc`, `algorand`, `arbitrum`, `optimism`, `base`,
`avalanche`, `polkadot`. The EVM L2 aliases (`arbitrum`, `optimism`, `base`) reuse
the Ethereum validation with a distinct chain tag — demonstrating L2 coverage, no
separate contracts needed. Each: `Name`/`Validate`/`Canonicalize`,
chain-tagged preimage (no cross-chain hash collision), shape-only address checks
(POC). One EVM adapter + one Solidity contract set cover Ethereum L1 and every
EVM L2.

## Live on-chain footprints (public testnets)

| Chain | Contract / module | Address | Notes |
|---|---|---|---|
| Ethereum Sepolia | AttestationAnchor | `0x3fC3bE148c4902C21dfaf4ccff1E0c99d6F57089` | real token-derived root |
| Ethereum Sepolia | Groth16Verifier | `0x8032A63cA0f19cA5Ce81f479d0c29213C6640a69` | ZK verifier |
| Ethereum Sepolia | AttestationVerifier | `0x311612c4E2D7E93CF5d80C0138B55C8A723B95ef` | ZK-gated anchor |
| Arbitrum Sepolia | Groth16Verifier | `0x805d8Cd70ab6aA00bFD5956DA65062aC7Fb689fD` | ZK verifier |
| Arbitrum Sepolia | AttestationVerifier | `0x349edc056b6A3809a5B7FCFC8f260539aB0e13D8` | ZK-gated anchor |
| Arbitrum Sepolia | AttestationAnchor | `0x07229AdF304d557e8D4a02B2a5ED92C13907Dc3d` | plain anchor |
| Starknet Sepolia | attestation_anchor (Cairo) | `0x0620fe8ccb9c19fe9acce44dccc6a6a3d851974dcd97f05949982453de853de1` | real token-derived root |
| Aptos testnet | attestation_anchor (Move) | `0x0b1f35b54e92d49d21d1badca271b9ab5686f22f82d6f88c6731cac20cbe0aa2` | real token-derived root |
| Solana devnet | SPL-memo anchor wallet | `BeWdnfiJ52LpaGudU6ZhGLVcpeBEYxHYewZC4DZopVi4` | memo anchor |
| Hedera testnet | HCS topic (attestation anchor) | `0.0.9357269` (seq 1) | real token-derived ctx hash `9448…7581`; keyless mirror-node verify; milestone A1 |
| Hedera testnet | `did:hedera` DID document (HCS) | `0.0.9357387` | issuer DID + bound humanAnchor; keyless mirror-node resolve; milestone A2 |
| Sui testnet | attestation_anchor (Move) | pkg `0xb816f6…e4ec`, shared AnchorBook `0xa21fa5…6c8c` | real token-derived ctx hash `624ee0…97da` anchored (tx `3PW4WA…b3RY`); append-only shared-object anchor |
| BSC testnet (97) | Groth16Verifier | `0x0637d7c0188438f152582Cfeb5A4291576785721` | ZK verifier |
| BSC testnet (97) | AttestationVerifier | `0x95AdE1083107ceeE9110235D928473907a217664` | ZK-gated anchor; **ZK-verified anchor tx `0xf62eb9bc9174e0c5eac1f91315b231ea96493162fe0f7bce88ab61ffbe7e9102`**, block 116431949, ~316k gas (BN254 pairing) |
| BSC testnet (97) | AttestationAnchor | `0xdD7590197459adA2F0a81Dbbcc97ed834A5AfBEe` | plain anchor; tx `0x4dd20aad00ee139b2c2b113f6237165e8742f471776ff7267ee423df10eb5926`, block 116431651 |
| X Layer testnet (1952) | Groth16Verifier (re-keyed) | `0x31457D719B86B076c9Ea4cA2c5af93d960B2A968` | current VK; supersedes `0xd2bBB93C…1DBDA7` (stale Jun-27 VK) |
| X Layer testnet (1952) | AttestationVerifier (re-keyed) | `0x2A2e4F42C10dd2e22307Ea5418c045DafF5C7916` | ZK-gated anchor; supersedes `0x9181A846…6E27Dc` |
| X Layer testnet (1952) | AttestationAnchor | `0x9B81ca5a149708833Ea426b8c5bDb08E56cBC890` | plain anchor; ctx hash `0x53daf105…3a56`, tx `0xc5b88a9b326898c28292aa3f75c95f2be1902a7bfe38a86b30d6ff99b6f28339`, block 34370495 |
| Morph Hoodi (2910) | Groth16Verifier | `0x252f72F5Db3351180c21c857959994A113110d18` | ZK verifier (old Jun-27 VK — see the note below) |
| Morph Hoodi (2910) | AttestationVerifier | `0xFb58A234940025f764f06cdC5D6B441D63268808` | ZK-gated anchor |
| Morph Hoodi (2910) | AttestationAnchor | `0x1656DA9E3e0967d95485D66C44fAB21F19a4DE5E` | plain anchor; ctx hash `0x871743d3…8610`, tx `0x8eb96d4e4067567e8c218fef3f3ecc8b5f7ae462c3ff38500fe5e0e113fe3aba`, block 6534262 |

The on-chain ZK verifiers verify a threshold selective-disclosure proof on-chain
and record the root only if it checks out; a tampered proof reverts. Proven this
way on **Ethereum Sepolia** (tx `0x57dc36…d76c`), **Arbitrum Sepolia** (tx
`0xd099c8…a325`), **BSC testnet** (tx `0xf62eb9bc…9102`) and **X Layer testnet**.

> **VERIFICATION-KEY CAVEAT — read before quoting these present-tense.** The ZK
> keys were regenerated on 2026-06-28 (F1 / Poseidon2) and re-exported on
> 2026-06-30. The verifiers on **Ethereum Sepolia, Arbitrum Sepolia and Morph
> Hoodi still carry the superseded Jun-27 verification key** and would reject a
> proof produced by the current keys. Each of them did verify a real proof at the
> time, so the past-tense claim stands and the transactions above are genuine;
> "this verifier verifies our proofs" is only true **today** on BSC testnet and
> the re-keyed X Layer pair. Redeploy from the re-exported `Groth16Verifier.sol`
> before making a present-tense claim about the other three.

The Hedera HCS footprint is **live on testnet** (topic `0.0.9357269`, sequence 1,
consensus timestamp `1782658058.681753330`) — a real `cmd/anchor -chain hedera`
context hash anchored via `clients/hcs-anchor` and confirmed keyless on the public
mirror node. The Sui footprint (Move attestation anchor, pkg `0xb816f6…e4ec`) is
also live — a real context hash anchored into a shared `AnchorBook` object. All
*anchor* footprints above are **testnet**.

**Ethereum MAINNET (2026-07-08).** The Groth16 verifier is deployed and a real
proof has been verified on-chain:

| What | Value |
|---|---|
| Verifier contract | `0xb64e248338E90290B3188d2c44A8e327a646Ab01` |
| Verified-anchor tx | `0x7273f74db58bd8e2311cb78fe603efc826bcdb8409c6221e8112cf155d8ca731` |
| Block / time | 25,489,362 · 2026-07-08T17:32:23Z |
| Deployer | `0x946EC09E8d270f99CD2dCc96EE02cA0B559e0eD3` |
| Gas used (verify+anchor) | 316,507 |

https://etherscan.io/address/0xb64e248338E90290B3188d2c44A8e327a646Ab01
https://etherscan.io/tx/0x7273f74db58bd8e2311cb78fe603efc826bcdb8409c6221e8112cf155d8ca731

> **Why this row exists.** This deployment went live on 2026-07-08 and was
> recorded NOWHERE — not here, not in a broadcast log, not in any evidence file.
> On 2026-08-31 that absence led to a confident, wrong conclusion that the
> mainnet deploy had never happened, and to the claim being struck from a public
> standards proposal that was in fact accurate. An on-chain footprint that is not
> written down is one nobody can defend, including the person who made it.
> **Record the address and tx hash at deploy time, always.**
>
**XRPL MAINNET (2026-07-04).** The x402 loop ran end to end on XRPL mainnet:

| What | Value |
|---|---|
| Payment tx | `C92405A32D6ABB9A2A01FF95DAFE9E6A7BC68D2FF6092570C1B76FF7418D9A0D` |
| Amount | 1,000 drops = **0.001 XRP** (deliberately minimal; the point is the loop, not the value) |
| SourceTag | `402` |
| From / To | `raejui8S7517XMRwd1YMUtF5JrdvagX3LW` -> `rQJFs9vZhoW6daSLLn3QPPEwymBdp43J5w` |
| Date | 2026-07-04 17:56:51 UTC, validated |
| Ledger index | 105372915 (tx index 54) |
| CTID | `C647DCF300360000` — decodes to ledger 105372915, tx index 54, **network id 0 = XRPL mainnet**. Quote the CTID: it self-certifies the network and the ledger without trusting an explorer. |
| Fee | 0.000012 XRP |
| Memos | `spt-txn/humanAnchor` = `18b433c4…14f196`; `spt-txn/contextHash` = `d1c9b6e0…b040dc` |

**The commitment on the ledger re-derives from ledger state.** `scripts/verify-xrpl-loop.py` recomputes the stamped `spt_txn_context_hash` from the payer, destination, amount, currency and the anchor in the first memo, and it matches exactly; a one-drop change to the amount or a one-nibble change to the anchor both fail to reproduce it. So the payment is bound to that human anchor in state nobody can rewrite. The gate's issuance timestamp is committed in the preimage but not transmitted, so the script recovers it by a short scan (it lands 4 s before validation) — stamping it as a third memo would turn that scan into one equality.

https://livenet.xrpl.org/transactions/C92405A32D6ABB9A2A01FF95DAFE9E6A7BC68D2FF6092570C1B76FF7418D9A0D

Same lesson as the row above: until 2026-08-31 only the ACCOUNT was recorded (in
DEMO-RUNSHEET.md), never the transaction hash. An account link makes a reviewer
hunt; a tx hash is the evidence. Record the hash.

> The contract source is NOT yet verified on Etherscan. Verifying it makes the
> deployment inspectable rather than merely present — worth doing.

## ZK circuit metrics (BN254 / Poseidon2 / Groth16, `go run ./cmd/zk-bench -prod`)

| circuit | constraints | setup | prove | verify | proof |
|---|---|---|---|---|---|
| commitment | 373 | 34 ms | 6 ms | ~1.0 ms | 164 B |
| threshold | 2,026 | 91 ms | 7 ms | ~0.8 ms | 164 B |
| chain (4-hop) | 52,001 | 1.88 s | 181 ms | ~1.0 ms | 164 B |

Verify is constant ~1 ms and proofs are a constant 164 B regardless of chain length.
The chain circuit grew 5,936 → 17,945 → 52,001 constraints (prove 16 → 84 → 181 ms)
as F1 was closed in two steps: phase 1 added per-hop issuer registry-membership
(Poseidon2 Merkle), phase 2 added per-hop in-circuit Baby Jubjub EdDSA signature
verification (~7k constraints/hop). Verify and proof size are unchanged (Groth16 is
constant-size), so even a fully signature-checked 4-hop chain verifies in ~1 ms.

## Build & test

Go 1.25+, gnark v0.15.

```
go build ./...
go vet ./...
go test ./...
go run ./cmd/agentdemo        # offline agentic delegation + revocation demo
go run ./cmd/zk-bench -prod   # full-size circuit metrics
go run ./cmd/anchor -chain ethereum   # mint a chain, print the real ContextHash + anchor calldata
```

All 87 packages build and vet clean; the 55 that carry tests pass, 0 failures
(go1.25.13, 2026-09-09).

## Honest boundaries

POC, internally security-reviewed, not externally audited, not production. Agentic layer POC-tested, not battle-tested
at scale. The opt-in ZK chain mode now verifies, in-circuit, that **each hidden hop
carries a real Baby Jubjub signature from a registered CT-issuer over its actual
scope** (F1 closed — phases 1+2), reaching parity with the cleartext path's
issuer-trust check. This requires issuers to dual-key (Ed25519 for JWS/VC interop +
a Baby Jubjub key for the ZK proof); the Baby Jubjub key is an auxiliary ZK artifact,
not the authoritative (or PQ) signature. See
[SECURITY-REVIEW-2026-06-28.md](SECURITY-REVIEW-2026-06-28.md). On-chain footprints
are testnet. The human-anchor binding in ZK chain mode is a cleartext endpoint
check (by design — the agent must not hold the human's anchor preimage). The
offline verifier library is the primary path; hosted endpoints are a convenience.
