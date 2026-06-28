# SPT-Txn — reproduce it in minutes

A reviewer walkthrough. Local steps need Go 1.25 + gnark v0.15; the on-chain and
live-endpoint checks need nothing but `curl` (and a browser). Nothing here moves
funds or requires keys.

## 1. The whole suite is green

```
go test ./...
```
Token chain, eight-step verifier, all ZK circuits, the two-party Travel Rule, the
disclosure SDK, and 15 ledger adapters — all pass.

## 2. Real zero-knowledge (measured, not claimed)

```
go run ./cmd/zk-bench -prod
```
Prints constraints / setup / prove / verify / proof-size for the production
circuits. The agentic **chain** circuit (~52k constraints) verifies a registered
issuer's signature over each hidden delegation hop in-circuit; verify is ~1 ms and
the proof is a constant 164 B.

## 3. Agentic delegation + revocation (offline)

```
go run ./cmd/agentdemo
```
Shows multi-hop CT→CT delegation (scope can only narrow), the offline N-hop
verifier, and a granular revocation cascade (revoking a delegator denies its
sub-agents while the delegator's own authority stands).

## 4. Bind a real token to a transaction (any of 15 chains)

```
go run ./cmd/anchor -chain xrpl        # or: hedera, sui, ethereum, arbitrum, …
```
Mints a real CAT → CT → SPT-Txn chain, runs the eight-step engine to **ALLOW**, and
prints the genuine `spt_txn_context_hash` bound inside the token + ready-to-use
anchor calldata for that chain.

## 5. Authorize-before-pay for x402 (agentic payments)

```
go run ./cmd/x402gate -price 1000 -ceiling 5000     # ALLOW + humanAnchor Memo to stamp
go run ./cmd/x402gate -price 9000 -ceiling 5000     # DENY — payment exceeds the agent's scope
```
The SPT-Txn gate that decides whether an agent may make an x402 XRPL payment, and
emits the humanAnchor Memo for on-ledger accountability with no PII.

## 6. Live services (no install — `curl`)

```
curl -sk https://foss.violetskysecurity.com:4445/travel/health   # Travel Rule API
curl -sk https://foss.violetskysecurity.com:4446/agent/health    # agentic verify API
```
Site: <https://foss.violetskysecurity.com> — the interactive eight-step verifier
demo runs client-side in the browser.

## 7. Live on-chain footprints (keyless verification)

Each holds a real token-derived hash; verify without keys or cost:

- **Ethereum Sepolia** anchor `0x3fC3bE…57089`; **on-chain ZK verifier**
  `0x311612…95ef` (a tampered proof reverts). Also live on **Arbitrum Sepolia**.
- **Starknet Sepolia** `0x0620fe…53de1` · **Aptos testnet** `0x0b1f35…0aa2`.
- **Sui testnet** — Move anchor, shared `AnchorBook`
  `0xa21fa55d3babad018be0af72bf0b16d6617a1e8d33ab05222f1d4f08a38d6c8c`:
  `sui client object <id>` shows the stored root.
- **Hedera testnet** — HCS topic `0.0.9357269` (anchor) and `0.0.9357387`
  (`did:hedera` document). Verify keyless on the public mirror node:
  `curl -s "https://testnet.mirrornode.hedera.com/api/v1/topics/0.0.9357269/messages?limit=5"`
  → each `message` base64-decodes to the SPT-Txn envelope.

Full current-state map (addresses, metrics, build/verify): `docs/STATUS.md`.
Reproduce the deployments: `docs/RUNBOOK.md`.
