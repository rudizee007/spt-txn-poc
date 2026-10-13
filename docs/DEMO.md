# SPT-Txn — reproduce it in minutes

A reviewer walkthrough. Local steps require Go 1.26.6 or newer, as declared in
`go.mod`. Go downloads the pinned dependencies, including gnark v0.16.3. Run the
commands below from the repository root. The offline authorization examples
need no wallet credentials and do not submit payments. Dependency downloads
require network access on the first run; tests use local HTTP listeners.

### Recorded verification

On 13 October 2026, public revision
`149b57f9a3ce1eee786de7be8af4bbfecd15a3a1` passed root-module build, test
(`-count=1`), and vet on macOS arm64 using Go 1.26.6 and Go 1.27.1.
The offline delegation demo and both x402 gate examples below also passed on
both versions. Tests covered 55 packages; another 32 packages had no test files.

To reproduce that source baseline in a new checkout:

```sh
git clone --no-recurse-submodules https://github.com/rudizee007/spt-txn-poc.git spt-txn-review
cd spt-txn-review
git checkout --detach 149b57f9a3ce1eee786de7be8af4bbfecd15a3a1
export GOWORK=off
export GOTOOLCHAIN=go1.26.6
```

Then run the checks and offline examples below. This record covers the public
root module and those examples. Nested payment clients, optional HSM builds,
other platforms, live services, and settlement were not verified in this run.
It does not establish production readiness or independent security certification.

## 1. The whole suite is green

```sh
GOWORK=off go build -mod=readonly ./...
GOWORK=off go test -mod=readonly -count=1 ./...
GOWORK=off go vet -mod=readonly ./...
```
Token chain, eight-step verifier, all ZK circuits, the two-party Travel Rule, the
disclosure SDK, and root-module ledger adapters are covered. Nested Go modules
(such as payment clients) and optional build tags require separate checks.

## 2. Real zero-knowledge (measured, not claimed)

```
go run ./cmd/zk-bench -prod
```
Prints constraints / setup / prove / verify / proof-size for the production
circuits. The agentic **chain** circuit (~52k constraints) verifies a registered
issuer's signature over each hidden delegation hop in-circuit; verify is ~1 ms and
the proof is a constant 164 B.

## 3. Agentic delegation + revocation (offline)

```sh
GOWORK=off go run -mod=readonly ./cmd/agentdemo
```
Shows multi-hop CT→CT delegation (scope can only narrow), the offline N-hop
verifier, and a granular revocation cascade (revoking a delegator denies its
sub-agents while the delegator's own authority stands).

Expected decisions:

| Scenario | Result |
|---|---|
| Sub-agent B pays $4000 within its $5000 ceiling | ALLOW |
| Sub-agent B tries $6000 | DENY at mint because the scope is exceeded |
| Sub-agent B pays $4000 after A's delegation authority is revoked | DENY |
| Agent A pays $7000 under its retained $8000 capability | ALLOW |

Generated anchors vary between runs; compare the decisions rather than the hash
values. This example demonstrates the public authorization implementation.

## 4. Bind a real token to a transaction (any of 15 chains)

```
go run ./cmd/anchor -chain xrpl        # or: hedera, sui, ethereum, arbitrum, …
```
Mints a real CAT → CT → SPT-Txn chain, runs the eight-step engine to **ALLOW**, and
prints the genuine `spt_txn_context_hash` bound inside the token + ready-to-use
anchor calldata for that chain.

## 5. Authorize-before-pay for x402 (agentic payments)

```sh
GOWORK=off go run -mod=readonly ./cmd/x402gate -price 1000 -ceiling 5000     # ALLOW + humanAnchor Memo to stamp
GOWORK=off go run -mod=readonly ./cmd/x402gate -price 9000 -ceiling 5000     # DENY — payment exceeds the agent's scope
```
The SPT-Txn gate that decides whether an agent may make an x402 XRPL payment, and
emits the humanAnchor Memo for on-ledger accountability with no PII.
These are local XRPL authorization examples. They do not settle a payment or
demonstrate Arc/Circle integration.

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
