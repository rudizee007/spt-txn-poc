# Demo runsheet — SPT-Txn agentic x402 (~2:30)

> A guided, one-pass screen recording. Goal: show that an AI agent pays only when
> authorized, on a real ledger, that the merchant checks the *authorization* (not
> just the payment), that the same loop runs unchanged on many chains, and that the
> human behind it is accountable but private.
> Everything below is one command per beat — no live typing of long strings.

## The story in one line

x402 (HTTP-402) is the agent-payment standard Coinbase/Google (AP2) are building on.
SPT-Txn is the **authorization + accountability layer** on top of it: the gate decides
*if* an agent may pay and stamps a privacy-preserving anchor; the merchant verifies the
authorization offline; the human stays pseudonymous but lawfully recoverable — on any chain.

## Before you hit record (one-time setup)

- Big terminal font (18–20pt), dark theme, wide window; clear scrollback.
- Pre-build so nothing compiles on camera:
  ```
  cd "/Users/rudizee/Claude/Projects/SPT-TXN POC/spt-poc"
  go build ./...
  (cd clients/xrpl-pay && go build -o xrpl-pay .)
  (cd clients/eth-pay  && go build -o eth-pay .)      # also covers Base — just change -endpoint
  (cd clients/sol-pay  && go build -o sol-pay .)
  ```
- Export the credential(s) for the chain(s) you'll show live, and confirm each derives
  the funded payer (never commit/keep a real secret):
  ```
  export SPT_XRPL_SEED='sEd…'   ; clients/xrpl-pay/xrpl-pay -whoami
  export ETH_OPERATOR_KEY='0x…' ; clients/eth-pay/eth-pay  -whoami
  export SOL_OPERATOR_KEY='/tmp/sol-payer.json' ; clients/sol-pay/sol-pay -whoami
  ```
- Open browser tabs ready to show:
  - the **mainnet** proof: https://livenet.xrpl.org/accounts/raejui8S7517XMRwd1YMUtF5JrdvagX3LW
  - one testnet explorer per chain you'll flash in Beat 4 (paste the tx the run prints).
- Free the demo ports so nothing is stale: `for p in 8401 8402; do lsof -ti tcp:$p | xargs kill -9 2>/dev/null; done`

## Beat 1 — the hook (10s)

- **SAY:** "SPT-Txn is the authorization and accountability layer for AI-agent
  payments. An agent pays only when it's authorized, on a real ledger, and the
  human behind it stays private but accountable — on any chain."
- **SHOW:** the title / the repo, or just the clean terminal.

## Beat 2 — the guardrail: DENY (25s)

- **RUN:**
  ```
  ./scripts/x402-demo.sh deny
  ```
- **POINT AT** the line: `GATE DENY … payment outside agent capability scope … 9000 > ceiling 5000 → agent refuses to pay, nothing signed.`
- **SAY:** "The agent tries to spend more than the human granted it. The gate
  refuses — cryptographically, before anything is signed. An AI agent literally
  cannot exceed its delegated budget."

## Beat 3 — the authorized flow: ALLOW → pay → verify → deliver (40s)

- **RUN** (pick your lead chain — XRPL reads cleanest; Base/`ethereum` is the most
  on-theme for "agentic"):
  ```
  ./scripts/x402-demo.sh real                    # XRPL testnet
  # or:  CHAIN=ethereum ./scripts/x402-demo.sh real
  ```
- **POINT AT**, in order: `GATE ALLOW`, `settled on <chain>: tx …`, `resource delivered
  (merchant verified attestation): … "verified":true`.
- **SAY:** "Now it's in scope. The gate authorizes, the agent settles a real
  payment carrying a zero-knowledge anchor — no personal data on-chain — and the
  merchant re-runs the full eight-step verifier before it delivers. It's trusting
  the *authorization*, not just that money arrived."
- **SHOW:** paste the printed explorer link; point at the on-chain anchor (XRPL: the
  **Memo** + **SourceTag 402**; EVM: the tx **Input Data**; Solana: the **SPL Memo**).

## Beat 4 — blockchain-agnostic: the same loop, five chains (25s)

- **SAY:** "The authorization core never changes. Same gate, same verifier, same
  attestation — only a ~200-line submitter differs per chain. Here's the identical
  command pointed at a completely different stack."
- **RUN** one contrasting chain live (Solana — non-EVM, base58, on-chain SPL-Memo anchor):
  ```
  CHAIN=solana ./scripts/x402-demo.sh real
  ```
- **SHOW:** a row of explorer tabs already proving the other footprints — XRPL (through
  **mainnet**), Hedera, Aptos, Ethereum, Solana. Two address families (EVM hex + base58),
  both on-chain-anchor and attestation-bound anchor tiers.
- **SAY:** "Five chains, EVM and non-EVM. Because it's the *authorization* that's
  portable, not the plumbing."

## Beat 5 — accountability: sealed identity, lawful recovery (30s)

- **RUN:**
  ```
  go run ./cmd/deanondemo
  ```
- **POINT AT:** the sealed-envelope line, then `LAWFUL RECOVERY … Alice Q. Public…`,
  then the two `REFUSED` lines.
- **SAY:** "The real identity behind that anchor was sealed at issuance in a
  post-quantum hybrid envelope — nothing on-chain. It's recoverable only by the
  escrow authority under a signed, lawful request. No basis, or the wrong
  authority — refused. Pseudonymous by default, recoverable under due process."

## Beat 6 — it's real: mainnet (15s)

- **SHOW:** the pre-opened `livenet.xrpl.org/accounts/raejui8S7517XMRwd1YMUtF5JrdvagX3LW`
  tab; point at the 0.001 XRP Payment with SourceTag 402.
- **SAY:** "And this isn't just testnet — the same flow ran on XRPL **mainnet**.
  Here's the live transaction."

## Beat 7 — close (10s)

- **SAY:** "Privacy-preserving FATF Travel Rule compliance, plus accountable AI-agent
  payments — on the x402 standard the whole agentic ecosystem is adopting.
  Blockchain-agnostic, post-quantum hybrid, open source."
- **SHOW:** `foss.violetskysecurity.com`.

## Notes

- Total ≈ 2:30. To tighten to ~2:00, cut Beat 4's live Solana run and just flash the
  explorer tabs, or drop Beat 6's narration and flash the mainnet tab during Beat 7.
- The `real` beat takes a few seconds to validate (XRPL ~13s, Solana ~2–4s) — let it
  breathe or trim in a light edit.
- **Base = the agentic flourish, near-free:** Base is EVM, so `eth-pay` covers it with
  just `ENDPOINT=<Base Sepolia RPC> CHAIN=ethereum ./scripts/x402-demo.sh real`. Base is
  Coinbase's chain and the home of x402/AgentKit — a strong line if you add it to Beat 4.
- Nothing here types a seed or a long hash on camera; creds are exported before recording
  and the humanAnchor/tx flow through the tooling automatically.
