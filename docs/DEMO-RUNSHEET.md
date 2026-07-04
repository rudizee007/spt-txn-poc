# Demo runsheet — SPT-Txn agentic x402 (~2 min)

> A guided, one-pass screen recording. Goal: show that an AI agent pays only when
> authorized, on a real ledger, that the merchant checks the authorization (not
> just the payment), and that the human behind it is accountable but private.
> Everything below is one command per beat — no live typing of long strings.

## Before you hit record (one-time setup)

- Big terminal font (18–20pt), dark theme, wide window; clear scrollback.
- Pre-build so nothing compiles on camera:
  ```
  cd "/Users/rudizee/Claude/Projects/SPT-TXN POC/spt-poc"
  go build ./... && (cd clients/xrpl-pay && go build -o xrpl-pay .)
  ```
- Set the funded **testnet** seed once (for the ALLOW/real beat), and confirm it:
  ```
  export SPT_XRPL_SEED='sEd…'                              # your funded testnet seed (never commit a real one)
  clients/xrpl-pay/xrpl-pay -whoami                        # prints the payer address it derives
  ```
- Open two browser tabs ready to show:
  - testnet explorer (you'll paste the tx hash the run prints)
  - the **mainnet** proof: https://livenet.xrpl.org/accounts/raejui8S7517XMRwd1YMUtF5JrdvagX3LW
- Free the demo ports so nothing is stale: `for p in 8401 8402; do lsof -ti tcp:$p | xargs kill -9 2>/dev/null; done`

## Beat 1 — the hook (10s)

- **SAY:** "SPT-Txn is the authorization and accountability layer for AI-agent
  payments. An agent pays only when it's authorized, on a real ledger, and the
  human behind it stays private but accountable."
- **SHOW:** the title / the repo, or just the clean terminal.

## Beat 2 — the guardrail: DENY (25s)

- **RUN:**
  ```
  ./scripts/x402-demo.sh deny
  ```
- **POINT AT** the line: `GATE DENY … value 9000 exceeds parent ceiling 5000 → agent refuses to pay, nothing signed.`
- **SAY:** "The agent tries to spend more than the human granted it. The gate
  refuses — cryptographically, before anything is signed. An AI agent literally
  cannot exceed its delegated budget."

## Beat 3 — the authorized flow: ALLOW → pay → verify → deliver (40s)

- **RUN:**
  ```
  ./scripts/x402-demo.sh real
  ```
- **POINT AT**, in order: `GATE ALLOW`, `settled on XRPL: tx …`, `resource delivered
  (merchant verified attestation): … "verified":true`.
- **SAY:** "Now it's in scope. The gate authorizes, the agent settles a real
  payment on the XRP Ledger carrying a zero-knowledge anchor — no personal data
  on-chain — and the merchant re-runs the full eight-step verifier before it
  delivers. It's trusting the *authorization*, not just that money arrived."
- **SHOW:** paste the printed `testnet.xrpl.org/transactions/…` link in the browser;
  point at the **SourceTag 402** and the **Memo** (the humanAnchor).

## Beat 4 — accountability: sealed identity, lawful recovery (30s)

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

## Beat 5 — it's real: mainnet (15s)

- **SHOW:** the pre-opened `livenet.xrpl.org/accounts/raejui8S7517XMRwd1YMUtF5JrdvagX3LW`
  tab; point at the 0.001 XRP Payment with SourceTag 402.
- **SAY:** "And this isn't just testnet — the same flow ran on XRPL **mainnet**.
  Here's the live transaction."

## Beat 6 — close (10s)

- **SAY:** "Privacy-preserving FATF Travel Rule compliance, plus accountable AI-agent
  payments. Blockchain-agnostic, post-quantum hybrid, open source."
- **SHOW:** `foss.violetskysecurity.com`.

## Notes

- Total ≈ 2:10. If you want it tighter, drop Beat 5's narration and just flash the
  mainnet tab during Beat 6.
- The `real` beat takes ~13s for XRPL to validate — that pause is fine; let it breathe,
  or trim it in a light edit.
- Nothing here types a seed or a long hash on camera; the seed is exported before
  recording and the humanAnchor/tx flow through the tooling automatically.
