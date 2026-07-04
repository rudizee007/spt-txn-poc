# Build plan — Agentic x402-on-mainnet demo

> The single demo that converts "good idea, not far enough along" into a fundable,
> reviewer-verifiable proof point. One reproducible run where an AI agent, holding a
> scope-bounded capability delegated by a human, autonomously pays for a metered API
> via x402 on XRPL, the SPT-Txn gate authorizes it, the payment carries a
> zero-knowledge human anchor, the resource provider verifies the attestation offline,
> and the human identity is recoverable only under lawful process.
>
> Chain: **XRPL first.** It is the natural home for the FATF Travel Rule, it already has
> an x402 client (T54 `x402-xrpl`), `cmd/x402gate` is already XRPL-shaped, and it ties the
> demo directly to the best-fit rolling grant (Ripple/XRPL). The design stays
> chain-agnostic behind the ledger adapter, so Solana and Hedera follow (milestone #1).

## 1. Actors

- **Human principal ("Alice")** — the accountable person. Her real identity is sealed
  into a PQ-hybrid escrow envelope at issuance and never appears on the wire.
- **Issuer org (`domain-a`)** — issues Alice's CAT, seals her identity to escrow.
- **AI agent** — holds a CT delegated from Alice's CAT, scope = "pay ≤ N RLUSD to data APIs."
- **Resource server / merchant** — a metered API that speaks x402 (returns HTTP 402 with
  XRPL payment requirements), and validates the settled payment before serving.
- **Verifier (resource side)** — runs the offline eight-step engine on the presented
  SPT-Txn attestation, so the merchant knows the payer was authorized and accountable,
  not just that money arrived.
- **Escrow / deanon authority (`deanonsvc`)** — holds the PQ-hybrid escrow key; can recover
  Alice only via a signed, lawful-basis request.

## 2. What already exists (reuse, do not rebuild)

- CAT → CT → SPT-Txn issuance + scope attenuation: `internal/{cattoken,cttoken,txntoken}`.
- Eight-step offline verifier: `internal/verifier`.
- **Authorization gate + anchor/context-hash stamping (XRPL): `cmd/x402gate`** — already
  mints the chain for an x402 payment, runs the verifier, ALLOW/DENY, and emits
  `Destination / Amount / SourceTag / Memo=humanAnchor / spt_txn_context_hash`. It just
  never submits.
- Agentic delegation + revocation cascade: `cmd/agentdemo`; in-circuit ZK chain proof (F1).
- Ledger adapters (canonicalize + context hash, offline): `internal/ledger`.
- PQ-hybrid escrow + lawful deanon service: `internal/escrow`, `cmd/deanonsvc`,
  `cmd/escrowkeygen`.
- Trust Registry + service: `internal/trustregistry`, `cmd/trsvc`.

## 3. What is missing (the actual build)

- **(A) Real XRPL submission.** A client that takes the gate's ALLOW output and submits a
  signed XRPL `Payment` (Memo=anchor, SourceTag, correct Amount/Destination) to testnet,
  then mainnet. New module, pattern of `clients/hcs-anchor` (separate module, out of the
  offline core). The core `ledger.Ledger` interface stays submit-free by design.
- **(B) x402 HTTP loop, client-agnostic gate.** Expose the gate over a tiny local interface
  (CLI or Unix socket) so it is the authority and clients are pluggable. Build a minimal
  metered resource server (returns 402, validates the settled payment) and TWO agent
  clients: a **Go** reference client (runs on-box, hardened) and a **Python** adapter using
  T54 `x402-xrpl` (runs OFF-box, ecosystem-native). Neither client holds authority; both
  call the Go gate.
- **(C) Attestation transport + verify.** Carry the SPT-Txn token (or a compact reference)
  alongside the x402 retry so the resource server verifies authorization offline — the
  differentiator over vanilla x402, which only proves payment, not authority/accountability.
- **(D) Escrow wiring.** Seal Alice's identity at CAT issuance and `POST /escrow/store` to
  `deanonsvc`; then show a signed lawful-basis `/escrow/deanonymize` recovering her — the
  accountability half of the story.
- **(E) Reproducible harness.** One script that runs A–D on XRPL **testnet** end to end,
  plus one documented **mainnet** run with captured evidence (milestone #4 packaging).

## 4. Flow (the x402 loop with the gate inline)

1. Agent requests the metered resource → server replies **402** with
   `{price, currency=RLUSD, payTo, sourceTag}`.
2. Agent hands the requirement + its CT to the **gate** (`x402gate` logic): mint
   CAT→CT→SPT-Txn for this exact Payment and run the verifier.
   - **Over scope → DENY**: agent does not pay. (Demo shows this branch too.)
   - **In scope → ALLOW**: gate returns the stamp fields (Destination, Amount, SourceTag,
     Memo=anchor, context hash) + the attestation token.
3. Agent submits the XRPL Payment via **(A)**, with Memo=anchor + SourceTag.
4. Agent retries the resource with the tx hash + attestation.
5. Server validates: payment settled on-ledger for the right amount/destination, Memo anchor
   present, and the **attestation verifies offline** → serve 200. Otherwise refuse.
6. Out of band: escrow authority can recover Alice from the anchor only via a signed,
   lawful-basis deanon request.

## 5. Mainnet safety (security by design)

- **Testnet first** (XRPL testnet + faucet); a single mainnet run only after the testnet
  path is green.
- Dedicated demo account; **tiny amounts** (a few drops / minimal RLUSD).
- Keys never in the repo; gitleaks already guards. Submission keys loaded from an
  env-pointed path, same discipline as `deanonsvc` (`escrow.ParseKey` pattern).
- No PII on the ledger — only the zero-knowledge anchor + context hash (already the design).
- Capture evidence (explorer link, verifier output) without exposing keys.

## 6. Phased tasks

- **P0 — XRPL submitter (testnet).** Module (A): submit a `Payment` with Memo+SourceTag;
  confirm on the testnet explorer. Deliverable: one real testnet tx from an ALLOW decision.
- **P1 — x402 loop (local + testnet).** Module (B): 402 → gate → pay → retry → 200, against
  a local metered server. Decide x402 impl: integrate T54 `x402-xrpl` (Python) vs. a minimal
  Go 402 handshake. (Re-verify `x402-xrpl` current status first.)
- **P2 — attestation verify (C).** Resource server runs the offline verifier on the presented
  token; DENY the retry if authorization does not verify even when payment settled.
- **P3 — escrow + lawful deanon (D).** Seal Alice at issuance → `deanonsvc`; demonstrate a
  lawful recovery and that an unauthorized/basis-less request is refused.
- **P4 — mainnet run.** One real XRPL mainnet payment end to end; capture the evidence bundle.
- **P5 — package (milestone #4).** Clone-and-run script, ~2-min demo video script, verifier as
  a downloadable library.

## 7. What "verifiable end-to-end" means (the evidence a reviewer/counterparty checks)

1. A real on-ledger tx (explorer link) with the human anchor in the Memo + SourceTag.
2. The SPT-Txn attestation for that exact payment verifies offline (anyone can re-run it).
3. The **DENY** branch: an over-scope agent is refused before it can pay.
4. The **accountability** branch: lawful deanon recovers the human; an unauthorized request
   is refused, audit-logged.
5. All of it reproducible from one script on testnet; one documented mainnet instance.

## 8. Grant tie-in

This demo is the shared proof point for the best-fit rolling grants — **XRPL/Ripple**
(Travel Rule + x402), **Aptos Payments** (funds compliance layers), **EF ESP** (ZK scoped
disclosure) — and, ported to Solana x402, a **Colosseum** hackathon entry. It directly
answers the Solana/Sui "not far enough along" objection: a real transaction, an external-
facing flow, and an agentic differentiator, all at once.

## 9. Decisions (resolved 2026-07-02)

- **Everything is TESTNET today.** Every chain footprint (ETH Sepolia, Arbitrum, Starknet
  Sepolia, Aptos/Hedera/Sui testnet, Solana devnet) is test networks; the server/site is
  live mainnet *infrastructure* but no mainnet blockchain value has moved. P0–P3 = XRPL
  testnet; P4 = the one real mainnet payment. Closing that gap is the point of this demo.
- **x402 implementation: BOTH.** The gate is the authority; clients are pluggable. Keep the
  gate + verifier + submitter in **Go on the hardened box**, exposed over a tiny local
  interface (CLI or Unix socket). Ship **two clients**: (i) a Go reference client, (ii) a
  **Python adapter** using T54 `x402-xrpl`. Trust-boundary rule: the Python runs **off-box**
  (dev host / separate non-hardened node) and calls the Go gate — no Python runtime enters
  the OpenBSD trust boundary. Result: Go-native purity on the box + ecosystem credibility.
- **Currency: BOTH, XRP first.** `x402gate` already parametrizes `-currency`. XRP (native
  drops) for P0/P1 to get the pipe working; then add **RLUSD** (issued IOU — needs a
  trustline to the issuer on both accounts) for the stablecoin story. Sequence XRP → RLUSD.
- Attestation transport (still open, decide at P2): HTTP header on the x402 retry (richer)
  vs. on-ledger-only Memo + server re-derivation (simpler, fully public). Likely support both.
- Mainnet amount + funding account: decide at P4 (tiny amount, dedicated demo account).
