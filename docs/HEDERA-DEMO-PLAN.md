# Plan — agentic x402 demo on Hedera (P1–P4)

> The blockchain-agnostic payoff. The entire authorization + accountability stack
> (gate, eight-step verifier, escrow, deanon) is chain-independent, and the Hedera
> ledger adapter (`internal/ledger/hedera.go`) already exists. So most of the
> Hedera demo falls out for free once two XRPL-specific things are generalized.

## What already works, unchanged

- **`internal/gate`** — the CAT→CT→SPT-Txn decision + verifier. (Currently pinned
  to `"xrpl"`; see prep below.)
- **`internal/ledger/hedera.go`** — Validate + Canonicalize for a Hedera
  `CryptoTransfer`: sender/receiver as `0.0.x` (or `0x` EVM alias), amount,
  currency `HBAR` (or an HTS token id), and the humanAnchor in `Extra["memo"]`
  (≤100-byte Hedera memo; a 64-hex anchor fits). The context-hash (verifier step 8)
  binds to these fields on any host.
- **`cmd/merchantsvc`** — chain-agnostic verify (only a cosmetic `"network":"xrpl"`
  label to generalize). The 8-step verifier picks the ledger adapter from
  `Txn.Chain`, so it verifies a Hedera attestation with no change.
- **`internal/escrow`, `cmd/deanondemo`** — P3 accountability is entirely
  chain-agnostic; it already works.

## The only chain-specific work

1. **Gate chain parameter** (PREP — done alongside this doc): `gate.New(chain, …)`
   so the gate uses `ledger.Get(chain)` and stamps `Chain: chain`. `gatesvc -chain`.
   This unblocks P1/P2/P3 on Hedera with zero further core changes.
2. **A Hedera submitter — `clients/hedera-pay`** (the real new build; the P0 analog
   of `clients/xrpl-pay`). Submits a real HBAR `TransferTransaction` on testnet,
   `SetTransactionMemo(humanAnchor)`, and returns the tx id / hashscan link.
   Separate module (Hedera SDK stays out of the core — the blockchain-agnostic
   invariant), reusing the `hiero-sdk-go/v2` setup already proven in
   `clients/hcs-anchor`. Flags mirror `xrpl-pay`: `-to`, `-amount`, `-memo`,
   `-json`, `-whoami`, `-genaccount`, `-yes` + a mainnet guard.
3. **Demo script** — a `hedera` mode (or a sibling script) that points the agent's
   `-pay-bin` at `hedera-pay` and sets Hedera addresses/amounts.

## Hedera specifics

- **Testnet account:** free from portal.hedera.com — gives an operator account
  `0.0.x` + private key, pre-funded with ~1000 test HBAR. (No faucet juggling like
  XRPL; the portal funds it.)
- **Payment:** `TransferTransaction().AddHbarTransfer(sender, -amt).AddHbarTransfer(receiver, +amt).SetTransactionMemo(anchor)`; amount in **tinybars** (1 HBAR = 100,000,000 tinybars). Execute → receipt → status `SUCCESS`, plus the transaction id.
- **Client:** `hiero.ClientForTestnet()` with the operator set; mainnet =
  `ClientForMainnet()` for P4-H.
- **Reserve:** Hedera has **no per-account reserve** (unlike XRPL's 1 XRP) — an
  account just needs a small HBAR balance for fees (fractions of a cent). Simpler.
- **Evidence:** hashscan.io/testnet/transaction/… (and /mainnet for P4-H); the memo
  (humanAnchor) is visible on the tx.

## Phases (map to the XRPL demo)

- **P0-H** — build `clients/hedera-pay`; one real testnet HBAR transfer carrying the
  anchor memo. (The one substantive build.)
- **P1-H** — run the loop: `gatesvc -chain hedera`, merchant (Hedera pay-to), agent
  `-pay-bin …/hedera-pay`. ALLOW settles; DENY refuses. Free once P0-H + the chain
  param exist.
- **P2-H** — merchant verifies the attestation. Free (verifier is chain-agnostic;
  the Hedera adapter provides the context-hash binding).
- **P3-H** — escrow + lawful deanon. Already works (`cmd/deanondemo`,
  `gate.SealIdentity`).
- **P4-H** — one real Hedera **mainnet** transfer + evidence (small HBAR, dedicated
  account, `-yes` gate).

## Prereqs for the build session

- A Hedera **testnet** operator account (portal.hedera.com) — account id `0.0.x` +
  private key. Set as env (e.g. `HEDERA_OPERATOR_ID`, `HEDERA_OPERATOR_KEY`) — key
  handled like the XRPL seed (env only, never repo/flag).
- Decide sender vs receiver: a second testnet account (portal gives one), or send
  to any activated account. Hedera has no self-transfer restriction issues beyond
  sender ≠ receiver.

## Grant tie-in

Running the *identical* agentic-compliance flow on Hedera (HBAR + memo + HCS) as on
XRPL is the concrete proof of the blockchain-agnostic claim — and it's the direct
deliverable for the **Hedera / HBAR Foundation** grant (Privacy Fund; complements the
existing HCS anchoring + did:hedera work in `clients/hcs-anchor`).
