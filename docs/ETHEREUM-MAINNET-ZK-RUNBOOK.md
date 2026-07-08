# Ethereum Mainnet — on-chain ZK verifier + anchor (runbook)

Goal: deploy the SPT-Txn Groth16 verifier to **Ethereum mainnet** and run **one real
on-chain ZK verification** (`AttestationVerifier.anchorVerified` verifies a threshold
proof and anchors the context hash on success). This is a **one-time capability
milestone** — a second mainnet footprint after XRPL — not a recurring cost. At the
time of writing (~0.3 gwei) the whole thing is ~$1–2 of gas.

Run everything from the Mac (Foundry + the mainnet key stay local). The key is
**env-only, never in the repo or chat.**

---

## 0. Prerequisites (once)

- **Foundry** installed (`forge`, `cast`) — same tools as the Sepolia run.
- The pinned trusted-setup keys present in `./zk` (the on-chain `Groth16Verifier.sol`
  was exported from that `vk`; if you never regenerated the setup, nothing to do).
- A **dedicated mainnet wallet** funded with **~0.01–0.02 ETH** (~$18–36). Use a
  **fresh key** for this deploy — not a key holding other funds. Get its address:
  `cast wallet address --private-key "$PK"`.
- A **mainnet RPC**. Keyless works for a one-off: `https://ethereum-rpc.publicnode.com`
  (an Alchemy/Infura URL is more reliable for broadcasting if you have one).

```sh
cd "~/spt-poc"
read -s PK            # paste the mainnet private key (hidden; avoids shell history)
export PK
export RPC=https://ethereum-rpc.publicnode.com
export ADDR_SENDER=$(cast wallet address --private-key "$PK")
```

## 1. Gas gate — DO NOT skip

Only proceed when gas is cheap. Ideal is the sub-1-gwei window; above ~20 gwei, wait.

```sh
cast gas-price --rpc-url "$RPC"                 # wei/gas; /1e9 = gwei
cast balance "$ADDR_SENDER" --rpc-url "$RPC"    # confirm the key is funded
```
Also eyeball https://etherscan.io/gastracker. Rough cost = gas × price:
deploy ≈ 1.5–2.5M gas, each verify ≈ 250–300k gas.

## 2. Build + deploy the verifier (2 contracts)

```sh
cd solidity && forge build

# a) the Groth16 verifier (exported from the pinned vk)
forge create src/Groth16Verifier.sol:Verifier \
  --rpc-url "$RPC" --private-key "$PK" --broadcast
#   → note the deployed address as $VERIFIER_ADDR

# b) the AttestationVerifier wrapper (verifies proof, anchors on success)
forge create src/AttestationVerifier.sol:AttestationVerifier \
  --rpc-url "$RPC" --private-key "$PK" --broadcast \
  --constructor-args $VERIFIER_ADDR
#   → note the deployed address as $ATT_ADDR
cd ..
```

Record both **deploy tx hashes** and both **contract addresses** (evidence).

> The bare `AttestationAnchor.sol` (non-ZK anchor) is **not needed** here —
> `anchorVerified` already anchors after it verifies. Deploy it only if you also want
> a separate no-proof anchor.

## 3. Generate a real proof and verify it ON MAINNET

Use the **same invocation you used on Sepolia** (RUNBOOK §5), pointing `-addr` at the
mainnet `$ATT_ADDR`. This produces a genuine threshold proof (amount ≥ threshold, with
the amount hidden) and prints a ready `cast send`:

```sh
go run ./cmd/zk-solcalldata -dir ./zk -amount 5000 -threshold 1000 -root <ROOT> -addr "$ATT_ADDR"
# run the printed `cast send …`  (with $RPC and $PK exported)
```

Confirm the on-chain verification succeeded (the counter increments only on a valid proof):

```sh
cast call "$ATT_ADDR" "getCount()(uint256)" --rpc-url "$RPC"     # → 1
```

Record the **verify tx hash** — this is the headline: *a real SPT-Txn ZK proof verified
on Ethereum mainnet.*

## 4. (Optional, ~$0.15) Tamper test — proves it's really verifying

Flip one hex character in the proof bytes and resend: it must **revert** with
`0x7fcdd1f4` (the verifier's invalid-proof error). This demonstrates the contract is
genuinely checking the proof, not rubber-stamping.

## 5. Capture evidence (for README / site / milestone)

Collect and save:
- `Groth16Verifier` address + deploy tx → Etherscan link
- `AttestationVerifier` address + deploy tx → Etherscan link
- The **anchorVerified** tx hash → Etherscan link (the proof-verified-on-mainnet tx)
- `getCount()` = 1 (and, if run, the reverted tamper tx)

Etherscan: `https://etherscan.io/tx/<HASH>` and `https://etherscan.io/address/<ADDR>`.

## 6. After it's live — update the record

Tell me the addresses + tx hashes and I'll:
- add **Ethereum mainnet** to the on-chain footprints in `README.md` and the site
  (`web/index.html` POC section), stated honestly ("on-chain ZK verifier live on
  Ethereum mainnet");
- flip the roadmap line — "on-chain footprints are testnet" becomes "…testnet, plus
  a live on-chain ZK verification on Ethereum mainnet";
- add a milestone/evidence note (the P4-equivalent for Ethereum);
- fold it into the **Ethereum ESP** grant framing (you'd move from "EVM adapter +
  Sepolia anchor" to "live on Ethereum mainnet").

---

### Safety recap
- Key is **env-only** (`read -s`), never committed, never pasted in chat.
- Use a **dedicated, low-balance** mainnet key for this deploy.
- **Gas-gate** every run; a one-time deploy at low gas is ~$1–2, but a spike to
  30–50 gwei makes it $100–180 — just wait for a low window.
- The verifier deploy is **one-time**; each later verification is ~$0.15 at current
  gas, and the default SPT-Txn path stays **offline and free** — on-chain verify is
  the deliberate exception, used only where an on-chain action must be gated on the proof.
