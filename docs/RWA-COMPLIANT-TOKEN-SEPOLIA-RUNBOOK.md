# Compliant RWA token — Ethereum Sepolia runbook

Goal: prove **privacy-preserving RWA compliance on-chain** — a permissioned token
(`CompliantRWAToken`) whose transfers succeed only between holders who have proven
eligibility in **zero knowledge**, with no PII on-chain. A non-eligible transfer
**reverts `NotEligible`**. This is the ERC-3643 permissioned-transfer model made
privacy-preserving.

Two stages:
- **Stage 1 (this runbook, runnable now):** the **attribute gate** — eligibility via a
  threshold proof (accredited / amount-over-threshold, value hidden). Reuses the exact
  ZK tooling you proved on Ethereum mainnet.
- **Stage 2 (after the membership tool is built):** add the **membership gate** — the
  holder proves they're in the approved-holder Merkle set. Outlined at the end.

Everything runs from the Mac (Foundry + keystore local). Sepolia is free — fund keys
from a faucet, no real ETH.

---

## 0. Prerequisites

- **Foundry** (`forge`, `cast`) and the pinned `./zk` trusted-setup keys.
- A **Sepolia RPC**: `https://ethereum-sepolia-rpc.publicnode.com` (keyless).
- Your reusable **`deployer` keystore** (the mainnet signer) funded with a little
  **Sepolia** ETH from a faucet (e.g. sepoliafaucet.com / pk910 PoW faucet). Cheap:
  the whole demo is a handful of small txs.
- A **second keystore `holderB`** to demonstrate a transfer *between* eligible holders,
  funded with a tiny bit of Sepolia ETH (one `register` tx).

```sh
cd "/Users/rudizee/Claude/Projects/SPT-TXN POC/spt-poc"
export SEPOLIA=https://ethereum-sepolia-rpc.publicnode.com

# second holder keystore (skip if you already have one)
cast wallet import holderB --interactive         # paste a fresh 0x… key + set a password
export ADDR_A=$(cast wallet address --account deployer)
export ADDR_B=$(cast wallet address --account holderB)
export ADDR_C=0x000000000000000000000000000000000000dEaD   # an UNREGISTERED address (demo the revert)
```

Fund both `$ADDR_A` and `$ADDR_B` with Sepolia ETH, then confirm:
```sh
cast balance "$ADDR_A" --rpc-url "$SEPOLIA"
cast balance "$ADDR_B" --rpc-url "$SEPOLIA"
```

## 1. Export the threshold verifier from CURRENT keys, then build

Re-export so the on-chain verifier matches your current `./zk` prover keys (avoids the
Jun-27-vk-vs-current-key mismatch that reverts with `0x7fcdd1f4`):

```sh
go run ./cmd/zk-export-solidity -circuit threshold -dir ./zk -o solidity/src/Groth16Verifier.sol
cd solidity && forge build
```
`forge build` also compiles `CompliantRWAToken.sol` — this is your compile check.

## 2. Deploy the threshold verifier + the RWA token (attribute gate)

```sh
# a) threshold Groth16 verifier
forge create src/Groth16Verifier.sol:Verifier --rpc-url "$SEPOLIA" --account deployer --broadcast
export THRESHOLD_VERIFIER=0x…Deployed_to

# b) the RWA token — attribute-only gate:
#    (name, symbol, membershipVerifier=0x0, attributeVerifier, holdersRoot=0, threshold=1000,
#     requireMembership=false, requireAttribute=true)
forge create src/CompliantRWAToken.sol:CompliantRWAToken --rpc-url "$SEPOLIA" --account deployer --broadcast \
  --constructor-args "SPT Compliant RWA" "cRWA" \
  0x0000000000000000000000000000000000000000 "$THRESHOLD_VERIFIER" 0 1000 false true
export RWA=0x…Deployed_to
cd ..
```

## 3. Generate an attribute (threshold) proof

`zk-solcalldata` prints a real proof (amount ≥ threshold, amount hidden). We only need
the **proof (bytes)** and the **commitment** from its output; the `-root`/`-addr` are for
the unrelated `anchorVerified` command, so any dummy values are fine:

```sh
go run ./cmd/zk-solcalldata -dir ./zk -amount 5000 -threshold 1000 \
  -root 0000000000000000000000000000000000000000000000000000000000000001 \
  -addr 0x0000000000000000000000000000000000000000
```
Copy the printed `proof (bytes)` → `$PROOF` and `commitment` → `$COMMIT`:
```sh
export PROOF=0x19d1c320…      # the proof bytes line
export COMMIT=11544900853436696727272124070411121161601916552371073614116568888497488884530
```
> The same proof works for both holders here because Stage 1 is not yet address-bound
> (the documented honest boundary in the contract). Stage 2 / production binds it.

## 4. Register both holders (attribute proof; membership arg is empty `0x`)

```sh
# holder A (deployer)
cast send "$RWA" "register(bytes,bytes,uint256)" 0x "$PROOF" "$COMMIT" --rpc-url "$SEPOLIA" --account deployer
# holder B
cast send "$RWA" "register(bytes,bytes,uint256)" 0x "$PROOF" "$COMMIT" --rpc-url "$SEPOLIA" --account holderB

# confirm both eligible:
cast call "$RWA" "eligible(address)(bool)" "$ADDR_A" --rpc-url "$SEPOLIA"   # true
cast call "$RWA" "eligible(address)(bool)" "$ADDR_B" --rpc-url "$SEPOLIA"   # true
cast call "$RWA" "eligible(address)(bool)" "$ADDR_C" --rpc-url "$SEPOLIA"   # false
```
A **bad** proof would make `register` revert (`0x7fcdd1f4`) and grant nothing — that's
the ZK gate working.

## 5. Mint, then demonstrate the compliance gate

```sh
# issuer mints RWA to the eligible holder A
cast send "$RWA" "mint(address,uint256)" "$ADDR_A" 1000000000000000000 --rpc-url "$SEPOLIA" --account deployer

# COMPLIANT transfer A → B (both eligible) → succeeds
cast send "$RWA" "transfer(address,uint256)" "$ADDR_B" 100000000000000000 --rpc-url "$SEPOLIA" --account deployer
cast call "$RWA" "balanceOf(address)(uint256)" "$ADDR_B" --rpc-url "$SEPOLIA"   # → 100000000000000000

# NON-COMPLIANT transfer A → C (C not eligible) → REVERTS NotEligible(C)
cast send "$RWA" "transfer(address,uint256)" "$ADDR_C" 100000000000000000 --rpc-url "$SEPOLIA" --account deployer
#   expected: execution reverted, custom error NotEligible(0x…dEaD)
```

That revert **is the headline**: the tokenised asset cannot move to a party who hasn't
proven compliance in zero knowledge — enforced on-chain, no PII anywhere.

## 6. Capture evidence

- `Verifier` (threshold) address + deploy tx
- `CompliantRWAToken` address + deploy tx
- the two `register` txs, the `mint` tx, the **successful** A→B transfer tx
- the **reverted** A→C transfer (Sepolia Etherscan shows the `NotEligible` revert)
- `eligible(A)=true`, `eligible(B)=true`, `eligible(C)=false`, `balanceOf(B)` after transfer

Sepolia explorer: `https://sepolia.etherscan.io/tx/<HASH>` / `.../address/<ADDR>`.
Send me these and I'll add an **RWA footprint** to the README + site, and fold
"compliance-gated RWA transfers proven on-chain (ZK, no PII)" into the RWA-chain grant
framing (Aptos Payments / XDC / an RWA-focused chain).

---

## Stage 2 — add the membership gate (after the tool is built)

Once `cmd/zk-export-solidity -circuit vasp` + the membership-calldata tool are in place:

1. Export + deploy the membership verifier:
   ```sh
   go run ./cmd/zk-export-solidity -circuit vasp -dir ./zk -o solidity/src/MembershipVerifier.sol
   cd solidity && forge build
   forge create src/MembershipVerifier.sol:Verifier --rpc-url "$SEPOLIA" --account deployer --broadcast
   export MEMBERSHIP_VERIFIER=0x…
   cd ..
   ```
2. Build the approved-holder Merkle tree and take its **root** (the membership tool prints it).
3. Point the token at both verifiers with **both** checks required — either redeploy with
   `membershipVerifier=$MEMBERSHIP_VERIFIER … requireMembership=true requireAttribute=true`,
   or `setConfig(root, 1000, true, true)` on the existing token after wiring the membership
   verifier in the constructor.
4. Generate the membership proof + root, and register:
   ```sh
   go run ./cmd/rwa-membership-calldata -dir ./zk -member alice@rwa -addr "$RWA"
   ```
   It prints the **holders root** (set the token's `eligibleHoldersRoot` to it, via the
   constructor or `setConfig`), the **proof bytes**, and a ready `register(...)` snippet.
   Run that `register` (membership-only, or add the attribute proof + commitment in args 2–3
   for the dual gate). A holder NOT in the set can't produce a valid proof → `register`
   reverts → stays ineligible.

### Honest boundary (carried from the contract)
The Stage 1/2 proofs prove *a* valid holder/attribute exists in the set; they are **not
yet bound to `msg.sender`**, so a valid proof could be replayed by another address.
Production must bind the proof to the registering address (address as a public signal, or
via the SPT-Txn humanAnchor). This runbook proves the on-chain gating mechanism;
address-binding is the next circuit iteration.
