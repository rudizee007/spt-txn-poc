# RWA msg.sender binding — Tier 1 + Tier 2 (runbook)

Closes the honest boundary in `CompliantRWAToken` (V1): the eligibility proof is
now **cryptographically bound to the caller**, so a valid proof pulled from public
calldata **cannot be replayed** by another address. Two tiers, both in
`CompliantRWATokenV2`:

- **Tier 1 — address-bound attribute (`AddrThresholdCircuit`).** The threshold
  proof (amount ≥ threshold, amount hidden) carries the holder address as a public
  input; the contract verifies with `msg.sender`. Anti-replay, **no issuer**.
- **Tier 2 — issuer-bound eligibility (`EligibilityCircuit`).** Additionally
  requires a **trusted issuer's Baby Jubjub EdDSA signature** over
  `H(DomainHolder, holderAddr, commitment)`, verified **in-circuit** (same machinery
  as F1). The token pins the issuer key `(issuerX, issuerY)` on-chain — the ERC-3643
  trusted-issuer analogue. Eligibility becomes **non-transferable and vetted**.

Everything runs from the Mac. Sepolia is free.

---

## 0. Verify the code first (definitive check)

```sh
cd ~/spt-poc
go build ./...
go test ./internal/zkproof/ -run 'AddrThreshold|Eligibility' -v
```
Expect green:
- `TestAddrThreshold_BindsAddress` — valid proof verifies; **replay from another address is rejected**.
- `TestEligibility_IssuerBound` — valid; rejected for a different address and a different issuer key.
- `TestEligibility_RejectsUntrustedSigner`, `_RejectsAddressSwap`, `_RejectsBelowThreshold`.

## 1. Generate ONLY the two new circuits' keys

Do **not** regenerate the existing keys — that would invalidate the deployed
mainnet AttestationVerifier and the V1 Sepolia verifier. The `-only` flag adds the
new circuits and leaves the pinned keys untouched:

```sh
go run ./cmd/zk-setup -dir ./zk -only addrthreshold,eligibility
```

## 2. Export the Solidity verifiers (from the pinned keys)

```sh
go run ./cmd/zk-export-solidity -circuit addrthreshold -dir ./zk -o solidity/src/AddrThresholdVerifier.sol
go run ./cmd/zk-export-solidity -circuit eligibility  -dir ./zk -o solidity/src/EligibilityVerifier.sol
cd solidity && forge build && cd ..
```
`forge build` also compiles `CompliantRWATokenV2.sol` (compile check).

## 3. Common env

```sh
export SEPOLIA=https://ethereum-sepolia-rpc.publicnode.com
export ADDR_A=$(cast wallet address --account deployer)   # or paste it literally
export ADDR_B=$(cast wallet address --account holderB)
export ADDR_C=0x000000000000000000000000000000000000dEaD    # unregistered
```

---

## Tier 1 — address-bound (anti-replay, no issuer)

```sh
# a) deploy the Tier-1 verifier
forge create solidity/src/AddrThresholdVerifier.sol:Verifier --rpc-url "$SEPOLIA" --account deployer --broadcast
export T1_VERIFIER=0x…

# b) deploy the token in Mode.AddressBound (enum 0); issuerX/issuerY unused → 0
#    (name, symbol, verifier, mode=0, threshold=1000, issuerX=0, issuerY=0)
forge create solidity/src/CompliantRWATokenV2.sol:CompliantRWATokenV2 --rpc-url "$SEPOLIA" --account deployer --broadcast \
  --constructor-args "SPT RWA T1" "cRWA1" "$T1_VERIFIER" 0 1000 0 0
export RWA1=0x…
```

Register holder A (proof BOUND to A; must be sent from A):
```sh
go run ./cmd/rwa-register-calldata -tier 1 -dir ./zk -holder "$ADDR_A" -rwa "$RWA1" -account deployer
#   run the printed `cast send … register(bytes,uint256) <proof> <commitment>`
cast call "$RWA1" "eligible(address)(bool)" "$ADDR_A" --rpc-url "$SEPOLIA"   # true
```

**Replay test (the headline).** Take the *exact* proof + commitment printed for A
and try to register **from B**. It must **revert** (public input `holderAddr` =
B ≠ A):
```sh
cast send "$RWA1" "register(bytes,uint256)" <A_PROOF> <A_COMMIT> --rpc-url "$SEPOLIA" --account holderB
#   expected: execution reverted (invalid proof, 0x7fcdd1f4) — replay defeated
```
Register B properly (its own bound proof), then mint + transfer exactly as the V1
demo. The difference vs V1: a stolen proof no longer works.

---

## Tier 2 — issuer-bound (production)

```sh
# a) deploy the Tier-2 verifier
forge create solidity/src/EligibilityVerifier.sol:Verifier --rpc-url "$SEPOLIA" --account deployer --broadcast
export T2_VERIFIER=0x…
```

Generate holder A's registration; the tool creates+saves the issuer key on first
run and prints `issuerX/issuerY` to pin on-chain:
```sh
go run ./cmd/rwa-register-calldata -tier 2 -dir ./zk -holder "$ADDR_A" -rwa PLACEHOLDER -account deployer -issuer-key ./zk/rwa-issuer.key
#   note issuerX and issuerY from the output
export ISSUER_X=…
export ISSUER_Y=…
```

Deploy the token in `Mode.IssuerBound` (enum 1), pinning the issuer key:
```sh
forge create solidity/src/CompliantRWATokenV2.sol:CompliantRWATokenV2 --rpc-url "$SEPOLIA" --account deployer --broadcast \
  --constructor-args "SPT RWA T2" "cRWA2" "$T2_VERIFIER" 1 1000 "$ISSUER_X" "$ISSUER_Y"
export RWA2=0x…
```

Register A (re-run the tool with the real `-rwa "$RWA2"`, same issuer key), then run
the printed `register(bytes,uint256)` (the uint256 arg is `0`, ignored in Tier 2):
```sh
go run ./cmd/rwa-register-calldata -tier 2 -dir ./zk -holder "$ADDR_A" -rwa "$RWA2" -account deployer -issuer-key ./zk/rwa-issuer.key
cast call "$RWA2" "eligible(address)(bool)" "$ADDR_A" --rpc-url "$SEPOLIA"   # true
```

Two failure modes to demonstrate:
- **Replay:** run A's Tier-2 proof from B → reverts (address in the signed message and the public input is A).
- **No issuer attestation:** a holder the issuer never signed for cannot produce a
  valid proof at all (`rwa-register-calldata` self-verify fails before any tx).

Mint + compliant transfer + reverted transfer to `$ADDR_C` mirror the V1 demo.

## 4. Capture evidence + record

For whichever tier(s) you deploy: verifier address + deploy tx, token address +
deploy tx, the `register` tx, `eligible(A)=true`, the **reverted replay** tx, and
(Tier 2) the pinned `issuerX/issuerY`. Send them and I'll add the replay-safe RWA
footprint to README + site and fold it into the RWA grant framing.

---

### What this changes vs V1
V1 proved the on-chain gating mechanism but the proof was **not bound to
`msg.sender`** — a valid proof was replayable. V2 Tier 1 binds the address as a
public input (anti-replay); V2 Tier 2 additionally requires an issuer signature
over that address (non-transferable, vetted). The general-purpose `threshold` and
`vasp` circuits are **unchanged**, so the Travel-Rule services and the deployed
mainnet AttestationVerifier are unaffected.
