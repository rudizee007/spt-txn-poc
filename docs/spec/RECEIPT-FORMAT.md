# SPT-Txn P2 Specification — Transaction Receipt & Transparency Log

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/receipt`, `internal/audit` (Merkle log), `cmd/receiptverify`.
**Threat model:** `docs/THREAT-MODEL.md` §3.6.

---

## 1. Transaction Receipt

A compact signed record emitted **at decision time** by an issuer or PEP.
Nobody in the GRC market can say "this control was enforced at the moment of
this specific transaction, and here is a cryptographic proof." This is that
proof. The auditor verifies a chain instead of sampling controls.

### 1.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `v` | string | `"spt-receipt-v1"` |
| `pep` | string | issuer/PEP identity (trust-registry name) |
| `decision` | string | `"PERMIT"` or `"DENY"` — nothing else |
| `class` | string | `"ok"` (permits), `"violation"`, or `"unavailable"` (denials). Operators MUST be able to tell an outage from an attack. |
| `rule_path` | string | the rule/check that fired (e.g. `intent.digest-mismatch`, `chain.hop2.scope`, `replay.cache-unavailable`) |
| `token_hash` | string | base64url SHA-256 of the presented compact token; `""` if none presented |
| `policy_hash` | string | base64url SHA-256 of the policy bundle version evaluated |
| `intent_digest` | string | the bound intent digest, if any |
| `jurisdiction` | string | jurisdiction profile applied (e.g. `EU-DORA`, `US-FED`) |
| `ts` | int64 | unix time, UTC, at decision |
| `nonce` | string | 128-bit random, base64url — makes receipts unlinkable across logs holding the same token hash |
| `sig` | string | Ed25519 signature (see 1.2) |

**No payloads, no PII, ever.** Hashes and references only. Selective
disclosure to third parties happens via SD-JWT at a different layer.

### 1.2 Signing (normative)

    signing_input = "spt-txn-receipt-v1" || 0x00 || JCS(receipt minus sig)

JCS is the shared canonicalizer (`internal/jcs`) — the same single
implementation as intent binding, same rejection rules. The receipt signing
key is the **log/audit key**, separate from the token issuance key, on a
separate rotation schedule (THREAT-MODEL §3.5).

### 1.3 Emission rules

- Every decision emits a receipt, **including denials**. Issuance is not
  complete until the receipt is appended.
- Receipt emission failure is itself a deny condition for the guarded action
  (class `unavailable`), subject to the deployment's buffering policy (§2.3).

## 2. Transparency Log

### 2.1 Structure

Receipts append to the existing hash-chained JSONL log (`internal/audit`):
each entry carries the previous entry's hash; periodic Merkle roots
(RFC 6962-style leaf/interior domain separation, unpaired-node promotion)
are signed and published. Design lineage: Certificate Transparency / Rekor.

- **Inclusion proofs:** any single receipt is provable against a published
  signed root without revealing the rest of the log (`audit.MerkleProof` /
  `audit.VerifyInclusion`).
- **Witness co-signing (implemented — `internal/audit` `Witness` /
  `CosignedRoot`):** signed tree heads are co-signed by one or more external
  witnesses. A witness co-signs a head only after confirming it is an
  **append-only extension** of the last head that witness attested (its prefix
  at the previously-attested count must reproduce the previously-attested
  root); it refuses a rewritten, forked, or truncated history. A verifier
  requires a **threshold of distinct known witnesses** (`VerifyCosigned`, N of
  M). A compromised operator — who holds the log key and can therefore sign an
  alternate history — still cannot obtain witness co-signatures for it, so the
  threshold-co-signed head a regulator checks cannot be a silently rewritten
  one. Witness signatures are domain-separated and bound to the operator
  identity (no cross-operator replay). The POC witness recomputes roots from
  the presented log; a production witness consumes a compact RFC 6962
  consistency proof, with the identical security property.

### 2.2 Verifier CLI

`cmd/receiptverify` verifies, offline:

1. receipt signature against the log public key,
2. receipt hash inclusion against a signed root (proof file),
3. signed-root signature.

Exit 0 only if all three hold. Output states which check failed — the CLI is
for auditors; unlike the PEP's uniform errors, it is maximally explicit.

### 2.3 Availability policy (explicit, per deployment)

If the log is unreachable, decisions MAY proceed with a local durable
append-only buffer that is reconciled on reconnect — or the deployment MAY
declare log-unavailable a fail-closed condition. **This is a deployment
decision that MUST be configured explicitly; it never defaults silently.**

## 3. Export layer

A thin mapping from receipt fields to control frameworks (NIST SP 800-53
AU-2/AU-10/AC-3, DORA Art. 9, etc.) ships as data, not platform. **We do not
build a GRC dashboard.** Export to what customers already run.
