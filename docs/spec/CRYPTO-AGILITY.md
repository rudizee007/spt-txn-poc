# SPT-Txn P6 Specification — Crypto-Agility and PQC Readiness

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/suite`.
**Threat model:** `docs/THREAT-MODEL.md` §4.3 (downgrade).

---

## 1. Position

Transaction-scoped tokens are short-lived, which makes SPT-Txn one of the few
token systems where PQC migration is genuinely easy: **our tokens outlive
their algorithms by minutes, not years.** Algorithm rotation is the same
designed operation as key rotation — overlap windows, not incidents.

## 2. Suite identifier — covered by the signature (normative)

Every signed envelope carries a suite identifier **inside** the signed bytes:

    signing_input = "spt-txn-env-v1" || 0x00 || suite_id || 0x00 || payload

A downgrade therefore requires forging the very signature it is trying to
weaken (THREAT-MODEL §4.3). The envelope's outer, unsigned copy of the suite
id exists only for dispatch; verification MUST fail if it disagrees with the
signed copy — which it structurally cannot, because the verifier reconstructs
`signing_input` from the outer id and a mismatch invalidates the signature.

Registered suites:

| `suite_id` | Algorithms | Status |
|---|---|---|
| `EdDSA` | Ed25519 | current default |
| `HYBRID-Ed25519-MLDSA65` | Ed25519 **and** ML-DSA-65 (FIPS 204), both signatures required at signing | transition suite |

`alg: none`, unknown suites, and empty suite ids are rejected by allowlist.
An unimplemented-but-known suite (e.g. hybrid on a build without the PQC
backend) is DENY class `unavailable` — never silent fallback to another
suite.

## 3. Verification modes (explicit, never inferred)

| Mode | Behavior |
|---|---|
| `verify-either` (transition) | hybrid envelope valid if **either** classical or PQC signature verifies — tolerates ecosystem partners mid-migration |
| `verify-both` (strict) | hybrid envelope valid only if **both** verify — CNSA 2.0 posture |

The mode is verifier **configuration**. It MUST NOT be inferred from the
token, the envelope, or the peer. A hybrid-signed envelope always carries
both signatures; the mode only governs acceptance.

## 4. Jurisdiction suite floors (non-bypassable)

A jurisdiction profile pins a minimum suite set, checked **before** signature
verification dispatch: if the profile requires hybrid, a classical-only
envelope is rejected (`violation`) regardless of whether its classical
signature is valid. Floors are policy-bundle data, hashed into every receipt.

## 5. Implementation constraints

- ML-DSA backend: audited pure-Go implementation (`filippo.io/mldsa`,
  ML-DSA-65), behind build tag `mldsa` until `crypto/mldsa` lands in the Go
  standard library (public API targeted for Go 1.27), at which point the
  backend swaps without touching call sites. No cgo. No custom crypto.
- Builds without the tag still parse hybrid envelopes and fail closed
  (`unavailable`) — agility plumbing is always compiled and tested; only the
  PQC primitive is gated.
- Key rotation and algorithm rotation share one mechanism: suites bind to
  keys in the trust registry; an issuer may be live with `EdDSA` and
  `HYBRID-Ed25519-MLDSA65` keys simultaneously during an overlap window.
- TLS and at-rest layers are deliberately out of scope here (tracked
  separately); this spec covers token/receipt envelopes.
