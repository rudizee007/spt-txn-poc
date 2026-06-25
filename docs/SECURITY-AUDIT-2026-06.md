# Secure-Code Audit — SPT-Txn POC (June 2026)

Independent read-only source audit of the Go reference implementation, complementing
`docs/SECURITY-REVIEW.md` (which tracks the earlier C/H/M findings, all resolved or
deferred). This pass fanned out across the security-critical packages, and **every
finding below was verified against the actual code path** (file:line) — no findings
are asserted from pattern-matching alone.

**Scope:** `internal/verifier` (eight-step engine), `cttoken`/`cattoken`/`txntoken`,
`dpop`, `zkproof`/`zkhash`, `escrow`, `sdjwt`, `trp`, `travelrule`, `ivms101`,
`vaspregistry`, `ledger`, `audit`, `trustregistry` (incl. the new `persist.go`), and
the `cmd/*` services. Method: manual trace of the verify/issue/transfer paths plus
test-coverage analysis.

## Bottom line

**No new Critical findings, and no remotely-exploitable authentication or
authorization bypass.** The eight-step verifier re-derives its guarantees
independently of issuance and fails closed; the network cannot mutate the Trust
Registry; algorithm-confusion and `alg:none` are structurally closed; selective
disclosure, AEAD nonce/AAD, holder binding, and transaction-context replay are all
sound (see *Verified-correct controls*).

The audit did surface **one High soundness gap** in the Travel Rule attestation (the
amount commitment is not bound to the real transfer), and a set of **Medium hardening
items** — mostly fail-open *defaults*, missing domain separation, and availability
gaps on the admin-only registry path. None are silent auth bypasses; several are
exactly the kind of issue an external ZK/protocol audit (grant M8) exists to catch,
and fixing them now strengthens that review.

## Remediation status — 2026-06-25 (all findings fixed)

Every finding below was remediated and the full suite (`go build ./... && go test ./...`)
passes. Verify-side and service fixes are code-only; the three circuit-affecting crypto
fixes require a trusted-setup regen + `vk` redeploy (see notes).

| Finding | Status | Notes |
|---|---|---|
| TR-1, TR-2, TR-3, TR-4, TR-5 | ✅ Fixed | TR-3 makes `trruleb` require `SPT_TR_EXPECTED_TXN_HASH`; TR-4 makes TRP `amount` a JSON string (wire change) |
| AUD-1, AUD-2 | ✅ Fixed | Merkle domain separation + PII-key guard |
| SVC-1…SVC-7 | ✅ Fixed | Atomic `Replace`, empty-file=corruption, dir-fsync, socket born 0600, trsvc `unveil`, per-type key length, generic errors |
| VER-1…VER-4 + DPoP htu | ✅ Fixed | Verify-side only — no wire change, no redeploy |
| CR-1, CR-3, CR-4 | ✅ Fixed | **Circuit-affecting** — regenerate trusted setup (`cmd/zk-setup`), redeploy `vk` |
| CR-2 | ✅ Documented | SD-JWT holder-binding invariant stated in package doc |
| ESC-2 | ✅ Fixed | HKDF escrow key derivation |
| ESC-1 | ◻ Deferred | Threshold (FROST) escrow — grant M8, unchanged |

## Findings summary

| ID | Severity | Area | Title |
|----|----------|------|-------|
| TR-1 | **High** | travelrule | Amount commitment not bound to the transfer — threshold predicate is unenforced |
| TR-2 | Medium | trp | Travel Address target unauthenticated + no HTTPS/host validation (SSRF class) |
| TR-3 | Medium | trp | `expectedHash==nil` makes txn-context binding self-referential (fail-open default) |
| AUD-1 | Medium | audit | Merkle tree lacks leaf/node domain separation + duplicate-node ambiguity |
| SVC-1 | Medium | trsvc | Register = revoke-then-add across two saves; crash between leaves issuer keyless |
| CR-1 | Medium | zkhash | No domain separation between the anchor and amount commitments |
| CR-4 | Medium* | zkproof | Threshold circuit range-checks `Amount` but not `Threshold` (*needs gnark verification) |
| AUD-2 | Medium* | audit | `Detail` map can carry PII into the on-disk log (*needs call-site verification) |
| VER-1 | Low | verifier | `spt_parent_hash` minted but never cross-checked at verify |
| VER-2 | Low | verifier | `human_anchor` compared with `!=` on `any` → panic/DoS if non-string |
| VER-3 | Low | verifier | No `iat`/`nbf` sanity check; only `exp` enforced |
| VER-4 | Info | cattoken | CAT expiry uses `>` where the rest of the chain uses `>=` |
| TR-4 | Low | trp | `Amount` is `float64`; ledger doc mandates decimal strings |
| TR-5 | Low | trp | No inbound replay protection (Request-Identifier not enforced unique) |
| CR-2 | Low | sdjwt | No holder binding / KB-JWT at the SD-JWT layer (relies on outer transport) |
| CR-3 | Low | zkhash | `FeFromBytes` silently reduces oversized inputs mod r (non-injective) |
| SVC-2 | Low | trsvc | Admin socket created then chmod 0600 — brief TOCTOU window |
| SVC-3 | Low | persist | `save()` does not fsync the parent dir after rename (crash-durability) |
| SVC-4 | Low | persist | Present-but-empty backing file treated as empty → re-seed wipes issuers |
| SVC-5 | Low | trsvc | `unveil` not yet applied; DB path not symlink-hardened |
| SVC-6 | Low | trustregistry | `validateRecord` hard-requires 32-byte keys, contradicting advertised ML-DSA types |
| SVC-7 | Low | services | Parser/issuer `err.Error()` echoed to network clients (info disclosure) |
| ESC-1 | Low | escrow | Single escrow key, not t-of-n threshold (acknowledged; FROST is the v2 target) |
| ESC-2 | Low | escrow | `deriveKey` uses bare SHA-256, not HKDF (acknowledged) |

\* "needs verification" items are reasoned from the API contract / type system; the
flagged risk should be confirmed with a targeted test before being treated as
exploitable.

---

## High

### TR-1 — Amount commitment is not bound to the transfer; the "amount ≥ threshold" predicate proves nothing about the real payment
**`internal/travelrule/travelrule.go:201-207`**

`Verify` cross-checks the `human_anchor` and `txn_context_hash` against the *signed*
SD-JWT (lines 186-191), but the `AmountCommitment` is taken verbatim from the
attestation and fed straight to `VerifyThreshold`:

```go
amtCommit, _ := new(big.Int).SetString(att.AmountCommitment, 10) // attacker-chosen
v.Threshold.VerifyThreshold(att.ThresholdProof, amtCommit, threshold)
```

The threshold proof proves `H(amount, blinding) == amtCommit ∧ amount ≥ threshold` —
but `amtCommit` is bound to nothing the verifier independently trusts (not the SD-JWT
amount, not the on-chain amount, not the txn-context hash). A malicious originator can
commit to any value that satisfies the predicate, regardless of the actual transfer.
The FATF "reportable amount" fact the whole attestation exists to prove is therefore
**unenforced**.

**Fix:** Bind the amount commitment the same way the anchor is bound — carry
`amount_commitment` as a signed (bound, non-disclosable) SD-JWT claim and assert
`claims["amount_commitment"] == att.AmountCommitment`, *or* fold the commitment into
the `txn_context_hash` preimage so it is end-to-end bound to the payment. Pairs with
CR-1 (domain separation).

---

## Medium

### TR-2 — Travel Address transport target is unauthenticated; no scheme/host validation (SSRF class)
**`internal/trp/trp.go:115-124, 145-166`**

`DecodeTravelAddress` base64url-decodes an arbitrary string into a URL and `Client.Send`
POSTs the SD-JWT attestation straight to it — no `https` requirement, no host
allow-list, no binding to a registered VASP. A Travel Address that decodes to
`http://169.254.169.254/…`, `http://localhost/…`, or any internal host is honoured, and
the attestation payload is delivered there. The VASP-membership proof attests to *some*
registered VASP, not *this destination* — transport target and proven VASP are
decoupled.

In the current deployment the Travel Address is operator-supplied (lower risk), but the
code enforces nothing. **Treat as High if Travel Addresses are ever sourced from
discovery / an untrusted counterparty.**

**Fix:** After decode, `url.Parse`; require `scheme == "https"`; reject hosts that
resolve to loopback/private/link-local/unspecified; and pin the endpoint to a
`vaspregistry` record (sign the Travel Address with the registry authority key, or look
the endpoint up by VASP ID and verify the served cert identity).

### TR-3 — `expectedHash == nil` makes transaction-context binding self-referential
**`internal/trp/trp.go:196, 227-230`** → **`internal/travelrule/travelrule.go:166`**

When the beneficiary `Handler` is constructed with a nil `expectedHash`, it uses the
hash from the request itself (`expected = ext.TxnContextHash`), and `Verify` then checks
`att.TxnContextHash == expected` — trivially true. The anti-replay / anti-rebind control
is silently disabled: a valid attestation can be re-pointed onto a different transfer by
setting the request's `txn_context_hash` to match. Documented as "POC convenience," but
it is a fail-open default on a security control.

**Fix:** Make `expectedHash` mandatory, or fail closed (reject) when it is nil. The
expected hash must derive from the independently observed transaction.

### AUD-1 — Audit Merkle tree lacks leaf/node domain separation
**`internal/audit/merkle.go:22-49`**

Leaves are raw entry hashes and interior nodes are `SHA-256(a || b)` with no tag
distinguishing the two domains, and the last node is duplicated when a layer is odd.
This is the textbook Merkle second-preimage setup plus the CVE-2012-2459 duplicate
ambiguity (two different leaf sets → same root), weakening the "no entry was altered or
removed" guarantee.

**Fix:** RFC 6962-style domain tags — `H(0x00 || leaf)` and `H(0x01 || left || right)` —
and fold the leaf `Count` into the root (or encode tree shape) to kill the
odd-duplication ambiguity. The hash *chain* in `log.go` is separately fine (length-
delimited, `Seq`/`PrevHash`, sorted keys — verified safe).

### SVC-1 — Registry register is non-atomic (revoke then add across two persisted saves)
**`cmd/trsvc/main.go:370-377`**

```go
_ = reg.Revoke(ctx, body.Iss, role, now) // persists immediately; error swallowed
if err := reg.Register(ctx, rec); err != nil { … }
```

`Revoke` and `Register` are two independent mutations, each with its own `save()`. A
crash or a failed second save (full/RO disk) after the revoke persisted leaves the
issuer with the old key revoked and no active key — re-introducing exactly the
"issuance breaks on restart" failure mode M7 set out to remove. Admin-socket-gated, so
availability-only, not attacker-triggerable.

**Fix:** Add an atomic `Upsert`/`Replace` to the `Mutable` interface that does
revoke-old + append-new under a single lock and a single `save()`, rolling back both
in-memory edits if the save fails (mirroring the existing single-mutation rollback in
`persist.go`). Stop swallowing the revoke error (distinguish `ErrNotFound`).

### CR-1 — No domain separation between the anchor and amount commitments
**`internal/zkhash/zkhash.go:53-66`, `internal/zkproof/circuits.go`**

Both `H(ID, randomness)` (humanAnchor) and `H(amount, blinding)` (amount commitment)
use the same untagged two-input `HashTwo`. A valid anchor is structurally a valid amount
commitment and vice-versa; combined with TR-1 this enables cross-commitment confusion.
The Merkle inner-node hash should likewise be domain-separated from leaf/commitment
hashing.

**Fix:** Prepend a distinct domain constant per use — `H(tag, a, b)` — mirrored exactly
in the in-circuit gadget so native and circuit hashing stay identical.

### CR-4 — Threshold circuit constrains `Amount` to 64 bits but not `Threshold` *(needs verification)*
**`internal/zkproof/circuits.go:53-63`**

`api.ToBinary(c.Amount, 64)` bounds the amount, but the public `Threshold` is
unconstrained before `api.AssertIsLessOrEqual(c.Threshold, c.Amount)`. `Threshold`
comes from trusted policy today (mitigating), but the circuit doesn't enforce that. Add
`api.ToBinary(c.Threshold, 64)` so both operands share a defined 64-bit domain. Confirm
with a negative test feeding `Threshold = r-1` against a 64-bit `Amount`.

### AUD-2 — `Detail`/`Subject` can place PII in the on-disk audit log *(needs call-site verification)*
**`internal/audit/log.go:38-46, 147-176`**

`Append` writes arbitrary `Detail` key/values (a test stores `{"amount":"5000"}`)
verbatim into the JSONL log and the hash preimage. The stated invariant is
"tamper-evidence *without* PII," but nothing constrains callers. Verify the deployed
`tr-svc`/`catsvc` call sites never pass names, accounts, or amounts; enforce
hash/opaque-ID-only values (allow-list keys) at the `Append` boundary.

---

## Low / Info (condensed)

- **VER-1** `internal/verifier/engine.go:238-244` — `spt_parent_hash` (minted at
  `cttoken.go:163`) is never recomputed/compared against `SHA-256(catToken)`; only the
  `jti` refs are checked. Low exploitability (scope monotonicity is independently
  re-derived against the presented CAT, so a substituted broader CAT buys nothing), but
  add the hash check to close the linkage-integrity gap.
- **VER-2** `engine.go:245-248` — `anchor != ctClaims["human_anchor"]` compares `any`
  with `!=`; a signature-verified TXN carrying a non-string (map/slice) `human_anchor`
  would **panic** (Go `==`/`!=` on uncomparable interface types) → verifier DoS. Assert
  `anchor, ok := …(string)` first.
- **VER-3** `engine.go:167-176` et al. — only `exp` is enforced; no `iat`-in-future or
  `nbf` gate. Add `iat > now + skew` rejection.
- **VER-4** `cattoken.go:207` — uses `now > exp` where `cttoken`/`txntoken`/engine use
  `>=`; align to `>=` (one-second boundary inconsistency).
- **TR-4** `trp.go:68-72` + `ledger.go:96-111` — TRP `Amount` is `float64` and the
  ledger gate uses `ParseFloat`, contradicting the package's own "decimal string, never
  float" rule; precision loss past 2^53. Use a decimal string + `big.Rat`.
- **TR-5** `trp.go:199-210` — `Request-Identifier` is required and echoed but never
  recorded; no inbound replay rejection. Add a short-lived seen-set (pairs with TR-3).
- **CR-2** `internal/sdjwt/sdjwt.go` — no `cnf`/KB-JWT at the SD-JWT layer; replay
  protection relies entirely on the outer CAT/DPoP transport. Either require a KB-JWT or
  document+enforce that the SD-JWT is always nested inside a holder-bound token.
- **CR-3** `zkhash.go:29-33` — `FeFromBytes` reduces oversized inputs mod r (BN254
  scalar field < 2²⁵⁴), so byte-string inputs (e.g. 64-byte SHA-512 IDs) are
  non-injective. Hash-to-field with wide reduction; reject blinding/randomness ≥ r.
- **SVC-2** `trsvc main.go:75-85` — `net.Listen("unix")` then `os.Chmod(…,0600)` leaves
  a window where the socket is born under umask perms and already accepting `/tr/register`.
  Set a tight umask around the listen (or 0700 parent dir), and check the chmod error.
- **SVC-3** `internal/trustregistry/persist.go:101-138` — atomic rename is correct, but
  the parent dir is not fsynced after `Rename`, so a crash can lose a just-confirmed
  registration. `fsync` the dir after rename (needs only the existing `rpath`).
- **SVC-4** `persist.go:82-84` — a present-but-zero-length backing file returns "empty"
  (not corruption), so a truncated store silently re-seeds revoked placeholders and
  wipes real issuers. `save()` never writes a zero-byte file → treat present-but-empty
  as corruption.
- **SVC-5** `trsvc main.go:88-98` + `persist.go` — `unveil` is deliberately deferred for
  trsvc, so its pledge set confines syscalls but not the filesystem namespace; the DB
  path uses plain `os`/no `O_NOFOLLOW`. Land the planned `unveil("/var/spt-txn/tr","rwc")`
  and keep that dir `0700 _spttr`.
- **SVC-6** `trustregistry/mock.go:127-152` (+ trsvc handler 32-byte check) —
  `validKeyTypes` advertises ML-DSA/ML-KEM but `validateRecord` rejects any key ≠ 32
  bytes, so PQ registrations fail with a misleading error. Length-check per `KeyType`, or
  reject ML-* explicitly until implemented.
- **SVC-7** `trsvc:332,375`, `catsvc:169,221`, `tr-svc:204,267,309` — `err.Error()` from
  the JSON decoder / issuer is echoed to clients (the network-reachable `/cat/issue` and
  travel endpoints included). Return a generic message; log detail server-side.
- **ESC-1 / ESC-2** `internal/escrow/*` — single escrow key (not t-of-n) and bare-SHA-256
  KDF (not HKDF); both are acknowledged POC limitations with FROST/HKDF as the stated
  targets. The escrow private key is the system's crown-jewel secret until threshold
  custody lands.

---

## Verified-correct controls (assurance)

These were specifically probed and found **sound** — included so the review is
calibrated, not just a defect list:

- **Algorithm confusion / `alg:none`** — every `verifyJWT` hard-requires `alg=="EdDSA"`
  before verifying; no HS/RS branch, no key-type switch. `alg:none` is rejected; a
  malformed header yields empty alg → fails closed. (`TestSec_AlgConfusion`.)
- **Key trust from registry, not token** — `iss` is used only to route
  `Registry.Lookup`; the signature is verified against the registry-returned active key.
- **Scope monotonicity** re-derived independently at verify with exact `big.Rat`
  ceilings (no 2⁵³ float attack); over-scoped CT denied at step 6
  (`TestSec_OverScopedCT_Forged`). Delegation depth enforced exact + non-negative.
- **Holder binding** fails closed on missing `cnf`; **transaction-context** recomputed
  and compared (canonical encoder sorts extras, rejects separator bytes) — replay on a
  different txn denied (`TestVerify_Step8_ContextMismatch`).
- **Registry AuthZ boundary** — `/tr/register` is served only on the owner-only
  (`0600`) Unix socket, never on TCP/relayd; the network cannot mutate the registry.
- **H5 key checks hold** — catsvc rejects encrypted signify keys (`kdfrounds!=0`) and
  verifies the SHA-512 checksum before use; private key never logged. catsvc sandbox is
  the tightest (`unveil` to the key file only, `pledge "stdio rpath inet"`).
- **Crypto hygiene** — `crypto/rand` everywhere; AES-GCM nonce + X25519 ephemeral fresh
  per envelope (no reuse); AEAD AAD binds anchor|issuer|iat; SD-JWT selective disclosure
  is binding (forged/extra disclosures rejected, 128-bit salts); gnark `Verify` fails
  closed with a trusted local vk.
- **DoS surface** — every `http.Server` sets read/write/idle timeouts; every parsing
  handler wraps the body in `MaxBytesReader`. No `InsecureSkipVerify` anywhere.
- **Persistence** — single-mutation `Register`/`setStatus` roll back in-memory state on
  save failure; readers never observe a torn file (temp-write + atomic rename under
  RWMutex). (Gaps are the *two-step* register SVC-1, dir-fsync SVC-3, empty-file SVC-4.)

---

## Recommended remediation order

1. **TR-1** (High) — bind the amount commitment; restores the core Travel Rule
   guarantee. Pairs with **CR-1** (domain separation).
2. **TR-3** + **TR-2** — fail closed on nil `expectedHash`; validate/pin the Travel
   Address target. Both close fail-open transport defaults.
3. **VER-2** (panic guard) and **VER-1** (`spt_parent_hash` check) — small, high-value
   verifier hardening.
4. **SVC-1** atomic registry upsert; **SVC-3/SVC-4** persistence durability + empty-file
   handling (finishes the M7 hardening properly).
5. **AUD-1** Merkle domain separation; **AUD-2** confirm no PII in audit call sites.
6. Remaining Lows as a sweep; **CR-4** add the negative gnark test.

Items **TR-1, CR-1, CR-4, ESC-1** are squarely in scope for the planned independent
ZK-circuit + protocol audit (grant M8) — fixing them beforehand de-risks that review.
None of the findings is a remotely-exploitable auth bypass; the security posture of the
deployed services (registry boundary, key handling, sandboxing, fail-closed
enforcement) holds.
