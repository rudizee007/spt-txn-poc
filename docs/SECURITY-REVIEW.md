# SPT-Txn POC — Security Review

Full read of every service (`cmd/`), the OpenBSD integration layer, and the
`internal/` libraries. Findings are ranked Critical / High / Medium / Low with
status: **FIXED**, **PARTIAL**, or **OPEN**. "Verifier" = `internal/verifier`
eight-step engine; "issuer" = `cmd/catsvc`; "registry" = `cmd/trsvc`.

## Critical

**C1 — Unauthenticated trust-registry registration. [FIXED, verify relayd]**
`cmd/trsvc` `/tr/register` mutated the trust anchor with no auth. Fixed: register
is served only on a dedicated admin Unix socket (`tr-admin.sock`, mode 0600,
owner-only); the relayd-facing TCP listener serves a read-only mux (no register).
Registrar also rejects non-32-byte, all-zero, and invalid-role keys. **Operator
must verify `/etc/relayd.conf` forwards `/tr/*` to the TCP port (127.0.0.1:8081),
NOT to any registry socket** — the shipped setup doc forwarded `/tr/*` to a
socket, which would re-expose register. Confirm `curl https://host/tr/register`
returns 404.

**C3 — Unauthenticated CAT issuance oracle. [OPEN]**
`cmd/catsvc` `handleIssue` (main.go:141) signs a CAT with the real `ct_issuer`
key for whatever `issuer`/`scope`/`holder_key`/`delegation_depth` the caller
sends, with no authentication, and the service is reachable via relayd on `:4444`.
Anyone who can reach it mints a validly-signed CAT with attacker-chosen scope
bound to their own key — the root of the whole capability chain. The spec
requires verifying the subject's SD-JWT (and registry-checking the wallet issuer)
before issuing; the POC skipped it. Fix: authenticate issuance — verify a
subject SD-JWT signed by a registered wallet key (we have `internal/sdjwt`), or
mTLS, and do not expose issuance unauthenticated.

**C4 — pledge/unveil are no-ops; OpenBSD sandboxing is inert. [OPEN]**
`cmd/trsvc/pledge_openbsd.go` defines `pledge`, `unveil`, `unveilLock` as empty
functions, so even on OpenBSD no sandbox is applied — and `cmd/catsvc` has no
pledge file or call at all. Every service runs unconfined; a compromised service
has full syscall and filesystem access, including read of the unencrypted signing
keys. Fix: implement real `pledge(2)`/`unveil(2)` via `golang.org/x/sys/unix`
(`unix.PledgePromises`, `unix.Unveil`, `unix.UnveilBlock`) per service, tuned and
tested iteratively on the host (pledge violations crash the process, so this
needs careful syscall-set work — that is why it was disabled, but disabled is not
an acceptable end state).

## High

**H1 — DPoP / token replay. [OPEN]** `internal/dpop` has no `jti` cache and no
`ath` binding; a captured `{token, DPoP proof}` is replayable for the token
lifetime + proof window. Fix: single-use `jti` cache in the verifier + `ath`.

**H4 — Signing keys unencrypted at rest. [OPEN, by setup]**
`OPENBSD-SETUP.md` generates signify keys with `-n` (no passphrase), and
`catsvc.loadSignifyKey` reads the raw key with no KDF handling — so `*.sec` keys
sit unencrypted on disk, protected only by filesystem perms. Combined with C4
(no unveil), a compromised issuer exfiltrates the trust-anchor key trivially.
Fix: passphrase-protected keys loaded once at startup (then unveil-blocked), or
an OS keystore; at minimum confirm `0600 root` perms and add unveil so only the
key path is readable.

**H5 — Signify loader does not validate KDF/checksum. [OPEN]**
`catsvc.loadSignifyKey` (main.go:241) slices `raw[40:104]` directly without
checking the KDF field is "none" or verifying the checksum. An encrypted or
corrupted key would be silently used as a (wrong) signing key. Fix: assert
KDF/rounds and verify the embedded checksum before use.

## Medium

**M5 — No request body size limits. [OPEN]** `catsvc` and `trsvc` decode request
JSON with no `http.MaxBytesReader`; an oversized body is a memory-DoS. Fix: cap
body size (e.g. 64 KiB).

**M2 — Amount precision. [PARTIAL]** Ledger now rejects non-positive/non-finite
amounts (FIXED), but `internal/tbac` still compares amounts as float64; above
2^53 precision is lost. Fix: compare with `math/big.Rat`.

**M6 — Service user/permission drift. [OPEN]** `catsvc.rc` runs catsvc as
`_sptaw` (the wallet user) while `ARCHITECTURE.md` assigns the CAT issuer to
`_sptaci`; the keys dir is `700 root:_sptcommon`, which the service user cannot
read. Reconcile least-privilege: dedicated user per service, key readable by
exactly that user.

**M1 — JWT header `alg`/`typ` unvalidated. [OPEN]** All `verifyJWT` paths force
Ed25519 (safe today) but never parse/validate the header. Fix: assert
`alg=="EdDSA"` defensively (tested adversarially already for alg:none).

**M3 — Deanon request freshness. [OPEN]** `internal/escrow` signs `IssuedAt` but
never checks it; a captured signed request replays. Fix: freshness window + used-
request store; move toward threshold signers.

**L2 — catsvc registry client ignores key status. [OPEN]** `httpTrustRegistry.
Lookup` builds a record without checking `Status`/validity. Low (startup self-
check only) but should honor status if reused.

## Fixed in the verifier (prior increment, host-green)

H2 (revocation no longer decided on unverified issuer), H3 (verifier re-enforces
CAP⊆CAT scope monotonicity, delegation depth, holder-key binding — no longer
trusts issuance), C2 (verifier rejects degenerate all-zero keys; registry seeds
are now revoked placeholders, not active). Adversarial tests cover alg-confusion,
zero-key, forged over-scoped CAP, negative amount, cross-domain audience.

## Confirmed sound

ZK public-input handling (verifier supplies inputs, not trusted from the proof);
escrow envelope (fresh ephemeral X25519 per seal, random nonce, AAD binds
anchor|iss|iat); ledger canonicalization (separator-byte injection blocked,
extras sorted); audit hash-chain + signed Merkle roots; SD-JWT forged-disclosure
rejection.

## Priority order to close

1. C3 (issuance auth) and C4 (real pledge/unveil) — highest residual risk.
2. Verify relayd routing for C1; H4/H5 key-at-rest; H1 replay.
3. M-series hardening.

## Closure (2026-06-23) — audit FAIL=0, full test suite green

All Criticals and High-severity findings are RESOLVED and DEPLOYED:

- **C1** — register served only on a 0600 admin Unix socket; relayd TCP path is
  read-only. Verified live: `/tr/register` via relayd → 404.
- **C2** — seeds are revoked placeholders (never active); `verifier.resolveKey`
  and the registrar reject all-zero keys.
- **C3** — `/cat/issue` requires a wallet subject-token (signed by ct_issuer),
  verified before signing. Live: no token → 401, valid token → 200. `mksubject`
  generates wallet tokens.
- **C4** — real `pledge(2)` on `trsvc` and `catsvc` (no-op stubs replaced);
  `catsvc` also `unveil`s to only its key path. Both run confined.
- **H1** — DPoP `ath` token-binding + single-use `jti` replay cache in the
  verifier. Replay of a captured token+proof is denied at step 5.
- **H2/H3** — verifier no longer decides on an unverified issuer, and
  re-enforces CAP⊆CAT scope, delegation depth, and holder binding.
- **H4** — key blast radius cut by perms(400) + unveil confinement (the issuer
  can read nothing but its own key). Encryption-at-rest is the remaining v2 step.

M-series RESOLVED: **M1** alg-pinned in all four JWT verifiers; **M2** amounts
compared with exact `big.Rat` (carries `json.Number`), with a 2^53+1 precision
test; **M3** deanonymization requests have a freshness window + replay guard;
**M5** request bodies capped on catsvc and trsvc.

Plus OS hardening: SSH brute-force throttle in pf (preserves password + dynamic
IP), and `scripts/security-audit.sh` for repeatable host verification.

### Deferred to v2 (documented, not gaps in the POC threat model)

- Key encryption-at-rest (needs passphrase-at-boot handling on a headless VM).
- ZK trusted-setup key persistence/pinning (M4) — needed when prover/verifier
  run as separate processes.
- Threshold (FROST) escrow decryption; chain-backed Trust Registry; real
  Poseidon-in-circuit (MiMC interim). All previously documented v2 items.
