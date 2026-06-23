# Test Plan

How the POC is tested, at what level, with what tooling.

## Three layers of testing

**Unit tests** (`go test ./...`) — every package has `_test.go` files
covering the data structures, signing/verifying primitives, scope
containment logic, and audit log integrity. Fast, isolated, no network.
Run on every build.

**Integration tests** (`go test -tags=integration ./tests/...`) — in-
process tests that wire multiple services together and run end-to-end
flows. Use in-memory mock Trust Registry, no external network, no
relayd. Run before each milestone is considered complete.

**Smoke tests** (`./scripts/m*-smoke.sh`) — bash scripts that hit the
live host's HTTPS endpoints via `curl` and verify responses. Catch
deployment-level issues that unit and integration tests miss (cert
paths, relayd routing, socket permissions, pledge violations).

## What each test category covers

### Per-milestone test gates

Each milestone in [`BUILD-ORDER.md`](BUILD-ORDER.md) has a defined test
gate that must pass before the milestone is "done." A milestone is not
considered complete if any of its gates are red.

| M | Gate                                                              |
|---|-------------------------------------------------------------------|
| 0 | Skeleton tests green; TLS handshake clean; relayd 404 on unknown  |
| 1 | Trust Registry lookup over HTTPS returns correct seeded data      |
| 2 | CAT issued from SD-JWT verifies cleanly with `cnf` binding agent  |
| 3 | Scope attenuation accepts subset, rejects superset                |
| 4 | SPT-Txn Token issued, DPoP binding correct, lifetime 30s          |
| 5 | Eight-step engine: all 8 steps individually testable; full flow   |
| 6 | Audit log append-only invariant holds; Merkle roots verify        |
| 7 | Escrow envelope roundtrip; AAD tampering detected; deanon works   |
| 8 | Single-script demo runs clean from cold start to verified result  |

### Unit test coverage targets

| Package                     | Coverage target |
|-----------------------------|-----------------|
| `internal/trustregistry`    | ≥85%            |
| `internal/keys`             | ≥85%            |
| `internal/token`            | ≥85%            |
| `internal/tbac`             | ≥90%            |
| `internal/escrow`           | ≥85%            |
| `internal/audit`            | ≥85%            |
| `internal/dpop`             | ≥90%            |

90% on `tbac` because the eight-step engine is the core conformance
surface; each step needs at least one positive and one negative test.

### Specific test cases that must exist

**Token integrity tests** (covers Section 8.1):
- CAT signed by registered CT-issuer key verifies; signed by an
  unregistered key rejects.
- CAT with key embedded in the token (rather than fetched from registry)
  rejects — this is the spec's explicit MUST-NOT.
- Tampered CAT payload fails signature.
- Expired CAT rejects.

**Scope containment tests** (covers Section 3.4):
- Empty scope contained by any scope.
- Identical scopes contain each other.
- Subset contained, superset not contained.
- Disjoint scopes not contained.
- Scope with stricter `amount<=N` contained by scope with looser
  `amount<=M` where N<=M; rejects if N>M.

**Eight-step engine per-step tests** (covers Section 3.3):
- Step 1 (sig verify): pass with registered key; fail with revoked key.
- Step 2 (expiry): pass at iat<=now<=exp; fail before iat; fail after exp.
- Step 3 (audience): pass if aud matches; fail if mismatched; fail if
  multiple aud values and none matches.
- Step 4 (revocation): pass if not in revocation list; fail if listed.
- Step 5 (DPoP): pass with valid proof; fail with htm/htu mismatch; fail
  with jti reuse.
- Step 6 (chain): pass with verifiable CAT→Cap→Txn chain; fail if any
  link is unsigned or signed by wrong key.
- Step 7 (scope): pass if Txn scope ⊆ Cap scope ⊆ CAT scope; fail
  otherwise.
- Step 8 (context hash): pass if hash(txn_context) matches claim; fail
  if anything in the context was modified.

**Escrow tests** (covers Section 9.6):
- Envelope encrypt+decrypt roundtrip recovers the original zkDID.
- AAD = (humanAnchor || iss || iat) — modifying any of these after
  encryption causes decrypt to fail.
- Envelope keyed by humanAnchor: lookup works, returns the right one
  when multiple envelopes exist.
- Deanonymization request with valid lawful_basis_ref signature succeeds.
- Deanonymization request with wrong signer key fails.
- Escrow audit log entry created for every request, with no zkDID in the
  entry payload.

**Audit log tests** (covers Section 7):
- Append works; out-of-order writes serialized correctly.
- Merkle root deterministic for the same input.
- Merkle root signature verifies against the audit-key public key.
- Tampered log entry detectable via root mismatch.

### Negative tests are mandatory

For each "MUST" in the spec that this POC implements, there must be at
least one test that demonstrates the MUST is actually enforced (i.e., a
test that fails when the condition is violated, not just one that
succeeds when satisfied).

Specific examples:
- "Implementations MUST NOT accept issuer public keys embedded in the
  token itself or retrieved from a URL in the token" (Section 8.1) →
  test that constructs a token claiming a `jwks_uri` and verifies the
  verifier ignores it and uses the Trust Registry.
- "Implementations MUST verify that decryption of the envelope yields a
  plaintext whose first component, when committed, equals the
  humanAnchor in the AAD" (Section 9.6.2) → test that substitutes a
  zkDID-for-different-human and verifies the binding check fails.

## What we are deliberately not testing (yet)

- Real ZK proof verification. Mocked.
- Real threshold cryptography. Single-party for POC.
- Chain-based Trust Registry. Mock-backed.
- Multi-host deployment. Single-host.
- Performance / load. POC is correctness-focused.

Each of these has v2 work items that will introduce real tests.

## Test data

`testdata/` directory contains:
- `seed-trust-registry.sql` — known issuer keys for deterministic tests.
- `test-sdjwts/` — pre-generated SD-JWTs for various human enrolment
  scenarios.
- `test-agents/` — pre-generated agent keypairs.
- `golden-cats/` — known-good CATs for regression testing.
- `golden-txn-tokens/` — known-good SPT-Txn Tokens for verifier testing.

Golden values regenerate via `make regen-golden` if the canonical
serialization changes; otherwise they're treated as fixed regression
oracles.

## Running the tests

```sh
# Unit tests only (fast, runs in seconds)
go test ./internal/...

# With coverage report
go test -cover ./internal/...

# Integration tests (requires nothing external)
go test -tags=integration ./tests/...

# Smoke tests (requires a deployed instance)
./scripts/smoke-all.sh

# Per-milestone smoke
./scripts/m1-smoke.sh
./scripts/m5-smoke.sh
```

## CI

Not required for the POC, but recommended setup:

- GitHub Actions or sourcehut builds on every push.
- Matrix: OpenBSD-current and Linux (Linux for fast CI, OpenBSD for
  truth).
- On OpenBSD: run unit + integration. Don't run smoke (no public IP).
- On Linux: same.
- Block PRs on test failures.

For an individual-author POC repo, even just running tests locally
before each commit is fine. The discipline matters more than the
infrastructure.
