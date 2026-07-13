# SPT-Txn Security Architecture

**Audience:** a bank security architecture review board, a federal ATO package
reviewer, and an acquirer's technical due-diligence team. Written to be read by
all three.

**Scope:** this document describes the published architecture and its security
properties. It references only public work. It is not a marketing document; where
the system does not defend against something, it says so.

---

## 1. The problem, stated precisely

Authorization today is *role-scoped*. An actor — human, workload, or AI agent —
is granted a role, and that role's authority persists across every action the
actor takes for the life of the credential. This model fails at exactly the
moment actors fail: under credential theft, under prompt injection, under
goal hijacking, a compromised actor retains the full authority of its role.

The failure is structural, not incidental. Detecting the compromise is not a
prerequisite for the attacker to use the authority; the authority is simply
present. Every control that assumes "this actor is who it says and intends what
it usually intends" is void once the actor is manipulated.

SPT-Txn removes the assumption. Authority is *transaction-scoped*: it exists only
inside a short-lived token bound to one declared action, on one resource, under
one jurisdictional policy, verified against how the requesting workload was
attested. A compromised agent holds a token that is cryptographically useless for
any action other than the one it declared, seconds before.

## 2. Design invariants (non-negotiable)

These are enforced, not aspirational. Code that violates them does not ship.

- **Deny by default, fail closed.** Every timeout, malformed token, unreachable
  dependency, or missing evidence resolves to DENY, with a decision class that
  distinguishes a policy *violation* from an *outage* so an operator can tell an
  attack from a degradation.
- **Enforce structurally, not by convention.** Deny-by-default is a property of
  the type system: it is impossible to construct a request that has passed the
  enforcement point without a decision attached. A reviewer cannot silently
  delete a check and still compile.
- **No ambient authority.** Nothing is authorized by network position, a
  long-lived secret, or an assigned role. Authority lives only in a short-lived,
  transaction-scoped, cryptographically bound token.
- **Attenuation is monotonic and offline-verifiable.** Delegation can only
  narrow authority, enforced by construction and re-verified against the whole
  chain, with no call home.
- **Evidence is a byproduct.** Every decision emits a signed record at decision
  time. A component that cannot produce evidence does not ship.
- **No custom cryptography.** Standard-library and audited implementations only.
  Constant-time comparison for anything secret-adjacent.
- **Memory-safe languages only in the trust boundary.** No C/C++, including via
  cgo.
- **Latency is a security requirement.** The decision path holds p99 under
  ~10ms, because a PEP too slow to tolerate gets bypassed, and a bypassed PEP is
  worse than none. Measured: p50 ~35us, p99 ~72us on commodity hardware — roughly
  two orders of magnitude inside budget.

## 3. Architecture

### 3.1 Token chain

Three token types form a chain of decreasing authority, all signed JWTs,
verified offline:

- **Compliance Attestation Token (CAT)** — the root authority for an actor,
  establishing maximum scope and delegation depth. Optionally seals an
  attestation of the workload that requested it.
- **Capability Token (CT)** — a delegated token, a strict attenuation of its
  parent. Chains to arbitrary depth (bounded), agent to sub-agent to tool.
- **Transaction Token (TXN)** — short-lived, sender-constrained, bound to one
  concrete transaction and optionally to a declared intent.

### 3.2 The enforcement point

A single decision core sits behind thin, stateless skins — an Envoy `ext_authz`
filter (HTTP and gRPC), an OPA-compatible decision API, and Model Context
Protocol middleware for AI-agent tool calls. The skins hold no keys and contain
no decision logic; a compromised skin can deny service but cannot mint
authority. Deployable by a platform team in an afternoon, or it does not count.

### 3.3 Evidence plane

Every decision emits a signed Transaction Receipt into an append-only Merkle
transparency log with externally-witnessed signed tree heads. The result: an
auditor can prove that a specific control was enforced at the moment of a
specific transaction, inclusion-provable without revealing the rest of the log,
and impossible for even the operator to rewrite silently. Receipt fields map to
NIST SP 800-53, DORA, and SOC 2 controls for import into existing GRC tooling.

## 4. Threat model summary

Full STRIDE-per-component analysis is maintained separately. The bugs that would
actually kill this product, in likelihood order, and how each is closed:

1. **Canonicalization mismatch.** The verifier canonicalizes a request
   differently than the issuer did when computing the intent digest, yielding an
   authorization bypass. Closed by a single shared RFC 8785 canonicalizer,
   restricted to an unambiguous subset, differentially fuzzed against an
   independent implementation (validated byte-identical across 20,000 random
   values and continuous fuzzing).
2. **Attenuation bypass.** A child widens scope, extends lifetime, or escapes
   depth. Closed by monotonic construction plus a verifier that enforces the
   *chain intersection* of scope, so a dropped ceiling is inherited from an
   ancestor rather than becoming unconstrained. Property-tested over randomly
   generated chains.
3. **Algorithm downgrade.** Closed by covering the suite identifier with the
   signature and requiring both halves of a hybrid signature to be present.
4. **Replay.** Closed by nonce binding and single-use enforcement with a
   fail-closed replay cache.
5. **Parser vulnerabilities.** Closed by strict parsing, early length checks,
   and continuous fuzzing.
6. **Revocation gap.** Closed by offline Token Status List checks (fail-closed
   on an unavailable list) plus immediate key-cascade revocation.
7. **Confused deputy at the enforcement point.** Closed by acting strictly on
   the token's authority and never forwarding upstream credentials — including
   in the MCP middleware, which strips the token before forwarding.

### 4.1 Explicit non-goals

The system constrains an agent to its declared intent. It does **not** evaluate
whether that intent is wise — that is the policy layer's job. It does **not**
defend against a compromised issuer with signing-key access; that is mitigated
organizationally (separation of duties) and detectably (the transparency log
makes misuse visible after the fact). It does **not** attempt general legacy
protocol translation. Overclaiming any of these would cost credibility with the
exact buyers the system is for.

## 5. Cryptographic posture

Ed25519 for signatures; SHA-256 for digests and the Merkle log; constant-time
comparison throughout; issuer keys in HSM/KMS custody with rotation as a
designed operation. The log signing key is separate from the token issuance key.
Post-quantum readiness is built in as algorithm agility: a hybrid Ed25519 +
ML-DSA-65 (FIPS 204) suite with the suite identifier covered by the signature,
verify-either during transition and verify-both in strict mode, and
jurisdiction-pinned suite floors. Because transaction tokens are short-lived,
post-quantum migration is genuinely easy — the tokens outlive their algorithms
by minutes.

## 6. Assurance evidence

- **Reference implementation** under Apache 2.0: issuer, offline verifier,
  decision core, delegation, intent binding, receipts and transparency log,
  attested issuance, status list, algorithm agility, and gateway skins.
- **Property-based tests** on attenuation (the highest-value test in the
  codebase), differential fuzzing on the canonicalizer, parser fuzzing, and a
  latency-budget test that fails CI on regression.
- **Cross-implementation conformance vectors** (intent digests, receipt signing
  inputs, status-list decoding, canonical forms) generated by an independent
  implementation, so a third party can build interoperably without our code.
- **Adversarial review discipline:** trust-boundary changes receive a
  fresh-context review whose brief is "assume there is an authorization bypass;
  find it," followed by human line-by-line review. This process has found and
  closed real bypasses that passing tests did not surface.
- **Supply chain:** signed commits, pinned dependencies, `govulncheck` blocking
  in CI (zero reachable vulnerabilities), SLSA provenance and published SBOM on
  releases.
- **Formal analysis:** a cryptographic-theory paper with five game-based
  security proofs (SSRN 6379940; Zenodo 10.5281/zenodo.19299787).

## 7. Standards alignment

The construct maps directly onto the primitives that federal and enterprise
standards work is converging toward: the NCCoE "Software and AI Agent Identity
and Authorization" project (identification, authorization, non-repudiation,
prompt-injection mitigation); NIST SP 800-53 control enforcement with
machine-verifiable evidence; CISA Zero Trust Maturity Model identity and
workload pillars; the EU DORA / NIS2 / CRA / MiCA stack via jurisdictional
policy profiles; and OWASP's agentic-AI goal-hijacking concern via intent
binding. The IETF draft (`draft-coetzee-oauth-spt-txn-tokens`) is the
open specification of the token family.
