# SPT-Txn Threat Model

**Status:** v0.1 — living document. Update before, not after, touching trust-boundary code.
**Method:** STRIDE per component, plus an explicit adversary catalogue.
**Audience:** implementers, adversarial reviewers, and eventually a bank security architecture review board and a federal ATO reviewer. Write for that audience.

---

## 1. Scope: What Is Inside the Trust Boundary

Inside (Opus + adversarial review + human line-by-line):

- **Issuer** — token minting, signing, envelope construction, intent digest computation
- **Verifier / PEP decision core** — signature verification, canonicalization, chain validation, policy evaluation
- **Attenuation engine** — delegation chain construction and verification
- **TBAC policy engine** — jurisdictional rule evaluation, fail-closed paths
- **Key management** — HSM/KMS integration, rotation, algorithm rotation
- **Receipt emitter + transparency log** — Merkle append, inclusion proofs, log signing

Outside (Sonnet, normal review):

- Adapters and skins (Envoy filter, OPA shim, MCP middleware transport layer)
- CLI, docs, demo, CI plumbing

**The skins hold no keys and contain no decision logic.** A compromised skin must be able to deny service but must *not* be able to mint authority. If a design change would give a skin the ability to influence a decision, that change moves the skin inside the trust boundary — reject it or re-scope it.

---

## 2. Adversary Catalogue

| Adversary | Capability | Primary goal |
|---|---|---|
| **A1 — Compromised agent** | Full control of an AI agent's reasoning/planning loop; holds a validly issued token | Execute an action *other than* the one declared at issuance |
| **A2 — Compromised sub-agent / delegate** | Holds an attenuated child token; can craft arbitrary requests | Escalate beyond the attenuated scope; widen authority |
| **A3 — Compromised workload** | Runs code on an attested host; holds workload identity | Obtain tokens for actions outside its policy scope |
| **A4 — Network attacker** | Observes and replays traffic; can drop/delay | Replay a valid token; force fail-open by inducing timeouts |
| **A5 — Malicious/compromised PEP operator** | Controls a deployed PEP instance | Rewrite decision history; forge an alternate evidence chain |
| **A6 — Malicious insider at issuer** | Access to issuer infrastructure | Mint tokens outside policy; suppress evidence |
| **A7 — Supply-chain attacker** | Compromises a dependency or the build pipeline | Introduce a subtle bypass into the trust boundary |
| **A8 — Prompt-injection content** | Controls data an agent reads (web page, document, tool output) | Induce A1 |

**A1 and A2 are the design centre.** SPT-Txn exists because role-based authorization fails against exactly these two. Every design decision in the trust boundary should be evaluated by asking: *does this still hold if the actor is fully compromised?*

---

## 3. STRIDE by Component

### 3.1 Issuer

| | Threat | Mitigation |
|---|---|---|
| **S** | Attacker impersonates a workload to obtain a token | Attested identity ingress only (SPIFFE SVID / cloud workload identity / K8s SA token). **Never** issue on a bearer secret alone. Attestation evidence hash sealed into the issued token. |
| **T** | Token contents tampered post-issuance | Full envelope covered by signature, **including the algorithm suite identifier** (see §4.3) |
| **R** | Issuer denies having minted a token | Every issuance emits a receipt to the transparency log before the token is returned to the caller. Issuance is not complete until the receipt is logged. |
| **I** | Token leaks transaction detail to intermediaries | Intent digest, not intent plaintext, in the token. SD-JWT selective disclosure where richer context is required. |
| **D** | Issuer flooded, denying legitimate issuance | Per-identity rate limits at the exchange endpoint. **Degradation must not open a fast path** — a rate-limited caller is denied, never waved through. |
| **E** | Caller obtains a token broader than its policy allows | Policy evaluated at issuance, fail-closed. Requested scope is a *ceiling*, not an instruction — the issuer grants the intersection of requested and permitted, never the union. |

**Specific bug to hunt:** an issuer that echoes back the client's requested scope without intersecting it against policy. This is a one-line mistake with total consequences.

### 3.2 Verifier / PEP Decision Core

| | Threat | Mitigation |
|---|---|---|
| **S** | Forged signature accepted | Standard library verification only. Constant-time comparison. **Reject `alg: none` and any unexpected suite explicitly** — allowlist, never denylist. |
| **T** | Request mutated between intent binding and execution | Verifier recomputes the canonical digest of the *actual* call and compares to the digest bound in the token. See §4.1 — this is the highest-risk path in the system. |
| **R** | PEP denies having made a decision | Signed receipt emitted at decision time, appended to transparency log |
| **I** | Timing side channel reveals token or policy internals | Constant-time comparison; uniform error responses — do not leak *which* check failed to the caller (log the detail, return a generic denial) |
| **D** | Policy engine timeout induced by attacker | **Fail closed.** Timeout ⇒ DENY, with decision class `unavailable` (distinguishable from `violation`). Bounded evaluation time; no unbounded policy constructs. |
| **E** | Chain accepted without full parent validation | See §4.2 |

### 3.3 Attenuation Engine

| | Threat | Mitigation |
|---|---|---|
| **T** | Caveat block modified to widen scope | Each hop cryptographically sealed; verification walks the *entire* chain from root |
| **E** | Child token grants authority the parent did not hold | **Monotonicity enforced by construction, verified offline.** Property-based tests generating random chains, asserting authority never widens at any hop. |
| **E** | TTL extension via delegation | Child TTL strictly less than parent TTL, enforced at construction *and* re-verified at validation |
| **D** | Unbounded chain depth exhausts verifier | Hard depth bound; exceeding it fails **closed** |
| **R** | Revoked delegation still honoured | Chains of depth > 1 require a status-list check. No status source reachable ⇒ DENY (`unavailable`). |

### 3.4 TBAC Policy Engine

| | Threat | Mitigation |
|---|---|---|
| **T** | Policy bundle swapped or modified | Bundle signed; bundle version hash recorded in every receipt so a decision can be replayed against the exact policy that produced it |
| **E** | Rule ordering or default-allow lets an action through | **Default deny is structural.** No policy construct may express "allow anything not otherwise denied." Reject such constructs at bundle load, not at evaluation. |
| **D** | Pathological policy causes unbounded evaluation | Bounded evaluation; no unbounded recursion or backtracking in the rule language |

### 3.5 Key Management

| | Threat | Mitigation |
|---|---|---|
| **S/E** | Issuer key compromise ⇒ total forgery | HSM/KMS custody; short key lifetimes; rotation with overlap windows as a *designed operation*, not an incident procedure |
| **T** | Log signing key compromise ⇒ forged evidence history | **Log signing key is separate from token issuance key**, separate rotation schedule, and the log is witness co-signed (see §3.6) |
| **I** | Key material in process memory / core dumps / logs | Never hold key material longer than necessary; never log it; disable core dumps in the issuer's deployment profile |

### 3.6 Receipt Emitter + Transparency Log

| | Threat | Mitigation |
|---|---|---|
| **R** | Operator silently rewrites decision history (**A5**) | Append-only Merkle log with signed tree heads and **external witness co-signing**. A compromised operator cannot produce a consistent alternate history that a witness will co-sign. This is the control that makes the evidence trustworthy *to a regulator* rather than merely *to the customer*. |
| **I** | Log leaks transaction contents or PII | **Salted hashes and references only.** No payloads, no PII, ever, in the log. Selective disclosure via SD-JWT when a receipt must be shown to a third party. |
| **D** | Log unavailable ⇒ decisions cannot be recorded | Decisions may proceed with local durable buffering **only if** the buffer is itself append-only and reconciled; a permanently unreachable log is a fail-closed condition, not a shrug. **Decide this policy explicitly per deployment and document it — do not let it default silently.** |

---

## 4. The Bugs That Will Actually Kill This

Ranked by likelihood × impact. An adversarial reviewer should start here.

### 4.1 Canonicalization mismatch — **the critical one**

The issuer computes an intent digest over a canonicalized representation of the declared action. The verifier recomputes it over the actual call. **If the two canonicalizations differ in any respect, an attacker can craft two semantically different requests with the same digest — a full authorization bypass.**

Divergence sources: key ordering, unicode normalization, number representation (`1.0` vs `1`, exponent forms), whitespace, duplicate keys, `null` vs absent, integer overflow at parse.

Requirements:
- Specify the canonicalization scheme **exactly** (JCS / RFC 8785). Cite it in the spec.
- **One implementation, shared by both paths.** Two implementations *will* diverge — this is not a hypothetical, it is a certainty over time.
- Differential fuzzing: generate structurally distinct inputs, assert distinct digests; generate semantically identical inputs, assert identical digests.
- Reject rather than normalize anything ambiguous. **A parser that "helpfully" fixes malformed input is an attack surface.**

### 4.2 Attenuation bypass

Validating a child token in isolation without walking the full chain to the root. Or a caveat language expressive enough to widen scope in some edge case.

Requirements:
- Verification **always** walks the full chain from root. There is no fast path for "trusted" children.
- The caveat language must be *provably* narrowing — if it can express "allow X" as well as "deny unless X", it is unsafe. Restrict expressiveness.
- Property-based test: random chains, assert `authority(child) ⊆ authority(parent)` at every hop, for all generated inputs. **This is the single highest-value test in the codebase.**

### 4.3 Algorithm downgrade

In hybrid classical+PQC mode, an attacker forces verification against the weaker suite.

Requirements:
- The negotiated suite identifier is **inside** the signed envelope. A downgrade requires forging the signature it is trying to weaken.
- Policy floors are non-bypassable: if the jurisdiction profile requires hybrid, a classical-only token is rejected regardless of what the token itself claims.
- Verify-either (transition) and verify-both (strict) are distinct, explicitly configured modes. Never infer the mode from the token.

### 4.4 Replay

Short validity windows narrow but do not close this.

Requirements: nonce binding; single-use enforcement at the PEP; replay cache sized to the validity window. **Cache unavailable ⇒ DENY** (`unavailable`), not "allow and hope."

### 4.5 Parser vulnerabilities

Malformed token handling is where the CVEs live in every token system ever built. Fuzz it continuously. Reject early, reject strictly, allocate nothing before validating length.

### 4.6 Confused deputy at the PEP

The PEP acts with *its own* authority, or forwards upstream credentials, instead of acting strictly on the token's authority.

**This is exactly the MCP token-passthrough gap.** We have written about it publicly. Reproducing it in our own middleware would be both a vulnerability and an embarrassment. The PEP must never hold or forward credentials that outlive a single decision.

### 4.7 Fail-open under load

Every timeout, every unreachable dependency, every degraded path. Grep the codebase for every error branch in the trust boundary and confirm each one denies. **An error path that returns `nil` where a decision object was expected is a fail-open in disguise** — this is why the type system must make an un-decided request unconstructable (see `CLAUDE.md` §2).

---

## 5. Assumptions and Explicit Non-Goals

**We assume:**
- The attested-identity substrate (SPIFFE, TPM, cloud IdP) is not fully compromised. If the attestation root is owned, we cannot help. State this to customers plainly rather than implying otherwise.
- HSM/KMS custody holds.
- The transparency log's witness set is not fully colluding.

**We explicitly do not defend against:**
- A compromised issuer with HSM access minting arbitrary tokens. *Mitigation is organisational (separation of duties) plus detective (the transparency log makes it visible after the fact).* Say so; do not overclaim.
- An agent that is authorized to do a harmful thing and does exactly that. **SPT-Txn constrains agents to their declared intent; it does not evaluate whether the intent is wise.** That is a policy problem, and the policy layer is where it belongs. Do not let marketing blur this line — overclaiming here is how security products lose credibility with the exact buyers we want.
- Legacy protocol translation in the general case (out of scope by decision — see `CLAUDE.md` §6).

---

## 6. Review Checklist for Trust-Boundary Changes

Before merge:

- [ ] Every error path denies, and the decision class distinguishes `violation` from `unavailable`
- [ ] No `==` on anything secret-adjacent; `crypto/subtle` throughout
- [ ] No custom crypto, no custom canonicalization, no hand-rolled anything
- [ ] Canonicalization uses the single shared implementation
- [ ] Attenuation property tests pass on newly generated random chains
- [ ] Parser fuzzing run on any change to token parsing
- [ ] `govulncheck` clean
- [ ] Receipt emitted for every decision, including denials
- [ ] Suite identifier covered by signature
- [ ] Adversarial review completed in a **fresh context**, brief: *"assume there is an authorization bypass; find it"*
- [ ] Human line-by-line review by the maintainer
- [ ] No public commit references private-repo material (`CLAUDE.md` §0)
