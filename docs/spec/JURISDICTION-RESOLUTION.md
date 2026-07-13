# SPT-Txn — Jurisdiction Resolution (design note)

**Status:** v0.2 — design note, pre-implementation; the §6 design decisions are
resolved and the identifier scheme and precedence rule are now normative.
Normative language per RFC 2119. **Companion:**
`docs/spec/NHI-ATTESTED-ISSUANCE.md`, `draft-coetzee-oauth-spt-txn-tokens`
§Attested-Issuance and §Receipts. **Roadmap:** jurisdictional TBAC profiles.

> **Scope boundary (read this).** This note specifies the *mechanism* by which
> an issuer selects, binds, and enforces a jurisdiction — not the legal content
> of any regulator's rules and not the per-principal entitlement data. The rule
> content and per-jurisdiction ceilings are jurisdictional policy managed in the
> deployment's policy-administration layer and are out of scope here. Nothing in
> this public note describes that private material (see `CLAUDE.md` §0).

---

## 1. Problem

The reference issuer today loads a single policy-permitted scope ceiling
(`SPT_WL_PERMITTED_SCOPE` / `SPT_IDP_PERMITTED_SCOPE`) and grants
`intersect(requested, permitted)` at mint (see NHI-ATTESTED-ISSUANCE §6). A VASP
operating across regimes — e.g. **SEC** (US), **MiCA** (EU), **VARA** (Dubai),
**CIMA** (Cayman) — needs a *different* ceiling, and a different enforced rule
set, per jurisdiction. The issuer must therefore select the ceiling that applies
to a given exchange, and the PEP must enforce the matching regime.

The single hard requirement that shapes the whole design: **the caller must not
be able to choose its own jurisdiction.** If a workload bound to SEC could obtain
a looser regime by asking for it, that is a pick-the-loosest privilege
escalation — the same failure class as an audience or entitlement that defaults
open. Jurisdiction is an authorization-relevant input and must be treated as one.

## 2. Invariants (normative)

- **J1 — Derived, not declared.** The applicable jurisdiction MUST be *derived*
  from trusted inputs, never taken from a free request parameter. A request MAY
  carry a jurisdiction *hint*, but the issuer MUST validate it against the
  derived value and MUST fail closed on a mismatch; the hint MUST NOT be able to
  select a jurisdiction the derivation did not.
- **J2 — No pick-the-loosest.** Resolution MUST NOT let a principal obtain a
  more permissive regime than the one it is entitled to. Where two trusted
  signals disagree, the **stricter** regime governs.
- **J3 — Sealed and bound.** The resolved jurisdiction-profile identifier MUST
  be sealed into the issued token under the signature (a `spt_jurisdiction`
  claim), so it cannot be swapped or stripped downstream, and MUST be propagated
  unchanged through the delegation chain (like the human anchor).
- **J4 — Enforced at the PEP.** The PEP MUST evaluate the transaction against the
  rules of the *sealed* jurisdiction, loaded from its locally cached, signed
  policy snapshot. A token whose sealed jurisdiction is unknown, or whose
  snapshot is stale/unsigned/unavailable, MUST fail closed.
- **J5 — Deterministic and auditable.** Resolution MUST be deterministic for a
  given set of inputs, and those inputs MUST be recorded (hashed) in the decision
  receipt, which already carries a jurisdiction profile (draft §Receipts).
- **J6 — Fail closed on non-resolution.** If a jurisdiction cannot be resolved,
  the issuer MUST deny and issue no token, with a decision class that
  distinguishes an *unresolved* jurisdiction (a violation) from an *unavailable*
  policy source (an outage), per the receipt model.
- **J7 — Canonical identifier.** A jurisdiction profile MUST be identified by the
  canonical form `<REGION>-<REGULATOR>`, where `<REGION>` is an ISO 3166-1
  alpha-2 code (the reserved code `EU` for Union-wide regimes; an ISO 3166-2
  subdivision code where the regulator is subnational) and `<REGULATOR>` is a
  stable short tag, unique within that region, registered in canonical casing —
  e.g. `US-SEC`, `EU-MiCA`, `AE-VARA`, `KY-CIMA`. Identifiers are compared as
  exact strings; an unrecognized identifier MUST fail closed (J4/J6). A
  maintained tag registry keeps the tags collision-free.
- **J8 — Conjunction of applicable regimes ("stricter governs").** When more than
  one trusted signal resolves to a jurisdiction (e.g. the principal's licensed
  regulator *and* the transaction corridor), ALL resolved jurisdictions apply.
  The issuer MUST seal every applicable identifier (`spt_jurisdiction` is a set),
  MUST grant the intersection of every applicable jurisdiction's ceiling, and the
  PEP MUST enforce every listed regime — a transaction denied under any one
  regime is denied. "Stricter governs" is therefore realized as the conjunction
  of all applicable regimes (scope intersection plus multi-regime enforcement),
  never as a selection of the looser.

## 3. Resolution strategies

These are not exclusive; a deployment MAY compose them (§3.4).

### 3.1 Attested-principal's licensed regulator — *recommended default*

The jurisdiction is a property of the *attested identity*: the SPIFFE trust
domain / SVID path, or a signed licensing claim in the attestation, maps to the
regulator that licenses the entity behind the workload (e.g.
`spiffe://prod.vasp-ky/...` → CIMA). Because the value is derived from a verified
attestation the caller cannot forge, J1 and J2 hold **by construction** — a
workload cannot change its own trust domain to move regimes. The
`trust-domain → jurisdiction` mapping is policy data (§4).

*Best when* one workload corresponds to one licensed entity. *Caveat:* an entity
licensed in several regimes and running a single workload across them needs the
corridor signal (§3.2) to disambiguate per transaction.

### 3.2 Transaction corridor / counterparty

The applicable regime is a function of *both ends* of the flow — the originator's
and the beneficiary's jurisdictions — i.e. the corridor. This is the natural fit
for cross-border VASP transfers and dovetails with Travel-Rule handling
(`internal/travelrule`). The applicable ceiling is typically the **intersection**
of both ends' ceilings (the stricter governs), which composes directly with
`tbac.Intersect`.

*More expressive, more complex.* The corridor inputs (counterparty jurisdiction,
VASP directory entry) MUST themselves be attested or validated — a
caller-asserted counterparty is a J1 violation.

### 3.3 Per-jurisdiction endpoint — *operational, available today*

Run one issuer instance per jurisdiction, each with its own
`SPT_*_PERMITTED_SCOPE` (the mechanism that exists now), reachable only by
principals entitled to that jurisdiction (network- and authorization-gated at the
gateway). Jurisdiction is *which endpoint you reached*, and endpoint reachability
is the trusted signal.

*Simplest, needs no new issuer code.* It pushes the J1/J2 burden onto deployment
access control: if endpoint routing is not access-controlled, the guarantee is
lost. A sound first increment; strongest when combined with §3.1.

### 3.4 Composition

The strategies layer: per-jurisdiction endpoints (§3.3) each resolving the
principal's licensed sub-scope (§3.1), with the corridor (§3.2) narrowing
further per transaction. Because every layer only ever *intersects* (narrows),
composition is monotonic and cannot widen authority — J2 is preserved across all
of them.

## 4. Where ceilings and rules live (mechanism vs. policy)

- **Public mechanism (this reference).** The issuer holds a
  `jurisdiction → ceiling` map and a pluggable *resolver* that returns the
  jurisdiction from trusted inputs (§3). The granted scope is
  `tbac.Intersect(ceiling_for(jurisdiction), requested)`. A jurisdiction with no
  configured ceiling MUST fail closed (J6). This is a small, publishable
  generalization of today's single-ceiling loader.
- **Policy data (out of scope here).** The per-jurisdiction ceilings, the
  per-principal entitlements, and the regulator rule sets (SEC, MiCA, VARA, CIMA,
  …) are jurisdictional TBAC bundles authored and maintained in the deployment's
  **policy-administration point (PAP)**, and distributed to issuers and PEPs as
  **signed, offline-verifiable snapshots** — the same signed-snapshot,
  fail-closed-on-stale distribution model the Token Status List already uses.
  Authoring and management of that content is not part of this public reference.

The seam between the two is deliberately narrow: the public mechanism consumes a
signed snapshot keyed by jurisdiction and does not care how it was authored.

## 5. Token and receipt binding

1. The resolver yields one or more canonical identifiers (J7); the issuer seals
   them as the signed `spt_jurisdiction` claim — a set — in the root CAT (J3),
   propagated unchanged down the chain.
2. The granted scope is the intersection against *every* applicable
   jurisdiction's ceiling (J8, §4); all other issuance rules (mandatory
   audience/expiry, depth bound, proof-lifetime clamp) are unchanged.
3. At execution the PEP reads the sealed `spt_jurisdiction` set, loads each
   listed jurisdiction's signed policy snapshot from local cache, and enforces
   all of them; a transaction denied under any one regime is denied (J8). An
   unknown / stale / unsigned snapshot for any listed jurisdiction → deny (J4).
4. The decision receipt records the jurisdiction profile and a hash of the
   resolution inputs (J5), so an auditor can prove *which* regime was applied and
   *why* it was selected.

## 6. Resolved decisions

- **Identifier scheme — DECIDED.** ISO 3166 region plus a regulator/regime tag,
  canonical form `<REGION>-<REGULATOR>` (J7): e.g. `US-SEC`, `EU-MiCA`,
  `AE-VARA`, `KY-CIMA`. `EU` (reserved code) is used for Union-wide regimes and
  ISO 3166-2 subdivisions where a regulator is subnational. A maintained tag
  registry keeps them stable and collision-free; unrecognized identifiers fail
  closed.
- **Precedence — DECIDED.** Stricter governs, realized as the conjunction of all
  applicable regimes (J8): seal every applicable identifier, grant the
  intersection of their ceilings, and have the PEP enforce every regime — denial
  under any one is denial. Never a selection of the looser.
- **Corridor input — DECIDED in principle; wire format deferred.** Corridor
  inputs (counterparty jurisdiction, VASP-directory entry) MUST be attested or
  validated (J1); the concrete input format and directory binding are specified
  with the draft-07 corridor profile.
- **Claim registration — DECIDED.** `spt_jurisdiction` (a set of canonical
  identifiers) is registered in the draft's IANA section alongside the existing
  SPT-Txn claims when the jurisdiction feature is folded into draft-07.

## 7. Non-goals

- Authoring or shipping any regulator's rule content — a policy-pack concern.
- Making the *legal* determination of which regime applies. This note specifies
  the mechanism to derive, bind, and enforce a jurisdiction from trusted inputs;
  the legal mapping that feeds those inputs is a compliance input, not code.
