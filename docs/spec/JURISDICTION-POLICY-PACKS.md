# SPT-Txn — Jurisdiction Policy Packs, Regulatory Floor, and Drift (design note)

**Status:** v0.1 — design note, pre-implementation. Normative language per
RFC 2119. **Companion:** `docs/spec/JURISDICTION-RESOLUTION.md` (which jurisdiction
applies), `docs/spec/NHI-ATTESTED-ISSUANCE.md` (issuer-side scope intersection),
`draft-coetzee-oauth-spt-txn-tokens` §Attested-Issuance / §Status-List.
**Roadmap:** jurisdictional TBAC profiles.

> **Scope boundary (read this).** This note specifies the *mechanism* for
> packaging, signing, distributing, defaulting, overriding, and drift-checking
> per-jurisdiction ceilings. It does **not** contain any regulator's rule
> content, per-principal entitlement data, or the change-governance workflow —
> those are the private policy-administration / control-plane layer and are
> described here only at the boundary. Nothing below is unpublished IP (see
> `CLAUDE.md` §0).

---

## 1. What this adds

`JURISDICTION-RESOLUTION` decides *which* jurisdiction(s) apply to an exchange
and seals them into the token. This note defines *where the ceiling for each
jurisdiction comes from* and how a customer may safely tune it:

- a **maintained baseline** ceiling per jurisdiction, shipped as a signed,
  versioned **policy pack**;
- a **non-bypassable regulatory floor** carried in the same pack, which no
  operator configuration can loosen past;
- an **operator override** that may only ever narrow (be stricter);
- **drift**: any override is a signed diff against the baseline, surfaced and
  recorded so "this deployment deviates from the shipped default vX" is visible
  and auditable.

The whole model is expressed with the existing `tbac.Intersect` primitive — one
audited greatest-lower-bound function — so no new scope logic is introduced.

## 2. Effective ceiling (normative)

For a single applicable jurisdiction `J` with pack `pack(J)` = { `baseline`,
`floor` } and an optional operator override `override(J)`:

```
config(J)  = override(J)  if present, else baseline(J)
applied(J) = tbac.Intersect(floor(J), config(J))
```

Because `Intersect` only ever narrows, `applied(J)` is guaranteed contained in
`floor(J)` — **an operator can be stricter than the regulatory floor but never
looser.** The floor is thus non-bypassable by construction, not by convention.

For the conjunction of applicable jurisdictions `{J1..Jn}` (resolution invariant
J8, "stricter governs"):

```
permitted = tbac.Intersect(applied(J1), applied(J2), … applied(Jn))
granted   = tbac.Intersect(permitted, requested)     // issuer-side, NHI §Attested-Issuance
```

Every narrowing is the same primitive; the result is contained in every input,
so no jurisdiction, operator override, or request can widen authority.

## 3. Pack structure and signing (normative)

A policy pack is a signed object:

```
{
  "jurisdiction": "<REGION>-<REGULATOR>",   // canonical id, resolution J7
  "version":      <uint>,                    // monotonic per jurisdiction
  "iat":          <unix>,
  "exp":          <unix>,                    // freshness bound
  "baseline":     <scope>,                   // recommended default ceiling
  "floor":        <scope>,                   // loosest configuration permitted
  "rules_ref":    <opaque reference/digest>  // to the private rule content, if any
}
```

- Packs MUST be signed with the **policy-administration key**, which MUST be
  distinct from the token-issuance key and the log-signing key, with its own
  rotation schedule (mirrors the receipt/issuer key separation).
- `baseline` MUST itself be contained in `floor` (`Contains(floor, baseline)`
  nil); a pack failing this MUST be rejected at load.
- The pack carries only ceilings, the floor, metadata, and an opaque reference
  to rule content. The **rule content itself is not in the public pack** — it is
  the private policy layer; the reference lets a PEP bind to it without the
  public mechanism carrying it.

## 4. Distribution and fail-closed consumption (normative)

- Packs are distributed to issuers and PEPs as **signed snapshots**, exactly the
  model the Token Status List already uses: published by the policy-administration
  layer, polled and cached locally, verified **offline** in the decision path.
- A consumer MUST verify the pack signature against the configured
  policy-administration public key and MUST check freshness (`exp`). A pack that
  is **absent for a required jurisdiction, expired, unsigned, or fails signature
  or the `Contains(floor, baseline)` check MUST fail closed (deny)** — never a
  permissive fallback.
- Consistent with the issuer startup rule (NHI §6), an issuer with no valid pack
  for a jurisdiction it is asked to serve MUST refuse, not default.

## 5. Override and drift (normative)

- An operator override for jurisdiction `J` is applied only as `config(J)` in §2,
  so it is structurally incapable of loosening past `floor(J)`.
- Any override MUST be recorded as a **diff against the signed baseline
  `(jurisdiction, version)`**. The deployment MUST expose whether each
  jurisdiction is running the **unmodified baseline** or a **modified** config,
  and the diff.
- Every issuance and every PEP decision receipt MUST record: the applicable
  jurisdiction id(s), the baseline pack `version`, a boolean `baseline_modified`,
  and a digest of the applied ceiling. An auditor can then prove which policy
  version applied and whether it deviated from the shipped default, without
  seeing the private rule content.
- **Change governance is out of scope here.** Authoring baselines/floors,
  approving an override (maker-checker / four-eyes), and the drift UI live in the
  policy-administration / control-plane layer. This note only requires that an
  override be a signed-baseline diff and be recorded in evidence.

## 6. Division of labor (mechanism vs. policy)

| Concern | Where |
|---|---|
| Pack format, signing, `Intersect`-based floor enforcement, drift diff, receipt fields | **Public mechanism** (this note; issuer + PEP) |
| Signed-snapshot distribution & offline fail-closed verification | **Public mechanism** (reuses status-list model) |
| Baseline/floor *values*, regulator rule content, per-principal entitlement | **Private** policy-pack layer |
| Authoring, versioning workflow, four-eyes override approval, drift dashboard | **Private** control-plane / policy-administration layer |

The seam is a signed pack keyed by jurisdiction; the public side never needs to
know how it was authored, only that it verifies and is fresh.

## 7. Open items (feed draft-07)

- Claim/field registration for the receipt drift fields (`policy_version`,
  `baseline_modified`) alongside `spt_jurisdiction`.
- Pack serialization + canonicalization for the signature (reuse JCS / the
  receipt canonicalization, one implementation shared by signer and verifier).
- Policy-administration key rotation and overlap-window handling.
- Whether a pack MAY reference multiple rule-content versions (regime updates
  mid-validity) or must be re-issued per change (leaning: re-issue, monotonic
  version, for clean drift semantics).

## 8. Non-goals

- Shipping any regulator's rule content or thresholds in the public tree.
- The override-approval workflow (governance) — control-plane concern.
- Legal determination of the correct floor — a compliance input, not code.
