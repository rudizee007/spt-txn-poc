# SPT-Txn Glossary & Canonical Models

Authoritative terminology for the website, the IETF draft (-02 onward), the POC,
and the business deck (Part 2). When wording differs anywhere, **this file wins.**

Decision basis (2026-06-24): draft-01 uses **CT** 75×, "Capability Acquisition
Token" 4×, bare "CAT" 1×, "CAP" 0×, "Compliance Attestation" 0×. The standards
text is CT-centric and the CAT acronym is effectively free, so CAT is assigned to
the business-facing compliance credential and CT (not the invented "CAP") is the
capability primitive.

---

## 1. The three tokens (LOCKED)

**CAT → CT → SPT-Txn.** Issued by different actors, decreasing lifetime/scope:

- **CAT — Compliance Attestation Token.** The verify-once credential. Issued by a
  KYC/compliance provider after verifying the user's attributes. Holds the
  zkDID-bound, selectively-disclosable compliance claims. The user carries it and
  reuses it across platforms — never re-submitting documents. This is the
  attribute/identity layer, made a first-class token.
- **CT — Capability Token.** The scoped authorization. Issued by a platform /
  Trust Anchor when a CAT proof satisfies that platform's policy. A *root* CT
  establishes the maximum scope; *delegated* CTs (e.g. to an AI agent) are strict
  subsets with bounded delegation depth. Carries the humanAnchor. (This is the
  draft's primary primitive, "CT".)
- **SPT-Txn Token.** Per-transaction execution token (30-second TTL, bound to one
  transaction context, DPoP sender-constrained). Carries the Travel Rule ZK
  attestation. The token actually presented at the resource.

> Retired / collision notes:
> • "CAT = Capability Acquisition Token" and "CAT = Credential Attribute Token"
>   are both **retired**. CAT now means **Compliance Attestation Token** only.
> • "CAP" is **retired** — the capability token is **CT** everywhere (matches the
>   published draft). The draft's "root Capability Acquisition Token" is reframed
>   as the **root CT** in -02.

---

## 2. CANONICAL: the CAT + attribute model

Attributes are verified into the **CAT**; the **CT** is the authorization that a
satisfied CAT-proof unlocks. "You qualify" (compliance) is separate from "you may
act, up to this scope" (capability).

```
              ATTRIBUTE / IDENTITY LAYER   (who you are — proven, never disclosed)
  ┌────────────────────────────────────────────────────────────────────┐
  │  zkDID commitment  →  humanAnchor                                    │
  │  Credential claims, proven in zero-knowledge:                        │
  │    • STATIC  : KYC level, jurisdiction, accredited-investor          │
  │    • DYNAMIC : AML-risk, sanctions  ── DID-anchored attribute oracle │
  └───────────────────────────────┬────────────────────────────────────┘
                                   │  KYC/compliance provider verifies & issues
                                   ▼
  ┌────────────────────────────────────────────────────────────────────┐
  │  CAT — Compliance Attestation Token   (verify once · user holds)     │
  │   • selectively-disclosable compliance claims, bound to the zkDID    │
  │   • reusable across every platform — no document re-submission       │
  └───────────────────────────────┬────────────────────────────────────┘
                                   │  ZK proof of CAT vs the platform's policy
                                   ▼
              POLICY LAYER   (what's required)
  ┌────────────────────────────────────────────────────────────────────┐
  │  Policy object (representation-agnostic, chain-neutral)              │
  │   • composable across jurisdictions:  VARA ∧ MiCA ∧ CNAD            │
  │   • concrete on-chain instantiation:  Policy NFT  (informative)      │
  └───────────────────────────────┬────────────────────────────────────┘
                                   │  platform PDP issues on match
                                   ▼   ═════ ABAC → TBAC BOUNDARY ═════
  ┌────────────────────────────────────────────────────────────────────┐
  │  CT — Capability Token   (scoped authorization)                      │
  │   • root CT = maximum scope; delegated CTs attenuate (bounded depth) │
  │   • carries humanAnchor; e.g. "trade ≤ $50k/day until 2026-12"      │
  └───────────────────────────────┬────────────────────────────────────┘
                                   │  per transaction
                                   ▼
  ┌────────────────────────────────────────────────────────────────────┐
  │  SPT-Txn Token   (30s TTL · tx-bound · DPoP · Travel Rule attest.)   │
  │  ▸ DYNAMIC attributes (AML/sanctions) re-proven at CT-issuance and   │
  │    transaction time vs the oracle's committed state (max-proof-age)  │
  └────────────────────────────────────────────────────────────────────┘
```

### The static / dynamic rule (correctness guardrail)

Durable attributes (KYC level, jurisdiction, accreditation) are verified once and
bound into the **CAT**. Volatile attributes (AML-risk, sanctions) MUST NOT be
frozen into a long-lived credential; they are re-proven against the attribute
oracle's committed state when a **CT** is issued and again at **SPT-Txn** minting,
under a policy **max-proof-age**. So access can be revoked in real time by
updating the oracle feed, without revoking the CAT.

### Why this maps cleanly to the business model (Part 2)

KYC issues the **CAT** (verify once) → platform checks the ZK proof against its
**Policy** and issues a **CT** (instant, scoped) → agent gets a delegated **CT**
with the humanAnchor → each action emits an **SPT-Txn** token → all recorded to an
immutable audit trail. One credential, many platforms, milliseconds each.

---

## 3. Term definitions

- **humanAnchor** — a zkDID commitment carried from the CAT through every CT and
  SPT-Txn token, binding the chain to the accountable human without exposing
  identity. Satisfies EU AI Act Art. 14 human-oversight.
- **zkDID** — zero-knowledge Decentralized Identifier commitment: proves a valid,
  authorized-issuer DID satisfies policy without revealing the DID (breaks
  cross-verification correlation).
- **Policy object** — the representation-agnostic policy the platform PDP
  evaluates (normative, chain-neutral). **Policy NFT** is one concrete on-chain
  instantiation (informative), framed strictly as compliance infrastructure
  (utility), never an appreciating asset.
- **Trust Anchor / platform** — issues CTs after evaluating a CAT proof.
- **Trust Registry** — published (on-chain) list of issuers authorized to assert
  attributes / issue CATs; the POC VASP registry is an instance.
- **Attribute oracle** — DID-anchored signed feed of live attribute state (AML,
  sanctions); publishes committed state for blind, private lookup.
- **ABAC → TBAC boundary** — ABAC evaluates attributes once (CAT → CT issuance);
  TBAC enforces on the CT/SPT-Txn at every access point, no policy re-evaluation.
- **SD-JWT** — selective-disclosure JWT carrying the CAT's compliance claims.
- **Travel Rule attestation** — the FATF Rec-16 ZK attestation the SPT-Txn token
  carries (identity-commitment, amount-over-threshold, VASP-membership), bound to
  the transaction context.

---

## 4. Terminology & standards mapping

**Rule — anchor on first use.** Every coined term's first appearance in any
artifact (paper, draft, site, deck) MUST cite its base standard. Example:
*"a Compliance Attestation Token (CAT) is a W3C Verifiable Credential
[VC-DATA-MODEL] profiled for compliance attributes, serialized as an SD-JWT VC."*
Coin a term only when it adds a real profile, binding, or constraint; otherwise
use the standard word. One name per concept, everywhere.

| Our term | Base standard / reference | What we add |
|---|---|---|
| **CAT** — Compliance Attestation Token | W3C Verifiable Credentials Data Model 2.0; SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`) | compliance-attribute profile; zkDID binding; KYC-issued, reusable |
| **CT** — Capability Token | Object-capability security (Biscuit, Macaroons); OAuth access token | humanAnchor propagation; scope-subset + delegation-depth invariants |
| **SPT-Txn token** | OAuth Transaction Tokens (`draft-ietf-oauth-transaction-tokens`); DPoP (RFC 9449) | transaction-context binding; ~30s TTL; Travel Rule attestation |
| **zkDID** | W3C DID Core; anonymous credentials (BBS+, AnonCreds) | ZK commitment so the DID itself is never revealed (unlinkable) |
| **humanAnchor** | SD-JWT key binding; proof-of-personhood | registered claim `human_anchor`; immutable cross-token propagation |
| **Policy object / Policy NFT** | ABAC (NIST SP 800-162); XACML PDP/PEP; policy-as-code | composable cross-jurisdiction policy; on-chain instantiation (informative) |
| **Eight-step enforcement** | NIST SP 800-207 Zero Trust (PE/PA/PEP) | offline, cryptographic per-step enforcement on the bound token |
| *(note)* TBAC | **not** a canonical model — describe as "capability-based enforcement" | — |

Primitives used as-is (no coinage): Groth16/BN254 zk-SNARKs; Poseidon/MiMC;
Ed25519/X25519/ECIES; **ML-KEM (FIPS 203) / ML-DSA (FIPS 204)**; fuzzy extractors
+ nullifiers; **FATF Recommendation 16** (Travel Rule); **IVMS101**; VASP;
KYC/AML/CDD; OpenID4VCI (issuance). Jurisdiction note: "accredited investor" is
US (SEC Reg D) — use "eligibility/accreditation status" generically. BN254 has a
reduced (~100-bit) security margin vs BLS12-381 (~128-bit) — acknowledge the
trade-off.

## 5. Cross-references
Restoration plan & rationale: `docs/V2-TOPICS-CHECKLIST.md` (§F, §G, §H, §I).
TRP/TRISA interop: `docs/TRP-TRISA-INTEROP.md`.
