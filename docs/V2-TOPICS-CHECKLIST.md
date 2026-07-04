# SPT-Txn v2 — Master Topics Checklist (Working Paper + Website)

Purpose: a single coverage list so nothing is missed in the new v2 working paper
*or* on foss.violetskysecurity.com. Each topic notes its **status** so we write
honestly: `BUILT` (running in the POC), `DESIGNED` (specified, not yet coded),
`PLANNED` (roadmap/intent). Maintained as the source of truth while drafting.

Status legend: ✅ BUILT · ✳️ DESIGNED · 🗺️ PLANNED

---

## A. New additions (the focus of v2)

### A1. zkDID — zero-knowledge decentralized identity
- ✅ Identity commitment circuit (Groth16/BN254), the `human_anchor`.
- ✅ Anchor unified: token `human_anchor` == the ZK-proven commitment (one value).
- ✳️ DID method / document binding (did:web / did:spt) → commitment.
- 🗺️ Selective-disclosure credential model beyond SD-JWT (BBS+ / PQ alternative).
- Paper: define the DID method, the commitment scheme, binding to the token chain.
- Site: "Privacy-preserving identity" explainer; how anchor ties human↔agent↔txn.

### A2. zkDNS — BOTH layers (per decision)
**Layer 1 — decentralized name→key/endpoint discovery (trust layer):**
- ✳️ A naming/resolution layer that binds a name → public key + service endpoint
  without depending on centralized DNS roots / a single CA.
- ✳️ Complements/replaces the **DNSSEC** chain of trust with a verifiable,
  decentralized binding (ZK proof of a name's registration in a committed set).
- ✳️ Replaces TRP **Travel Address** / TRISA **GDS** discovery with a neutral,
  non-custodial VASP/agent directory (Merkle-committed, signed roots).
- Reuses the existing **VASP registry** pattern (committed set + membership proof).
**Layer 2 — private resolution (query privacy):**
- ✳️ Hide *who is resolving what* (resolver/query privacy) over DNSSEC, which
  leaks query contents. ZK / PIR-style lookup so a VASP can resolve a counterparty
  without revealing its query graph.
- Paper: threat model (censorship, query surveillance, root capture), the
  name→key binding proof, the private-lookup construction, relationship to
  DNSSEC and to ICANN-root trust.
- Site: "Beyond DNS/DNSSEC" section; why naming must be decentralized + private.

### A3. Post-quantum (PQ) plan — hybrid migration posture
- 🗺️ **Signatures:** migrate Ed25519 (SD-JWT, registry roots, audit) → NIST PQC
  **ML-DSA (Dilithium)**, hybrid (classical+PQ) during transition.
- 🗺️ **KEM / escrow:** ECIES/X25519 → **ML-KEM (Kyber)** hybrid for the escrow
  envelope and any key exchange.
- 🗺️ **ZK layer reality check:** pairing-based **Groth16 is NOT post-quantum**.
  Document the honest options: (a) PQ-secure proof systems (STARKs / hash-based,
  lattice SNARKs) as a future migration, (b) keep SNARKs for now but treat the
  *signature/KEM* layer as the near-term PQ priority since that's the standing-data
  exposure.
- 🗺️ **Crypto-agility:** algorithm identifiers in tokens/attestations so the suite
  can roll without breaking the wire format ("Quantum-Day ready" but honestly).
- Paper: a dedicated "Post-Quantum Migration" section with phased plan + rationale.
- Site: "Post-Quantum roadmap" — what's classical today, what migrates, when.

### A4. Hash / proof-system migration — MiMC → Poseidon
- ✅ Today: **MiMC** over BN254 (the only ZK-friendly hash in the pinned gnark).
- 🗺️ Migrate to **Poseidon** (fewer constraints, faster proving, ecosystem
  standard) — requires a gnark upgrade; tracked as v2.
- 🗺️ Re-evaluate the proving system itself (Groth16 trusted setup → PLONK/Halo2
  universal setup, or STARK for PQ) — note tradeoffs (setup, proof size, speed).
- Paper: "Cryptographic primitives & migration" — current vs target, why Poseidon,
  the trusted-setup story, links to the PQ section.
- Site: brief "what's under the hood" with the honest current-state note.

---

## B. Already-built substance to reflect (don't undersell what's real)

- ✅ **Token chain:** CAT → CAP (scope-attenuated) → SPT-Txn token (30s TTL,
  tx-context-bound, DPoP sender-constrained); agent is the holder; human anchor.
- ✅ **FATF Travel Rule (Rec 16)** privacy-preserving layer; **IVMS101** data model.
- ✅ **TRP transport** (OpenVASP) carrying the ZK attestation as a payload-level
  extension; cleartext-only transfers refused.
- ✳️ **TRISA bridge** (sealed Secure Envelope mapping) — designed, deferred.
- ✅ **Registered-VASP registry** (committed Merkle set, signed roots).
- ✅ **Two-party split:** separate originator (proving key) / beneficiary
  (verify-only) VASP services; proven cross-process and deployed (trruleo/trruleb).
- ✅ **SD-JWT** selective disclosure (reveal surname, hide given name / amount).
- ✅ **Three ZK predicates:** identity commitment, amount ≥ threshold, VASP
  membership — bound to the payment via `txn_context_hash`.
- ✅ **Blockchain-agnostic** ledger adapter (XRPL is a *target*, not a dependency).
- ✅ **Security-by-design on OpenBSD:** pledge(2)/unveil(2), privsep users, relayd
  TLS, pf, signify keys; **security audit FAIL=0**.
- ✅ **Audit log** with Merkle-root publication.
- ✳️/🗺️ **Threshold escrow / FROST** deanonymization (single-party ECIES today,
  FROST threshold = v2).
- ✅ **AI-to-AI / agent** use: the agent is the token holder; human stays
  accountable via the anchor — already in the token chain.

---

## C. Positioning & differentiation (grant + standards)

- 🗺️ **Related work / differentiation** vs DNA Protocol and other XRPL ZK-identity:
  three wedges — **no token**, **no new chain / blockchain-agnostic**,
  **compliance-first** (complements FATF/regulation, not anti-institutional) —
  plus the honest PQ note (they claim Dilithium; we add a PQ roadmap).
- 🗺️ **XRPL Credentials** complement (not compete): SPT-Txn is the off-ledger
  privacy + Travel Rule layer above on-ledger credentials.
- 🗺️ **Standards track:** IETF (extends `draft-coetzee-oauth-spt-txn-tokens-01`)
  and NIST (PQC alignment).
- 🗺️ **Real-world pilot** path (close the gap vs competitors' pilot claims).

---

## D. Cross-cutting sections every deliverable needs

- Threat model (per layer: token, Travel Rule, zkDNS, escrow).
- Security model & assumptions (trusted setup, key custody, PQ horizon).
- Privacy model (what each party learns; disclosure minimisation).
- Interoperability (IVMS101, TRP, TRISA, DNSSEC bridge).
- Key management (perms + pledge in the live deployment; **PKCS#11/HSM signing implemented & validated** — SoftHSM2/non-extractable Ed25519/`crypto.Signer`; FDE / threshold roadmap — see the
  key-management discussion; PQ key formats).
- Glossary (CAT/CAP/SPT-Txn, zkDID, zkDNS, Poseidon, ML-DSA/ML-KEM, IVMS101…).

---

## E. Website (foss.violetskysecurity.com) coverage map

The site should mirror the paper at a lighter depth:
1. **What it is** — privacy-preserving authorization + Travel Rule, blockchain-agnostic, no token.
2. **zkDID** — identity without exposure (A1).
3. **zkDNS** — decentralized + private naming beyond DNS/DNSSEC (A2, both layers).
4. **Post-Quantum roadmap** — honest hybrid plan (A3).
5. **Under the hood** — ZK predicates, Poseidon migration, OpenBSD hardening (A4, B).
6. **Standards & differentiation** — IETF/NIST, vs token/new-chain approaches (C).
7. **Try it / status** — live Travel Rule endpoints, security audit FAIL=0, repo link.

---

---

## F. Recovered from framework + author notes (restore in v2) — and WHY NFT dropped

### F0. The anomaly, diagnosed
The framework (v6 PDF + author notes) is RICH; the IETF drafts (-00, -01) are a
SCOPED-DOWN subset. Policy NFTs went from a headline, patent-defensible
contribution to a single passing line ("ABAC PDP evaluates against Policy NFT",
Section 7 flow). The changelogs never mention NFT → it was pared at the
framework→I-D conversion, not deleted in a revision.

**Why it was (reasonably) dropped — three reinforcing causes:**
1. **Chain-neutrality.** The I-D is an OAuth/Transaction-Token spec; IETF token
   specs avoid mandating blockchain objects. A "Policy NFT" is on-chain.
2. **ABAC→TBAC split.** The draft's thesis: ABAC evaluates policy ONCE at
   issuance, TBAC enforces on the token after. PNFTs live on the ABAC/issuance
   side — which the draft treats as out of scope.
3. **Regulatory cleanliness (the new insight from the notes).** The notes'
   own Howey + money-transmission analysis flag **commercially-sold Policy NFTs
   as the highest-risk token type** (securities borderline if marketed as
   appreciating; PNFT marketplace + KYC revenue-share = money-transmission risk;
   VASP/CIMA exposure). Keeping a standards-track token spec free of a tradeable
   on-chain compliance-asset layer is prudent — you don't want a regulator
   reading the IETF draft as "tradeable compliance securities."

**The cost:** the framework's distinctive IP (Policy NFTs as composable,
versioned, jurisdiction-aware compliance objects) vanished from the
standards-track narrative even though the abstract still advertises it.

**Restoration approach (v2):** add a representation-agnostic **policy-object
binding** to the NORMATIVE text (a "policy reference / policy commitment" the
ABAC PDP evaluates — chain-neutral, no securities baggage); document **Policy
NFTs as ONE concrete on-chain instantiation** in an INFORMATIVE appendix /the
framework paper, explicitly framed as utility/compliance-infrastructure (never
appreciating asset) to stay clear of Howey.

### F1. ✅ Terminology collision — RESOLVED (2026-06-24)
Three past meanings of CAT (Credential Attribute / Capability Acquisition /
Compliance Attestation). LOCKED: **CAT = Compliance Attestation Token (KYC-issued)
· CT = Capability Token (platform-issued) · SPT-Txn**. "CAP" retired (use CT).
See docs/GLOSSARY.md §1. Website + draft -02 must be reconciled to this
(CAP→CT; the capability-ceiling "CAT" → root CT; add CAT as the compliance layer).

### F2. Three-token model (from notes) to reconcile with the draft
- ✳️ **CATs** (Credential Attribute Tokens) — soulbound (identity) or
  transferable (capability); expiry-encoded; ZK-provable; DID-anchored not
  wallet-anchored.
- ✳️ **Policy NFTs (PNFTs)** — ABAC policy AS an NFT; smart contract IS the PDP;
  composable (policy A ∧ B for cross-border stacking), versioned, licensable.
- ✳️ **Access Grant Tokens (AGTs)** — minted when CATs satisfy a PNFT; TTL,
  revocable, optionally delegable; carries proof-of-evaluation. (Maps to the
  POC's SPT-Txn runtime token role.)

### F3. zkDID — full trust geometry (notes are detailed; ✅ commitment built)
- Unlinkability: DID itself never revealed; breaks the correlation attack.
- Fixes: AGT correlation (→ stealth addresses), oracle surveillance (→ blind
  queries vs committed state, DECO-style), regulator-vs-privacy (→ escrow
  selective deanonymization), verifier data-minimisation (no PII received).
- Trust anchor = on-chain **regulatory trust registry** (VARA/CNAD/GLEIF →
  licensed issuers → zkDID commitments). (Echoes the POC VASP registry.)

### F4. Biometric uniqueness — do it RIGHT (framework claims it; notes warn)
- ❌ NOT biometric hashes on-chain (low entropy, fuzzy, irreversible-leak,
  unresettable).
- ✳️ **Fuzzy extractor → secret R → commitment C + public helper P**; **nullifier
  N = PRF(R, domain)** for global Sybil-resistance; ZK proof of knowledge of R;
  secure-enclave **liveness attestation** (iris/fingerprint, not face-alone).
  Soulbound biometric-anchor NFT binds C to the zkDID. Enrollment authority =
  licensed KYC issuer (consistency vs identity).

### F5. zkDNS — NO prior source found (drafts: 0; notes: 0) → AUTHOR FRESH
- Not a "dropped" item; genuinely new. Write both layers (name→key discovery +
  query privacy) from scratch; align with the VASP-registry / trust-registry
  pattern already used.

### F6. Legal/regulatory framing (notes) — for framework/business docs, NOT the normative I-D
- Howey: core tokens are utilities (fail profit-expectation); PNFTs safe only if
  sold as compliance infrastructure, never as appreciating/yield assets.
- Money transmission: KYC revenue-share + third-party PNFT marketplace = real
  risk; keep SPT-Txn at the authorization layer, "do not touch the money."
- VASP (CIMA) registration likely; MiCA/CASP if EU; get written legal opinion.

### F7. Standards alignment & related work (notes) — paper's Related Work / outreach
- NIST: **IR 8587** (token forgery/theft/misuse — direct fit), SP 800-207/207A
  (Zero Trust), SP 800-204A/B/C (microservices ABAC), SP 800-63-4 (digital
  identity / ZK privacy), AI 600-1 + AI RMF (agentic delegation), SP 800-162
  (ABAC), SP 800-57 (key mgmt), SP 800-133r3 (key generation).
- **git-id (MyNextID)** complementarity: git-id = *who the agent is*, SPT-Txn =
  *what it may do*; 6 crypto gaps git-id leaves (esp. no PoP, no owner→agent
  binding) are what SPT-Txn's transaction-binding/TB property closes.
- Identifiers to carry forward: ORCID **0009-0009-6557-8843**; Zenodo DOIs
  10.5281/zenodo.19299787 and .18917439; datatracker draft-coetzee-oauth-spt-txn-tokens.

### F8. Versioning hygiene
- draft-01 contains a "Changes from -03" changelog (lineage isn't clean 00→01;
  intermediate 02/03 collapsed). Fix numbering before publishing -02; that churn
  is how content silently dropped.

---

## G. CANONICAL — the CAT + attribute model → see docs/GLOSSARY.md (authoritative)

Token chain LOCKED 2026-06-24 (supersedes earlier CAT=Capability Acquisition / CAP):
**CAT (Compliance Attestation Token, KYC-issued) → CT (Capability Token,
platform-issued; root sets max scope, delegated CTs attenuate) → SPT-Txn
(per-transaction)**. Attributes are verified into the CAT; the CT is the
authorization a satisfied CAT-proof unlocks. Full diagram, static/dynamic rule, and
term defs live in docs/GLOSSARY.md §1–3 — single source.

Naming evidence: draft-01 uses CT 75×, "Capability Acquisition Token" 4×, bare
CAT 1×, CAP 0× → CT-centric, CAT acronym free → CAT = Compliance Attestation.

## H. Business / commercial layer (Part 2 — plain-language model)

"Verify once, prove everywhere." Actors: User · Platform · KYC provider · AI agent
· SPT-Txn as neutral infrastructure ("Visa/SWIFT for authorization"). Flow: KYC
issues CAT → platform ZK-checks CAT vs Policy → issues scoped CT (ms, no docs) →
agent gets a delegated CT (humanAnchor) → SPT-Txn per action → immutable audit
(Hedera HCS). Network effect compounds with each platform / KYC provider /
jurisdiction added.

Four revenue streams, all structured to avoid money transmission: (1) platform
subscription / per-verification; (2) AI-company per-agent-transaction (EU AI Act
Art. 14 forcing function, Aug 2026); (3) KYC-provider **network-access fee** (NOT a
revenue share — matches the legal fix); (4) Policy-NFT marketplace.
⚠️ Stream 4 fix: the 20–30% fee MUST be billed directly to the publisher
(listing/platform fee), never skimmed from a buyer→publisher payment routed
through SPT-Txn — otherwise it re-triggers the money-transmission / Howey flags
from the legal notes. Tighten the wording before it ships. Policy NFTs stay
utility-framed (never appreciating assets).

---

## I. Draft -02 §1.1 Terminology (ready to lift into the I-D)

Normative/informative references to import: [VC-DATA-MODEL] W3C VC Data Model 2.0 ·
[SD-JWT-VC] draft-ietf-oauth-sd-jwt-vc · [TXN-TOKENS] draft-ietf-oauth-transaction-tokens ·
[RFC9449] DPoP · [RFC9700] OAuth 2.0 Security BCP · [DID-CORE] W3C DID Core ·
[SP800-162] NIST ABAC · [SP800-207] NIST Zero Trust · [SP800-63] NIST Digital
Identity · [FIPS203] ML-KEM · [FIPS204] ML-DSA · [FATF-R16] FATF Rec 16 · [IVMS101].

Definitions (each anchored on first use):
- **Compliance Attestation Token (CAT):** a [VC-DATA-MODEL] Verifiable Credential
  profiled for compliance attributes, serialized as an [SD-JWT-VC] and bound to a
  zkDID. Issued by a KYC/compliance provider; held by the user and reusable.
- **Capability Token (CT):** a capability token (cf. object-capability security)
  conveying a scoped authorization. A root CT establishes maximum scope; delegated
  CTs are strict subsets with bounded delegation depth. Carries the humanAnchor.
- **SPT-Txn Token:** a [TXN-TOKENS] transaction token bound to a specific
  transaction context and sender-constrained per [RFC9449]; ~30 s TTL.
- **zkDID:** a zero-knowledge commitment to a [DID-CORE] DID (cf. anonymous
  credentials / BBS+) proving issuer-authorized attributes without revealing the DID.
- **humanAnchor:** a claim (`human_anchor`) carrying a zkDID commitment to the
  accountable human, propagated immutably across CT and SPT-Txn tokens.
- **Policy object:** the [SP800-162] ABAC policy a PDP evaluates; a Policy NFT is
  one on-chain instantiation (informative).

Also: §11 Algorithm Agility & PQ Migration cites [FIPS203]/[FIPS204]; map the
enforcement engine to [SP800-207] PE/PA/PEP and the identity flow to [SP800-63].

---

## Open inputs needed
- The 3 PDFs (framework v6, theory, theory-expanded) for the verbatim Policy-NFT
  text — drop into Downloads/this folder, or I extract via Chrome.
- Confirm there is genuinely no prior zkDNS writeup (then we author it fresh).
