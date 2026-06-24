# Sovereign Policy Token Transactions (SPT-Txn): A Privacy-Preserving, Crypto-Agile Authorization Framework for Regulated and Agentic Systems

**Author:** Rudolf J. Coetzee · Violet Sky Security SEZC (Cayman Islands SEZC)
**ORCID:** 0009-0009-6557-8843
**Status:** Working paper / preprint (v2 draft), for deposit on **Zenodo**
(citable DOI; the project's existing preprints are 10.5281/zenodo.19299787 and
10.5281/zenodo.18917439). Companion to — and deliberately distinct in scope from —
the IETF Internet-Draft `draft-coetzee-oauth-spt-txn-tokens`.
**Date:** June 2026

> Scope & audience. This is the comprehensive **framework** paper (preprint /
> grant / NIST-engagement audience), not the IETF Internet-Draft. The I-D
> specifies only the transaction-token protocol; this paper covers the full
> architecture, the design alternatives considered, the cryptographic choices and
> their measured trade-offs, the post-quantum migration plan, and the
> regulatory/standards context. Coined terms are anchored to their base standards
> on first use (§10).

---

## Abstract

Every regulated interaction — opening an account, transacting a tokenised asset,
authorising an AI agent to act on a person's behalf — today requires identity and
eligibility to be re-verified from scratch, at every platform, at a cost of tens
of dollars and days of latency per check. The data exhaust of that model is a
standing breach liability, and it does not survive the move to autonomous agents,
where the accountable human dissolves within one or two delegation hops.

SPT-Txn is an authorization framework that verifies once and proves everywhere.
A user holds a **Compliance Attestation Token (CAT)** — a W3C Verifiable
Credential, issued by a regulated KYC/compliance provider, that binds
zero-knowledge-provable compliance attributes to a **zkDID** commitment. A
platform evaluates a zero-knowledge proof of the CAT against a representation-
agnostic **policy object** and, on a match, issues a scope-bounded **Capability
Token (CT)**; an AI agent receives a strictly attenuated, delegation-depth-bounded
CT carrying an immutable **humanAnchor** back to the accountable person. Each
action emits a transaction-bound **SPT-Txn token** (≈30 s lifetime,
sender-constrained per DPoP), and every step is recorded to a tamper-evident audit
trail. No personally identifiable information is transmitted or stored at the
verifying party; compliance is proven, not disclosed.

The framework is **blockchain-agnostic** (a ledger adapter; XRPL and others are
deployment targets, not dependencies), carries no native token, and is
**crypto-agile by design**: algorithm identifiers travel in every token and the
Trust Registry — not the token header — governs algorithm acceptance, enabling a
hybrid classical/post-quantum migration without a flag day. We report a working
reference implementation hardened on OpenBSD (pledge/unveil, privilege
separation), a live two-party FATF Travel Rule deployment carrying a payload-level
ZK attestation over the inter-VASP Travel Rule Protocol, measured cryptographic
benchmarks driving the primitive choices (Poseidon2 over MiMC; BN254 vs
BLS12-381; Groth16 vs PLONK), and a CycloneDX Cryptographic Bill of Materials
aligned to US Executive Order 14409 (2026).

---

## 1. Introduction

### 1.1 The problem

Three capabilities are each individually mature and collectively unintegrated:
attribute-based access control (ABAC) gives fine-grained, policy-driven
authorization but assumes a centralized, online policy decision point;
self-sovereign identity (SSI) and Verifiable Credentials give user-controlled,
privacy-preserving identity but no on-line policy enforcement and no transaction
binding; and capability/transaction tokens (object-capability security, the OAuth
Transaction Tokens work) give scoped, delegable authority but carry no identity
provenance and no compliance semantics. No deployed system composes them into a
single chain that is simultaneously privacy-preserving, regulator-satisfying,
offline-verifiable, and accountable across organisational and agentic boundaries.

The cost of that gap is concrete. Repeated KYC/AML verification is a multi-billion
dollar annual tax with onboarding abandonment rates that platforms quantify in the
tens of percent. The PII accumulated to satisfy it is a perpetual breach surface.
And the model fails outright for the agentic economy: when an AI agent transacts
on a human's behalf, neither regulators nor counterparties can reconstruct who
authorised what — a direct obstacle to obligations such as EU AI Act Article 14
(effective human oversight), enforceable from August 2026.

A fourth pressure is now statutory. US Executive Order 14409, *Securing the Nation
Against Advanced Cryptographic Attacks* (2026-06-22), mandates federal migration to
post-quantum cryptography (NIST FIPS 203/204/205), sets contractor deadlines
(2030/2031), and directs CISA and NIST to publish Cryptographic Bill of Materials
(CBOM) guidance within 270 days. Any authorization infrastructure built today must
be crypto-agile and inventory-able by construction.

### 1.2 Contributions

This paper makes the following contributions:

1. **A composed token chain** — CAT (compliance attestation) → CT (capability) →
   SPT-Txn (transaction) — that unifies SSI credentials, ABAC policy evaluation,
   and capability/transaction tokens, with an explicit ABAC→TBAC boundary: policy
   is evaluated **once** at issuance; thereafter every token is enforced
   cryptographically with no policy engine consulted (offline-verifiable).
2. **The CAT + attribute model** (§2.3): a precise account of where compliance
   attributes live (proven into the CAT, never disclosed), including a **static /
   dynamic guardrail** that prevents stale-compliance authorization for volatile
   attributes (AML-risk, sanctions).
3. **An immutable humanAnchor** — a zkDID commitment propagated unchanged across
   the chain — giving Sybil-resistant, privacy-preserving human accountability for
   agentic action (EU AI Act Art. 14).
4. **zkDID and zkDNS** (§3, §4): zero-knowledge identity that breaks the
   cross-verification correlation attack, and a two-layer naming/discovery design
   (decentralized name→key binding; private resolution) analysed against
   centralized DNS, DNSSEC, ENS, and Handshake.
5. **A measured cryptographic design** (§5): empirical benchmarks on the reference
   host driving the choices (Poseidon2 vs MiMC; BN254 vs BLS12-381; Groth16 vs
   PLONK), a lifetime-triaged **hybrid post-quantum migration** plan, and a
   CycloneDX CBOM aligned to EO 14409.
6. **A working, hardened reference implementation** with a live, two-party
   privacy-preserving FATF Travel Rule deployment (IVMS101 + SD-JWT + ZK over the
   OpenVASP Travel Rule Protocol), security-audited on OpenBSD.

### 1.3 What this paper is not

It is not the protocol specification (that is the IETF I-D). It does not claim
post-quantum security today — it claims a defined, measured migration path. It
treats on-chain instantiations (e.g. a policy expressed as an NFT) as
**informative** deployment options, never as normative or as tradeable assets, to
remain clear of securities and money-transmission classification (§9).

---

## 2. Architecture and the token chain

### 2.1 Actors

Five roles: the **user** (a person, or an AI agent acting for one); the
**KYC/compliance provider** (a regulated issuer of CATs); the **platform** (bank,
exchange, RWA venue, AI operator — the relying party and CT issuer); the **Trust
Registry** (the authority on which issuers and algorithms are accepted); and
**SPT-Txn** as neutral infrastructure in the middle. No party holds the user's PII
except the issuing KYC provider, under a lawful-access escrow (§5, §9).

### 2.2 The three tokens (locked vocabulary)

- **CAT — Compliance Attestation Token.** A W3C Verifiable Credential
  [VC-DATA-MODEL], serialized as an SD-JWT VC [SD-JWT-VC], issued once by a KYC
  provider after verifying the user's attributes, bound to the user's zkDID. The
  user holds it and reuses it across platforms with no document re-submission.
- **CT — Capability Token.** A capability token (object-capability lineage; the
  draft's primary primitive) conveying a scope-bounded authorization, issued by a
  platform when a zero-knowledge proof of the CAT satisfies the platform's policy.
  A *root* CT sets the maximum scope; *delegated* CTs (e.g. to an agent) are strict
  subsets with bounded delegation depth, carrying the humanAnchor forward.
- **SPT-Txn token.** A transaction token [TXN-TOKENS] bound to one transaction
  context and sender-constrained per DPoP [RFC9449], ≈30 s lifetime, carrying the
  Travel Rule attestation where applicable. The token actually presented at the
  resource.

### 2.3 The CAT + attribute model

Attributes are **inputs to** the CAT, not its contents. KYC level, jurisdiction,
and accredited/eligibility status (durable) are verified once and bound at CAT
issuance; AML-risk and sanctions status (volatile) are sourced from a DID-anchored
attribute oracle. The CAT carries *selectively-disclosable compliance claims and
proofs that policy is satisfied — never the raw values*.

**Static / dynamic guardrail.** Durable attributes are bound at CAT issuance.
Volatile attributes MUST NOT be frozen into the long-lived CAT; they are re-proven
at CT issuance and again at SPT-Txn minting against the oracle's committed state,
under a policy maximum-proof-age. This yields real-time revocation by updating the
feed without revoking the credential, and closes the stale-compliance hole (a
now-sanctioned party holding a still-valid capability).

The flow: KYC issues the CAT → the platform's PDP evaluates a ZK proof of the CAT
against a composable, jurisdiction-aware **policy object** (the ABAC→TBAC
boundary) → a scope-bounded CT is issued in milliseconds → an agent receives a
delegated CT carrying the humanAnchor → each action emits an SPT-Txn token → all
recorded to a tamper-evident audit trail. (Full diagram and term definitions:
`docs/GLOSSARY.md`.)

### 2.4 Deployment targets (blockchain-agnostic)

The framework binds no logic to a specific ledger; a ledger adapter abstracts the
anchoring of attestations, audit roots, and registry state, so a chain is a
*target*, never a dependency. Deployment targets include the **XRP Ledger
(XRPL)** — the primary integration and grant target, where SPT-Txn complements
XRPL's on-ledger Credentials/DID with this off-ledger privacy and FATF Travel Rule
layer and anchors audit roots to the ledger — alongside EVM-compatible chains,
**Hedera** (Consensus Service for the tamper-evident audit trail), XDC (RWA and
trade finance), Algorand, and Substrate parachains. No native token is introduced
on any of them; the framework's revenue and trust models do not depend on one.

---

## 3. zkDID — zero-knowledge decentralized identity

### 3.1 The correlation problem

A conventional Decentralized Identifier [DID-CORE] is revealed during
presentation: even when attributes are proven in zero knowledge, the verifier
learns *which DID* is asserting them. That identifier is a correlation handle — it
links a subject's activity across verifications, platforms, and time, reconstituting
the surveillance surface that selective disclosure was meant to remove. For a
system that must satisfy data-minimisation duties (e.g. GDPR) while proving
regulated facts, a stable, linkable identifier in every interaction is a liability.

### 3.2 The interim construction

SPT-Txn's interim zkDID, implemented in the reference POC, is a hiding-and-binding
commitment used as the **humanAnchor**:

    humanAnchor = H(identity_material, randomness)   over BN254

where H is the shared ZK-friendly hash (§5.2, Poseidon2), computed natively and
proven in-circuit by the *same* function — so the token's humanAnchor is exactly
the value a holder proves knowledge of, not a separate digest. **Fresh randomness
is drawn per CAT issuance**, so a subject's commitments are unlinkable across
tokens; the commitment circuit proves knowledge of `(identity_material,
randomness)` behind the public anchor without revealing either. This is the
algebraic-commitment / anonymous-credential lineage (Pedersen commitments; BBS+;
AnonCreds; zk-cred constructions), specialised to a single accountable-human anchor
that propagates immutably from CAT through CT to SPT-Txn. The interim is
self-sufficient — it delivers the essential privacy property using only the
project's own primitives, with no external dependency — though in the POC the
identity material is a deterministic test principal; production binds it to a
verified biometric uniqueness proof (§3.5).

### 3.3 Identity-method-agnostic: the adapter and the .zkdid production layer

What the interim does *not* provide is the full DID-method apparatus: a
`did:zkdid:` identifier, document, and resolution; issuer-authorised binding as a
method (in the POC this is handled separately by the Trust Registry, §7); and a
governed naming layer. These are supplied in production by **Toby Bolton's
`.zkdid` / `.zkdns` infrastructure**, the intended zero-knowledge identity and
naming provider, with which SPT-Txn integrates.

Crucially, SPT-Txn treats zkDID as an **interface** — `commit → prove → verify →
bind` — not a hard dependency. The interim commitment is one implementation of that
interface; `.zkdid` is the production implementation, adopted behind the same
interface with no change to the token chain. SPT-Txn is therefore
**identity-method-agnostic**, completing a consistent design discipline across
three axes: *ledger* (blockchain-agnostic; XRPL a target, not a dependency),
*policy representation* (the representation-agnostic policy object), and *identity
method* (zkDID behind an adapter). The framework runs today on its interim and
upgrades to `.zkdid`/`.zkdns` when that infrastructure is production-ready — a
forward-compatibility guarantee, not a blocking dependency.

### 3.4 The revised trust geometry

zkDID relocates where trust sits. The root of trust remains the **regulated
issuer** (a KYC/compliance provider certified by a regulatory trust registry, §7),
but the issuer's *accountability* is decoupled from the subject's *traceability*: a
regulator can audit the issuer; the issuer cannot surveil the user's downstream
access; a verifier cannot correlate a subject across sessions. Lawful
re-identification remains possible — but only via the escrow path (§5.5), under
quorum/lawful process, never from the on-the-wire data.

### 3.5 Hard problems (stated, not waved away)

- **Sybil resistance** requires proving *one human → one anchor* without revealing
  the human — a **biometric uniqueness** layer: a fuzzy extractor yielding a stable
  secret from noisy biometrics, plus a nullifier for global one-enrolment-per-
  person, inside a secure enclave with attested liveness (never biometric hashes
  on-chain). The POC uses a placeholder; this is a first-class part of the `.zkdid`
  integration.
- **Issuer coercion.** ZK cannot protect against a compromised or coerced issuer
  fabricating credentials; high-stakes attributes need multi-issuer attestation and
  governance, not cryptography alone.
- **Proof freshness.** A proof over committed state carries a timestamp; the policy
  enforces a maximum proof age (§2.3), implying a subject liveness requirement.
- **Proof-system soundness.** Integrity rests on the proving system and its
  parameters; production requires audited circuits and a sound or transparent setup
  (§5.4).

## 4. zkDNS — naming and discovery, and the alternatives

### 4.1 The problem

Inter-VASP and agent-to-agent authorization needs a way to discover a
counterparty and bind its **name → public key / service endpoint** with integrity,
and to do so without (a) depending on a single seizable/censorable root and (b)
leaking who is querying whom. The FATF Travel Rule ecosystem currently solves
discovery with sender-provided addresses (the OpenVASP *Travel Address*) or a
centralized directory (TRISA's Global Directory Service, GDS). Both reintroduce a
trust chokepoint and offer no query privacy. zkDNS is the design we propose to
close that gap; it is evaluated below against the established options.

### 4.2 Alternatives considered

**Centralized DNS + the ICANN root.** Ubiquitous and operationally mature, but the
root zone is a single governance and seizure point, and classic DNS provides
neither integrity nor confidentiality. Unsuitable as a trust anchor for
adversarial, cross-jurisdictional compliance traffic.

**DNSSEC.** Adds origin authentication and integrity via a hierarchical chain of
trust to the (still ICANN-governed) root, and DANE/TLSA can bind a key to a name.
But DNSSEC provides **no confidentiality** — queries and responses travel in the
clear — and inherits the centralized root and CA-like operational complexity.
zkDNS *complements* DNSSEC (a DNSSEC bridge is possible) rather than discarding it.

**ENS.** Decentralized name resolution on Ethereum; bridges existing DNS names via
a DNSSEC `_ens` record. Excellent for Web3 addressing, but general-purpose, **not
zero-knowledge** (registrations and resolutions are public on-chain — a
correlation surface), and not scoped to compliance/VASP discovery.

**Handshake.** Replaces the ICANN root zone with a blockchain-governed root and a
decentralized trust anchor — a genuine CA/root alternative. But it is a
general-purpose TLD system, not ZK, and not a name→key binding for a curated
compliance/VASP set. **Namecoin** (`.bit`) was the first such system and is now
throughput- and feature-limited. ICANN's OCTO-034 documents the real hazards of
alternative name systems (namespace collision, resolution ambiguity); we
acknowledge these and scope zkDNS narrowly to avoid them (it is not a public TLD).

### 4.3 zkDNS Layer 1 — decentralized name→key discovery

zkDNS L1 is **not** a general naming system. It is a name→key/endpoint binding over
a **decentralized, committed trust registry** of VASPs/agents (the same
Merkle-committed, signed-root structure used for VASP membership in §6): a party
proves in zero knowledge that a counterparty name is **registered and its key
binding is valid, without revealing the namespace or which entry** it matched.
This replaces the Travel Address / GDS chokepoint with a neutral,
capture-resistant root, and complements DNSSEC where a DNSSEC bridge is desired.
One line: *Handshake decentralizes the root; ENS resolves Web3 names; zkDNS adds ZK
membership proofs over a compliance/VASP trust registry.*

### 4.4 zkDNS Layer 2 — private resolution

Even with a decentralized binding, *who resolves what* leaks a behavioural graph
(which VASP is screening which counterparty, when). zkDNS L2 combines two
established techniques: **ODoH** (Oblivious DNS-over-HTTPS, RFC 9230) proxy/target
separation, so no single server learns both the querier's identity and the query;
and a **DECO-style** zero-knowledge lookup against the registry/oracle's
**committed state**, so a resolver proves a `name → key` (and live attribute)
result without revealing the query. This is the same "blind query against
committed state" primitive used for the dynamic attribute oracle (§5), unifying
discovery privacy and attribute privacy under one construction.

The constructions in §4.3–§4.4 specify the *properties* SPT-Txn requires of a
naming/resolution layer. In production these are provided by **Toby Bolton's
`.zkdns` infrastructure** (the companion to `.zkdid`, §3.3), integrated behind the
same adapter; SPT-Txn's interim VASP-registry membership proofs satisfy the L1
binding today, so the framework is not blocked on the external layer.

### 4.5 Threat model and open problems

The committed set's authority must itself be bootstrapped (who may add a VASP) —
addressed by the regulatory trust-registry governance of §7; namespace collision
is avoided by scoping (no public TLDs); liveness and freshness of the committed
root require periodic signed publication; and the privacy of L2 degrades if the
proxy and target collude. These are stated as limitations, not solved by fiat.

## 5. Cryptographic design, measured

Cryptographic choices here are **benchmarked on the reference host, not assumed.**

### 5.1 Circuits and commitments

Three Groth16 predicate circuits prove compliance facts while revealing nothing
about the underlying data: an **identity-commitment** circuit (the holder knows the
material behind the humanAnchor), a **threshold** circuit (a committed amount is at
or above the FATF reporting threshold, amount hidden, range-checked to 64 bits),
and a **VASP-membership** circuit (a counterparty is in the committed registry,
which member hidden, via a Merkle authentication path). The native commitment hash
and the in-circuit gadget are the *same function by construction* — so the token's
humanAnchor equals the zero-knowledge-proven commitment, end to end.

### 5.2 ZK-friendly hash: MiMC → Poseidon2

The commitment/Merkle hash is the dominant circuit cost. We migrated from MiMC to
**Poseidon2** and measured the effect on the reference host (gnark v0.15, Groth16):

| Hash | Curve | Constraints | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|---|
| MiMC | BN254 | 42,241 | 1m57s | 11.46 s | 14.7 ms | 164 B |
| **Poseidon2** | **BN254** | **23,809** | **1m05s** | **6.79 s** | 14.0 ms | 164 B |
| MiMC | BLS12-381 | 42,625 | 3m42s | 21.03 s | 18.9 ms | 244 B |
| Poseidon2 | BLS12-381 | 23,809 | 1m59s | 11.89 s | 18.5 ms | 244 B |

*(64-hash stress circuit, chosen to amplify the hash cost; production circuits are
661–5,305 constraints.)* Poseidon2 is an unambiguous win — **−44 % constraints,
−41 % prove, −44 % setup** vs MiMC, with identical proof size and verify. The
production VASP circuit fell 5,305 → 3,001 constraints on migration. Poseidon2 is
adopted; MiMC is the documented prior interim.

### 5.3 Elliptic curve: BN254 vs BLS12-381

The same benchmark quantifies the curve trade-off: **BLS12-381** (~128-bit margin)
costs roughly **2× the prove and setup time and +49 % proof size (164 → 244 B)**
versus **BN254** (~100-bit margin), with ~25 % slower verify. Because SPT-Txn
proofs are **ephemeral** — verified once and discarded within the 30-second token
lifetime — a ~100-bit *classical* attack on a proof whose value has already expired
is not a realistic threat, and BN254 additionally offers EVM precompile
compatibility. We therefore default to **BN254**, exposing **BLS12-381 as a
configurable high-assurance option**. Both are pairing curves and **neither is
post-quantum** (§5.6); the curve choice is a classical-margin/performance
trade-off, not a quantum one.

### 5.4 Proving system: Groth16 vs PLONK

Groth16 gives the smallest, constant-size proofs (3 group elements) and fastest
verify, at the cost of a **per-circuit trusted setup** — itself a trust assumption
and an operational burden (the benchmark's 1–4 minute setups are per circuit).
gnark also supports **PLONK**, whose universal/updatable setup amortises one
ceremony across all circuits, reducing the trusted-setup attack surface without
leaving the toolchain. We retain Groth16 for the POC (smallest proofs, mature) and
document PLONK as the migration lever when reducing trusted-setup risk outweighs
proof-size; this is independent of the post-quantum question.

### 5.5 Selective disclosure and escrow

Compliance claims are carried in an **SD-JWT** (selective disclosure): a surname can
be revealed to a regulator while the given name, amount, and other fields stay
hidden, each disclosed or withheld independently. The lawful-access **escrow**
envelope (deanonymization under quorum/lawful process only) currently uses
X25519/ECIES; its migration target is ML-KEM-768 (§5.6).

### 5.6 Post-quantum migration (triaged by lifetime)

NIST finalised the PQC suite in 2024 — **FIPS 203 ML-KEM**, **FIPS 204 ML-DSA**,
**FIPS 205 SLH-DSA** — and the accepted transition is **hybrid** (classical ∥ PQC,
secure if either holds). US Executive Order 14409 (2026-06-22) makes this a
deadline-bearing federal mandate (sensitive-system encryption by 2030, PQ
authentication by 2031, contractor FIPS by 2030) and directs CBOM guidance.

We triage by **data lifetime**, because a future quantum adversary cannot
retroactively forge a proof or token whose value already expired:

- **High priority — long-lived / retained.** Ed25519 on the **CAT**,
  **registry/trust-anchor roots**, and the **audit log**; X25519/ECIES on the
  **escrow** (5–7 yr retention; classic harvest-now-decrypt-later). Migrate to
  **hybrid Ed25519 + ML-DSA-65** and **hybrid X25519 + ML-KEM-768**.
- **Low priority — ephemeral.** Ed25519 on the **30-second SPT-Txn token** and the
  **Groth16 proofs** — migrate later.
- **PQ-OK already.** AES-256-GCM (NIST level 1); Poseidon2/SHA-256 (Grover-only).

Migration is enabled by **crypto-agility**: algorithm identifiers travel in every
token/attestation, and the Trust Registry — not the token header — governs which
algorithm a verifier accepts (downgrade-resistant), so a hybrid suite rolls
per-issuer without a flag day. The MiMC → Poseidon2 migration (§5.2) is the
proof-of-concept: a two-file, matched native/in-circuit change.

**PQ-ZK is a roadmap, scoped honestly.** Groth16/BN254 is pairing-based and **not
post-quantum**. Transparent, post-quantum proving exists — STARKs (hash-based, no
trusted setup) and lattice SNARKs (LaBRADOR, Greyhound) — but in different
toolchains, with larger proofs and far less audit history. Because the proofs are
ephemeral, migrating now would trade a fast, well-audited system for an immature
one to defend a threat the proofs do not face. We therefore state explicit
**migration triggers** (proofs requiring long-term retention; maturation and audit
of a PQ-ZK stack; regulatory requirement) rather than a premature rip-and-replace.

### 5.7 Cryptographic Bill of Materials

The full inventory — every primitive, where used, classical/quantum status, and
migration target — is published as a **CycloneDX 1.6 CBOM** (`docs/cbom.json`,
human-readable `docs/CBOM.md`), aligned to EO 14409's CBOM mandate. It is a
*have-and-provide* artifact: available to partners and reviewers on request rather
than broadcast (§disclosure-posture), since for an open-source system it reveals
nothing the source does not, but the commercial posture keeps the public surface
to a one-line attestation.

## 6. Privacy-preserving FATF Travel Rule (deployed)

*(to be drafted: IVMS101 data model; the three ZK predicates bound to the payment;*
*two-VASP verify-only topology; TRP transport carrying the payload-level*
*attestation; cleartext-refusal policy; TRISA bridge design; live deployment.)*

## 7. Security and threat model

*(to be drafted, per layer: token/chain, attribute oracle, escrow, zkDNS;*
*OpenBSD hardening — pledge/unveil, privsep, relayd, signify; trust-registry*
*persistence finding; trusted-setup risk; assumptions.)*

## 8. Related work and differentiation

*(to be drafted: vs DNA Protocol and XRPL ZK-identity — no token, no new chain,*
*compliance-first; vs git-id (MyNextID) — complementary (who the agent is vs what*
*it may do); SSI/VC, soulbound tokens, anonymous credentials; NIST alignment —*
*IR 8587, SP 800-207/204/63/162; the honest PQ posture vs "quantum-ready" claims.)*

## 9. Regulatory and legal posture

*(to be drafted, informative: utility framing (Howey); authorization-layer-only,*
*"do not touch the money" (money transmission); VASP/CIMA, MiCA; EU AI Act Art.*
*14; not legal advice.)*

## 10. Terminology and standards mapping

*(to be drafted from docs/GLOSSARY.md §4: every coined term → base standard, with*
*the anchor-on-first-use rule; VC-DATA-MODEL, SD-JWT-VC, TXN-TOKENS, RFC 9449,*
*RFC 9700, DID-CORE, SP 800-162/207/63, FIPS 203/204, FATF R.16, IVMS101.)*

## 11. Conclusion and roadmap

*(to be drafted.)*

## References

*(to be compiled.)*
