# XRPL Grants Application — SPT-Txn: A Privacy-Preserving Compliance & Travel Rule Rail for XRPL

**Applicant:** Rudolf J. Coetzee — Violet Sky Security SEZC (Cayman Islands SEZC)
**Contact:** rudizee@secbsd.org · ORCID 0009-0009-6557-8843
**Program:** XRPL Grants (rolling) — also for consideration: XRPL Accelerator, AI Fund
**Ask:** USD 190,000 over 12 months (milestone-based)
**Code (mandatory technical review):** https://github.com/rudizee007/SPT-TXN-POC
**Live demo:** https://foss.violetskysecurity.com (Travel Rule API: `:4445/travel/health`)
**Technical paper / theory:** Zenodo DOIs 10.5281/zenodo.19299787, .18917439; IETF
draft-coetzee-oauth-spt-txn-tokens; framework working paper (this repo, `docs/`).

---

## One-liner

SPT-Txn is the privacy-preserving **FATF Travel Rule and compliance-authorization
rail** that lets regulated institutions and VASPs transact, tokenise, and settle on
the XRP Ledger — proving compliance in zero knowledge instead of exposing PII —
complementing XRPL Credentials and removing the single biggest barrier to
institutional on-chain volume.

## The problem (why on-chain finance stalls at the compliance wall)

Regulated payments, stablecoin settlement, and real-world-asset (RWA) tokenisation
are exactly the financial activity XRPL wants on-ledger — and exactly the activity
that compliance blocks today. Every counterparty must re-verify identity and
eligibility from scratch (US$20–60 per check, days of latency, high onboarding
abandonment), the FATF Travel Rule (Recommendation 16) requires originator/
beneficiary data to move between VASPs, and the prevailing solutions ship that PII
in cleartext — a standing breach liability and a regulatory contradiction with data
minimisation (GDPR, MiCA). The result: institutions stay off-ledger, and on-chain
volume that depends on them never materialises.

## The solution

SPT-Txn verifies once and proves everywhere. A user holds a **Compliance
Attestation Token (CAT)** — a W3C Verifiable Credential issued by a regulated KYC
provider, bound to a zero-knowledge identity commitment (**zkDID / humanAnchor**).
A platform checks a zero-knowledge proof of the CAT against a policy and issues a
scope-bounded **Capability Token (CT)**; each transaction emits a transaction-bound
**SPT-Txn token**. For inter-VASP transfers, SPT-Txn carries a **payload-level ZK
Travel Rule attestation** (IVMS101 + selective-disclosure SD-JWT + three Groth16
predicates: identity, amount-over-threshold, VASP-membership) over the OpenVASP
Travel Rule Protocol — so a counterparty proves a transfer is reportable, between
registered VASPs, with an authenticated identity, **without transmitting the PII or
the amount**. No native token; the framework is blockchain-agnostic, with XRPL as
the primary target and integration.

## Why XRPL, and why now

- **Direct fit to Payments & FX + tokenisation:** SPT-Txn is the compliance layer
  beneath cross-border payments, stablecoin rails, and RWA on XRPL — it *unlocks*
  the regulated volume these use-cases need.
- **Complements XRPL Credentials:** XRPL's on-ledger Credentials/DID provide the
  anchor; SPT-Txn adds the off-ledger privacy + Travel Rule + per-transaction
  authorization layer on top, anchoring attestations and audit roots to XRPL.
- **Policy tailwind:** US Executive Order 14409 (June 2026) mandates post-quantum
  migration and Cryptographic Bills of Materials; SPT-Txn is crypto-agile by design
  and already ships a CycloneDX CBOM — positioning XRPL-built compliance infra ahead
  of the regulatory curve.

## Current status — a working, security-audited MVP (we exceed the bar)

This is not a concept. The reference implementation is **deployed and running** on a
hardened OpenBSD host:

- **Live two-party Travel Rule** — separate originator and beneficiary VASP services
  exchange a ZK attestation over a real TRP network hop; the beneficiary (holding
  only the verifying key) approves, disclosing surname + currency, never the amount.
- **Real zero-knowledge** — Groth16/BN254 circuits (not stubs); **Poseidon2**
  migration benchmarked on-host (−44% constraints, −41% prove vs MiMC).
- **Security by design** — OpenBSD pledge/unveil sandboxing, privilege separation,
  relayd TLS, signify keys; a host-runnable security audit at **FAIL=0**.
- **EO-14409-ready** — a published CycloneDX CBOM and a lifetime-triaged hybrid
  post-quantum migration plan.
- **Open source + standards** — public GitHub repo; an IETF Internet-Draft and two
  Zenodo preprints; terminology anchored to W3C VC/DID, SD-JWT, OAuth Transaction
  Tokens, NIST SP 800-207/162, FIPS 203/204, FATF R.16/IVMS101.

## What the grant funds (making it XRPL-native and production-grade)

| # | Milestone | Deliverable | ~Months | Tranche |
|---|---|---|---|---|
| M1 | **XRPL anchoring** | Ledger adapter integrated with XRPL; attestation + audit-root anchoring on XRPL Testnet; reproducible demo | 1–2 | $20k |
| M2 | **XRPL Credentials interop** | CAT/zkDID bound to XRPL Credentials; compliant onboarding flow end-to-end on XRPL | 2–4 | $24k |
| M3 | **Production-harden Travel Rule** | Persistent Trust Registry (closes a known POC gap), multi-VASP support, TRISA bridge, containerised Linux deployment target, monitoring | 3–5 | $24k |
| M4 | **Biometric uniqueness / Sybil resistance** | Fuzzy-extractor + nullifier + secure-enclave liveness replacing the interim test principal | 5–7 | $26k |
| M5 | **Post-quantum hybrid** | Hybrid Ed25519+ML-DSA and X25519+ML-KEM on long-lived keys; CBOM updated | 6–8 | $22k |
| M6 | **zkDID/zkDNS integration** | Adopt `.zkdid`/`.zkdns` (Toby Bolton) behind the existing adapter when available; otherwise harden interim | 7–9 | $16k |
| M7 | **Agentic authorization (build + test)** | End-to-end AI-agent delegated-CT flow with humanAnchor accountability, *tested* (currently designed, not yet tested) | 8–10 | $22k |
| M8 | **Independent ZK-circuit + protocol audit, multi-VASP pilot, docs** | Independent audit of the ZK circuits and protocol by a reputable firm (Veridise/Zellic/Trail of Bits-class); compliance pilot with ≥2 counterparties on XRPL; public audit report; full documentation | 10–12 | $36k |
|   |   |   |   | **$190k** |

## Budget summary (USD 190,000 / 12 months)

- Engineering incl. ZK-circuit work (lead developer — applicant): ~$130k
- **Independent ZK-circuit + protocol audit** (reputable firm; M8): ~$45k
- Infrastructure (XRPL testnet/mainnet ops, hosting, CI/tooling): ~$8k
- Pilot integration support (≥2 counterparties): ~$7k

## Team

**Rudolf J. Coetzee** — founder, Violet Sky Security SEZC; cybersecurity and
secure-systems background (CISO-level advisory, OpenBSD-hardened deployments);
author of the SPT-Txn IETF Internet-Draft and the companion cryptographic theory
preprints; sole developer of the reference implementation. (At least one developer
on the core team — met.) Collaboration with **Toby Bolton** (`.zkdid`/`.zkdns`) on
the production zero-knowledge identity/naming layer.

## Roadmap honesty & risk

- **Agentic AI authorization is designed but not yet tested** — the humanAnchor,
  delegation-depth bounds, and scope attenuation are built into the token model;
  M7 builds and *tests* the end-to-end agent flow. We state this plainly.
- **External dependencies are de-risked by design.** SPT-Txn is agnostic across
  ledger, policy representation, and identity method (each behind an adapter). It
  runs today on its own interim zkDID and VASP registry; `.zkdid`/`.zkdns` and XRPL
  Credentials are integrations that *enhance* it, not prerequisites — so no
  milestone is hostage to a third party's timeline.

## Links

- Code (technical review): https://github.com/rudizee007/SPT-TXN-POC
- Live demo: https://foss.violetskysecurity.com
- Working paper + glossary + CBOM: this repo, `docs/`
- IETF draft: datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens
- Preprints: Zenodo 10.5281/zenodo.19299787, 10.5281/zenodo.18917439
