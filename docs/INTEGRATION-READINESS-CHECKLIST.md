# Integration-readiness checklist (what an L1/L2 or VASP asks before integrating)

What a chain foundation or a regulated VASP will require before they interact
with or integrate SPT-Txn — and, honestly, **where SPT-Txn stands today**. Use it
two ways: as the diligence checklist to prepare for, and as a gap analysis that
shows what a design partner, an audit, and grant funding would close.

Status legend: **✅ have** · **◐ partial** · **○ planned / gap**.

## A. Vendor security & risk (the TPRM / security questionnaire)

| Item | Status | Notes |
|---|---|---|
| SOC 2 Type II report | ○ | Not done (POC, solo). The single most-requested artifact by regulated buyers; plan once revenue/partner justifies the audit. |
| ISO 27001 certification | ○ | Same — formal ISMS certification is a funded/maturity step. |
| Independent penetration test | ◐ | Host security-audit at **FAIL=0**, fuzzing (millions of execs, fails-closed), adversarial tests — but no third-party pen test yet. |
| Vulnerability & patch management | ◐ | CI (vet/build/test), dependency-light pure Go, OpenBSD syspatch; no formal SLA-tracked program. |
| Secure SDLC | ◐ | CI, tests, code + security reviews, threat model — not a documented, certified process. |
| SBOM / CBOM | ✅ / ◐ | CycloneDX **CBOM** published (`docs/cbom.json`); a full SBOM is trivial from Go modules (generate on request). |
| Incident response / BCP / DR | ○ | Not formalized (solo, one host) — tied to the scaling/multi-host roadmap. |
| Key management | ◐ | signify keys perms-controlled in the live deployment; **PKCS#11/HSM signing implemented & validated** (SoftHSM2, non-extractable Ed25519, issuer signing → `crypto.Signer`); live-service wiring + threshold/MPC pending (see `KEY-CUSTODY-PLAN.md`). |
| Encryption / FIPS 140-3 | ◐ | App crypto validated-capable via Go FIPS module; full-OS FIPS is a per-buyer Linux profile (see FIPS boundary §2a). |
| Data protection (GDPR / MiCA / DORA) | ◐ | **Strong by design** — no PII on-ledger, ZK disclosure, data-minimisation — but no formal DPA / privacy program yet. |

## B. Travel Rule / FATF interoperability (VASP-specific)

| Item | Status | Notes |
|---|---|---|
| IVMS101 data format | ✅ | Implemented (`internal/ivms101`). The dominant standard; table-stakes. |
| Protocol coverage (multi-protocol reality) | ◐ | **TRP live two-party**; TRISA bridge **designed** (`docs/TRP-TRISA-INTEROP.md`), not built; OpenVASP-aligned. 2026 reality = support a primary + a bridge for counterparty coverage. |
| KYC-capture-at-onboarding | ◐ (boundary) | The CAT issuer / KYC provider captures IVMS fields; SPT-Txn *carries* them. Flag to partners: the upstream KYC pipeline must capture the fields, or the message can't be filled. |
| Privacy-preserving disclosure | ✅ | SD-JWT selective disclosure + ZK predicates — discloses only the FATF-required set, amount hidden. A differentiator, not just parity. |
| Jurisdiction / sunrise handling | ○ | Depends on the integrating VASP's licensing; SPT-Txn is jurisdiction-agnostic and complements their program. |

## C. Technical integration (L1/L2 + VASP)

| Item | Status | Notes |
|---|---|---|
| Ledger adapter / binding | ✅ | One interface, **15 chains**, tested; chain-tagged, no cross-chain collision. |
| On-chain contracts | ◐ | Anchor + on-chain ZK verifier **live on testnets** (6 footprints); mainnet runbook ready, not deployed; independent contract audit pending. |
| Offline verifier as a library | ○ | The eight-step verifier exists; **packaging it as a standalone Go library** (the "embed, don't depend on our server" artifact) is the recommended next build. |
| API / documentation | ✅ | STATUS / RUNBOOK / DEMO / REVIEWER-BRIEF; live `/travel/health` + `/agent/health` endpoints; conformance vectors. |
| Uptime / SLA | ○ | One host today; scaling model defined (stateless replicas / library) but no SLA. |
| Observability | ○ | OTel / Prometheus / Grafana planned (PLATFORM doc) — needed once real consumers exist. |

## D. Cryptographic assurance

| Item | Status | Notes |
|---|---|---|
| Real ZK (not stubs) | ✅ | Groth16/BN254, Poseidon2; agentic chain proof with in-circuit issuer signatures (**F1 closed**). |
| Independent ZK + protocol audit | ○ | **The #1 ask for the trust core** — requested, not self-certified. Audit-prep spec ready (`docs/ZK-CIRCUIT-SPEC.md`). |
| Conformance vectors | ✅ | Deterministic per-chain context-hash + commitment vectors + CI drift-check (`cmd/conformance`). |
| Post-quantum plan | ✅ | Lifetime-triaged hybrid PQ migration plan + CBOM (EO-14409-aligned). |

## E. Legal & commercial

| Item | Status | Notes |
|---|---|---|
| Open-source license | ✅ | Apache-2.0 core — drives adoption and trust. |
| Legal entity | ✅ | Violet Sky Security SEZC (Cayman). |
| Liability / indemnification / MSA | ○ | No formal commercial terms yet — a contracting step at first paid engagement. |
| DPA / sub-processor list | ○ | Needed for any deployment touching counterparty data. |
| Sustainability model | ◐ | Articulated: managed Trust Registry + issuance/verification service on top of the OSS core. |

## Top gaps to close (priority order)

1. **Independent ZK-circuit + protocol audit** — the trust core; everything else
   is downstream of this for a security buyer. (Fundable; spec ready.)
2. **A design-partner pilot** — converts "POC" to "in use," and the pilot's own
   diligence tells you which of A–E to formalize first (don't pre-build SOC 2).
3. **Verifier as a standalone Go library** — the literal integration artifact for
   L1/L2/VASP, and it reinforces the offline/edge model.
4. **TRISA bridge + a second Travel Rule protocol** — multi-protocol counterparty
   coverage is a 2026 VASP expectation.
5. **Production key custody (HSM/KMS) + the scaling/multi-host split** — unlocks
   SLA, BCP/DR, and the security-questionnaire answers in section A.

**Honest framing for buyers:** SPT-Txn is strong exactly where it's hard to fake —
architecture, real ZK, privacy-preserving Travel Rule, multi-chain, open source —
and the open items are the *formal-assurance* layer (SOC 2, ISO, pen test,
independent audit, SLA) that a first partner + funding are meant to fund. State
both plainly; that honesty is itself a diligence signal.
