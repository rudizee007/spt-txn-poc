# SPT-Txn Roadmap

**Repository visibility: PUBLIC.** Written to be read by contributors, standards participants, and prospective partners.

---

## The Thesis

Federal and enterprise security demand is converging on a single missing primitive. Six structural patterns — visible in US federal RFIs, NIST/CAISI standards work, CISA directives, and the EU regulatory stack (DORA, NIS2, CRA, MiCA) — all resolve to the same requirement:

> *A policy enforcement point that sits inline, evaluates a request against jurisdiction- and context-aware policy, permits or denies, and emits tamper-evident evidence.*

Government calls it an AI gateway or an identity-aware proxy. Fintech calls it a transaction authorization layer. It is the same box. SPT-Txn is the token and policy primitive that makes it work.

**Standards position is the asset.** NIST/CAISI launched the AI Agent Standards Initiative in February 2026; NCCoE is scoping AI agent identity and authorization; the pattern is well established that NIST guidance becomes procurement requirement within 12–18 months, and then becomes the international baseline. Whoever's construct lands in the reference architecture wins the enterprise market by default. **Spec text in the right body outvalues implementation polish. When they compete for time, spec wins.**

---

## Priority Order

### P1 — Agentic delegation, intent binding, MCP PEP profile
**Hardest deadline. Highest strategic value. If anything slips to protect this, let it slip.**

Three constructs:

**Delegation chains with offline attenuation.** Each hop appends a cryptographically sealed caveat that can only narrow scope, verifiable offline. TTL decays monotonically. Chain depth bounded. Revocation via short-lived parent plus status-list check.

**Intent binding.** The token embeds a hash of the *declared action* — tool/method identifier, canonicalized parameter digest, target resource. The PEP verifies the *actual* call against the bound intent. **An agent whose reasoning is hijacked mid-task holds a token that is cryptographically useless for the hijacked action.** This is the direct answer to OWASP ASI01 goal hijacking and to the NIST RFI's stated concern about "cross-system calls without proper authorization chains."

**MCP PEP profile.** Reference middleware: every tool invocation requires a valid SPT-Txn token whose intent binding matches. The server never sees or forwards upstream credentials — this closes the token-passthrough gap. Each invocation emits a receipt; chained per task, these *are* the full decision-chain audit record that NIST language demands. **P1 + P2 together produce the agent audit trail as a free byproduct.**

*Why this is the differentiator:* everyone else scopes agents by **role** ("this agent may use the payments tool"). We scope by **transaction** ("this agent may execute this specific transfer it declared 400ms ago"). Role scoping fails exactly when agents fail — under manipulation. Transaction scoping does not care why the agent changed its mind.

Roughly 40% of this is spec text — which is precisely the artifact the standards window rewards. **The spec can land in NCCoE/IETF before the code is production-grade.** Sequence accordingly.

### P2 — Compliance receipts and transparency log
**Fastest path to revenue.**

The **Transaction Receipt**: a compact signed record emitted at decision time — token hash, policy bundle version hash, decision plus the rule path that fired, jurisdiction profile applied, timestamp, issuer/PEP identity. Appended to a Merkle transparency log (Certificate-Transparency / Rekor design lineage): append-only, signed tree heads, external witness co-signing. Anyone holding a receipt can prove inclusion; nobody — including the operator — can silently rewrite history.

A thin export layer sits on top: a verifier CLI and a mapping from receipt fields to control frameworks.

*Why it wins:* nobody in the GRC market can say **"this control was enforced at the moment of this specific transaction, and here is a cryptographic proof."** Everyone else screenshots dashboards quarterly. This inverts the audit — instead of *sampling* controls, the auditor *verifies a chain*.

**We do not build a GRC platform.** We export to the tools customers already have. Resist all scope creep here.

### P3 — Gateway form factor
**The adoption multiplier. No adoption, no standards story.**

Three thin skins over one decision core:
- **Envoy `ext_authz` filter** — covers Istio, service mesh, and most API gateways by extension
- **OPA-compatible decision API** — accept the input shape OPA integrations already send, answer in the shape they expect, so **every existing OPA integration point becomes an SPT-Txn integration point for free.** This converts an incumbent's install base into our distribution channel.
- **MCP middleware** — same core, agent-shaped socket (shared with P1)

Skins are stateless, hold no keys, contain no decision logic. A compromised skin can deny service; it cannot mint authority.

**Deployable in an afternoon by someone else's platform team, or it does not count.**

### P4 — NHI attested issuance
**Acquisition-critical.**

Ingress federation on the issuer: SPIFFE SVIDs (X.509 and JWT), cloud workload identity federation (AWS IRSA, GCP workload identity, Azure federated credentials), Kubernetes service-account tokens — profiled as an **RFC 8693 token exchange**. Workload presents attested identity, receives a transaction-scoped token narrowed to one action. The attestation evidence hash is sealed into the issued token, so a downstream verifier checks not only *who* but *on what attested substrate*.

Optional attestation-freshness predicates: *"payments above threshold T require attestation newer than 60 seconds."*

*Why it matters strategically:* the market's NHI tools **inventory secrets**; SPIFFE gives workloads **names**. Nobody closes the last mile — **per-action authorization conditioned on attestation state.** This is also what makes an identity vendor (Okta, Ping, CyberArk, Aembit) conclude *"plugs into us"* rather than *"competes with us."* That distinction is worth a great deal in an acquisition conversation.

### P5 — [Reserved]
*Deferred. Not tracked in this repository.*

### P6 — Crypto-agility and PQC readiness
**Cheap credibility. Do it in the gaps.**

Algorithm agility as a first-class token property: suite identifier in the envelope (**covered by the signature**, to defeat downgrade), hybrid signing (classical + ML-DSA), verify-either in transition and verify-both in strict mode, suite floors pinned by jurisdiction profile. Algorithm rotation treated as the same designed operation as key rotation.

*The good line, and it is true:* transaction-scoped tokens are short-lived, which makes SPT-Txn one of the very few token systems where PQC migration is genuinely easy. **Our tokens outlive their algorithms by minutes, not years.**

Standards bodies currently reward PQC readiness disproportionately. Low-cost draft text, high citation value.

### P7 — Legacy protocol translation
**DELIBERATELY CONCEDED IN BREADTH. Read this before proposing work here.**

General legacy auth translation — RACF, LDAP, SAML, mainframe middleware, every vendor's dialect — is an integration tar pit with a thousand-protocol surface. **A small team that attempts it dies of integration support load before shipping v2.** We are not attempting it. This is a partner channel: the published PEP contract from P3 *is* the partner surface, and an SI can build the RACF adapter without us.

**One surgical exception:** an **ISO 20022 / ISO 8583 financial-messaging PEP** — transaction-scoped authorization for payment rails. A payment instruction does not move unless accompanied by a valid token whose intent binding matches the instruction's amount, beneficiary, and currency; every instruction gets a receipt. One protocol family, one industry, and the industry where our credibility is strongest.

**Build-to-order only.** This waits for a bank that co-funds it. **Do not build it speculatively.** Failure mode to design for: fail closed to *"instruction held for manual release,"* never to a silent drop — banks will not tolerate dropped instructions, and the operations reality matters more than the security purity here.

*Naming a conceded scope boundary explicitly is a due-diligence asset. Keep it named.*

---

## Sequencing — 90 Days

| Weeks | Work |
|---|---|
| 1–2 | Repo split executed. IP assignment papered. |
| 2–6 | **P1 spec text** (delegation semantics, intent binding, MCP profile) + **P2 receipt format**. These are the NCCoE/IETF payloads. The window is the constraint. |
| 4–10 | **P3** Envoy filter + MCP middleware to demo quality. **P4** SPIFFE ingress. |
| 8–12 | **P6** draft section. **P2** verifier CLI. NCCoE letter of interest drafted and ready to fire the day the collaboration call opens. |
| — | **P7** waits for a co-funding bank. Not before. |

---

## Standing Constraints

- **Spec before code**, in the trust boundary, without exception.
- **Latency is a security requirement.** A PEP too slow to tolerate gets bypassed, and a bypassed PEP is worse than none.
- **Do not build a GRC dashboard.** Export to what customers already run.
- **Do not reopen P7.** The concession is deliberate and it is an asset.
- **Standards position outranks feature completeness.** When they compete, spec wins.
