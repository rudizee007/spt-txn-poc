# Letter of Interest — NCCoE "Software and AI Agent Identity and Authorization"

> **Draft for submission.** Fill the bracketed fields, move onto organization
> letterhead, and submit in response to the NCCoE call for collaborators
> accompanying the project description (expected summer 2026). This references
> the NIST/NCCoE concept paper *Accelerating the Adoption of Software and
> Artificial Intelligence Agent Identity and Authorization* (Feb 2026).
>
> **Public-disclosure note:** everything below is drawn only from already-public
> work (the IETF draft, the SSRN/Zenodo papers, and the public reference
> implementation). It contains no unpublished material. Keep it that way.

---

[Organization letterhead]

[Date]

National Cybersecurity Center of Excellence
National Institute of Standards and Technology
9700 Great Seneca Highway
Rockville, MD 20850

**Re: Letter of Interest — Software and AI Agent Identity and Authorization**

To the NCCoE Project Team,

[Organization] writes to express its interest in participating as a technology
collaborator in the NCCoE project on Software and AI Agent Identity and
Authorization, as scoped in the February 2026 concept paper *Accelerating the
Adoption of Software and Artificial Intelligence Agent Identity and
Authorization*. We believe the constructs we have developed and published
directly address the four capability areas the concept paper identifies as
most in need of practical, standards-based demonstration: **identification,
authorization, auditing and non-repudiation, and mitigation of prompt-injection
techniques.**

## Who we are

[Organization] develops transaction-scoped authorization infrastructure for
autonomous software and AI agents. Our work is public and citable:

- IETF Internet-Draft *draft-coetzee-oauth-spt-txn-tokens* (OAuth 2.0
  transaction-bound authorization tokens).
- A formal cryptographic-theory paper with five game-based security proofs
  (SSRN Abstract ID 6379940; Zenodo DOI 10.5281/zenodo.19299787).
- A public reference implementation (Apache 2.0) covering token issuance,
  offline verification, delegation-chain attenuation, intent binding, signed
  transaction receipts with a transparency log, attested workload-identity
  issuance, and post-quantum algorithm agility.

Our maintainer holds the CISSP-ISSAP, CISSP-ISSMP, and CSSLP credentials and
has designed authorization systems for regulated financial environments.

## How our work maps to the project's stated needs

**Identification of agents (and the workloads behind them).** We consume
attested identity rather than assuming it: SPIFFE SVIDs (JWT and X.509),
Kubernetes projected ServiceAccount tokens, and cloud workload-identity
federation (AWS IRSA, GCP Workload Identity, Azure federated credentials),
each profiled as an RFC 8693 token exchange. The attestation evidence is sealed
into the issued token, so a downstream verifier confirms not only *which* agent
acted but *on what attested substrate*.

**Authorization — scoped to the transaction, not the role.** Today's model
grants an agent a role whose authority persists across every action. That fails
precisely when an agent is compromised. Our tokens are bound to a single
declared action, on a single resource, under a single jurisdictional policy.
Delegation from agent to sub-agent to tool is expressed as a cryptographically
sealed chain in which each hop can only *narrow* authority, verifiable offline
with no call home. This is the concept paper's "authorization chain" made
concrete and machine-checkable.

**Auditing and non-repudiation — as a byproduct of enforcement.** Every
authorization decision emits a signed Transaction Receipt at the moment of
decision, appended to an append-only Merkle transparency log with
externally-witnessed signed tree heads (Certificate-Transparency lineage). An
auditor can prove that a specific control was enforced at the moment of a
specific transaction — inclusion-provable without revealing the rest of the
log, and impossible for even the operator to rewrite silently. We map receipt
fields to NIST SP 800-53 controls (AC-3, AC-4, AC-6, AU-2, AU-10, SC-24) so the
evidence imports into tools organizations already run.

**Mitigation of prompt injection and goal hijacking.** This is where the
transaction-scoped model is strongest. Each token embeds a digest of the
*declared* action — tool identifier, canonicalized parameter digest, target
resource. The enforcement point verifies the *actual* call against that bound
intent. An agent whose reasoning is hijacked mid-task holds a token that is
cryptographically useless for the hijacked action. This directly addresses the
concept paper's prompt-injection concern and OWASP ASI01 (goal hijacking),
without depending on detecting the injection itself.

**Revocation at scale.** Per-token revocation is published as an IETF Token
Status List (draft-ietf-oauth-status-list), checked offline by the verifier and
failing closed when the status snapshot is unavailable — complementing
immediate key-cascade revocation for delegated authority.

## What we would contribute

Should the project proceed to a build phase, [Organization] would contribute,
at no cost to NCCoE and under the Center's standard collaborator terms:

1. A reference enforcement point (policy enforcement point / identity-aware
   proxy) demonstrating transaction-scoped authorization for AI-agent tool
   calls, including an MCP (Model Context Protocol) profile and Envoy/OPA
   integration surfaces.
2. The offline verifier and the signed-receipt transparency log, with the
   control-framework evidence mapping.
3. The attested-issuance exchange consuming SPIFFE / cloud workload identity.
4. Cross-implementation conformance vectors so other collaborators can validate
   interoperable implementations independently.
5. Technical contributions to the practical guide, and continued alignment of
   our IETF draft with the reference architecture the project produces.

We would welcome the opportunity to discuss how these capabilities could support
the demonstration. Please contact the undersigned at [email] / [phone].

Respectfully,

[Authorized Signatory]
[Title]
[Organization]
