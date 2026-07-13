# SPT-Txn P4 Specification — NHI Attested Issuance

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/attest`, `cattoken` (attestation sealing), `cmd/workload-bridge`.
**Roadmap:** `docs/ROADMAP.md` P4 (acquisition-critical). **Threat model:** `docs/THREAT-MODEL.md` §3.1.

---

## 1. Position

The market's non-human-identity (NHI) tools **inventory secrets**. SPIFFE gives
workloads **names**. Nobody closes the last mile: **per-action authorization
conditioned on attestation state.** SPT-Txn does — a workload presents an
*attested* identity and receives a transaction-scoped token narrowed to one
action, with the attestation evidence hash **sealed into the token** so a
downstream verifier checks not only *who* acted but *on what attested
substrate*.

This is also the line that makes an identity vendor (Okta, Ping, CyberArk,
Aembit) conclude *"plugs into us"* rather than *"competes with us."* We consume
attested identity; we do not issue it.

**Scope boundary (read this).** This spec covers attestation of *runtime
workload identity* (who/where the workload is) and *attestation freshness*
(how recently it proved that). It does **not** cover build-provenance
conditioning (SLSA/SBOM predicates). That is separate, unpublished work and
MUST NOT appear here — see `CLAUDE.md` §0.

---

## 2. Attested-identity ingress (normative)

The issuer federates the following ingress types, each profiled as the
`subject_token` of an **RFC 8693 token exchange**. A bearer secret alone is
**never** sufficient (`docs/THREAT-MODEL.md` §3.1 S): every ingress carries a
cryptographically verifiable attestation.

| Method id | Substrate | Verification |
|---|---|---|
| `spiffe-jwt-svid` | SPIFFE JWT-SVID | JWT signed by the trust domain's JWKS; `sub` MUST be a `spiffe://` URI; audience REQUIRED and checked |
| `spiffe-x509-svid` | SPIFFE X.509-SVID | X.509 chain verified to a configured trust bundle; identity is the `spiffe://` URI SAN of the leaf |
| `k8s-sa` | Kubernetes projected ServiceAccount token | JWT signed by the cluster JWKS; audience REQUIRED; identity from `sub` (`system:serviceaccount:<ns>:<name>`) and `kubernetes.io` claims |
| `aws-irsa` | AWS IAM Roles for Service Accounts | OIDC assertion signed by the EKS OIDC provider JWKS; audience `sts.amazonaws.com` |
| `gcp-wif` | GCP Workload Identity Federation | Google OIDC ID token; issuer `https://accounts.google.com`; audience checked |
| `azure-fc` | Azure federated credential | Entra OIDC token; issuer/tenant and audience checked |
| `oidc` | generic OIDC workload | issuer + audience checked; no `spiffe://` requirement |

Common rules across all JWT-based methods:

- **Algorithm allowlist.** `RS256` and `EdDSA` only. `alg: none` and every
  unlisted algorithm are rejected explicitly.
- **Issuer/trust-domain match.** The token `iss` (or SPIFFE trust domain) MUST
  equal a configured expected value. No trust-on-first-use.
- **Audience REQUIRED** for SVID and cloud methods — the audience binds the
  token to *this* exchange endpoint and defeats cross-service replay of a
  workload assertion.
- **Temporal validity** (`exp`, `nbf`) checked with bounded leeway.
- **Memory-safe verification only.** Standard library `crypto/rsa`,
  `crypto/ed25519`, `crypto/x509`. No cgo, no custom crypto.

## 3. Evidence digest (normative)

Verification yields an `Identity`. Its **evidence digest** is:

    evidence_digest = base64url( SHA-256( "spt-txn-attest-v1" || 0x00 || E ) )

where `E` is the exact presented evidence — the compact JWT bytes for
JWT/SVID/OIDC methods, or the leaf certificate DER for X.509-SVID. The digest
(not the raw evidence) is what gets sealed, so the token never carries the
workload's bearer assertion downstream.

## 4. Sealing into the issued token (normative)

When a token is issued off an attested exchange, the issuer seals a
`spt_attestation` claim **covered by the token signature**:

```json
"spt_attestation": {
  "method":         "spiffe-jwt-svid",
  "subject":        "spiffe://prod.example/ns/pay/sa/charger",
  "trust_domain":   "prod.example",
  "evidence_digest":"<base64url sha256>",
  "iat":            1750000000,
  "exp":            1750000300
}
```

Because it is inside the signature, a downstream PEP cannot be fed a fresher
or different attestation story than the one the issuer verified
(`docs/THREAT-MODEL.md` §3.1 T). The sealed `exp` is the attestation's own
expiry, distinct from the token's `exp`; the token's `exp` MUST NOT exceed the
attestation `exp` (you cannot outlive the proof you were minted on).

## 5. Attestation-freshness predicates (normative)

The issuer MAY enforce freshness at exchange time:

> *Actions of class X require attestation newer than D.*
> e.g. "payments above threshold T require attestation newer than 60 seconds."

Rules:

- Freshness is `now − attestation.iat`. Exceeding the configured `MaxAge` is a
  **DENY** with class `unavailable`-distinct reason `attestation-stale` (it is
  a violation of a freshness *predicate*, class `violation`).
- Freshness policy is data (a mapping from predicate to max-age), hashed into
  the receipt like any other policy input.
- The mechanism lives here; the *action-conditioned* policy (which action
  needs which freshness) is a jurisdictional/policy-pack concern and is not
  built in this public tree.

## 6. RFC 8693 workload exchange profile

`cmd/workload-bridge` endpoint:

    POST /token   (application/x-www-form-urlencoded or JSON)
      grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
      subject_token       = <attested workload assertion>
      subject_token_type  = urn:violetsky:token-type:{spiffe-jwt-svid|k8s-sa|oidc|...}
      audience            = <this exchange endpoint's identifier>   (required)
      holder_key_hex      = <64-hex Ed25519 public key of the workload/agent>
      scope               = <JSON object>   (optional; intersected with policy — a ceiling, never an instruction)
      requested_max_age_s = <int>           (optional freshness predicate)

    → issues an SPT-Txn CAT (root authority for this workload) with
      spt_attestation sealed, scope = intersection(requested, permitted),
      holder-bound to holder_key_hex, delegable to a sub-agent thereafter.

Fail-closed: any verification, audience, temporal, freshness, or scope failure
returns an OAuth error and issues **no** token. The workload's raw assertion is
never logged or forwarded (only its evidence digest is retained).

**Division of labor for the `intersection(requested, permitted)` above.** The
attestation establishes *identity*, never *entitlement*. The reference bridges
therefore enforce the bounds they can enforce without a policy source: a
**hard cap on `delegation_depth_max`** (a caller can never request an unbounded
delegation fan-out) and a CAT lifetime clamped so it never outlives the proof.
The requested `scope` is carried as an **advisory ceiling**; the authoritative
`intersection` against a per-principal *permitted* entitlement is performed
**downstream at the PEP/policy layer** (jurisdictional TBAC), which is where the
`permitted` set lives — not in the public reference issuer. An operator who
exposes a bridge without a PEP in front is relying on the ceiling alone and
MUST configure one; the bridge does not invent entitlement it cannot prove.

## 7. Non-goals

- Issuing workload identity (that is SPIFFE/cloud IdP; we consume it).
- Build-provenance conditioning — separate unpublished work; not here.
- Trusting a workload's self-reported attestation. Evidence is verified against
  the trust domain's keys at exchange time, never taken on the workload's word.
