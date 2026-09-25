# SPT-Txn x Google Identity: High-Level Design

**Status:** High-level design, not implemented. No live Google run yet. The same OIDC + RFC 8693 bridge is proven live against Keycloak and PingOne; Google needs one adapter change (ID tokens instead of access tokens).

## Purpose

Two integration points:

1. **Google as identity root:** Google Workspace, Cloud Identity or Google accounts authenticate the human; service accounts authenticate workloads and agents. SPT-Txn issues the CAT and everything downstream.
2. **AP2 interop:** Agent Payments Protocol mandates become an input SPT-Txn can bind to and extend, not a competing format.

Posture: Google is one identity root among many; no Google-only edition.

## Flow (identity root)

1. The human signs in with Google (OIDC) and the client obtains a **Google ID token** with `aud` set to the SPT-Txn client ID.
2. The client calls the SPT-Txn `idp-bridge` RFC 8693 endpoint with the ID token (`subject_token_type` = id_token).
3. The bridge verifies it against Google's OIDC discovery and JWKS (issuer `https://accounts.google.com`, RS256).
4. The bridge maps claims to a humanAnchor and assurance level, then issues a CAT.
5. CAT to CT to TXN and offline verification are unchanged.

## Claim mapping

| Google claim | SPT-Txn use |
| --- | --- |
| `sub` | humanAnchor subject (stable; never `email`) |
| `hd` | Workspace domain; pin allowed organizations |
| `aud` | Must equal the SPT-Txn client ID |
| `email_verified` | Informational only, not an assurance signal |
| Service-account ID token `sub` / `email` | Agent or workload identity for M2M |
| `amr` / `acr` | Usually absent; treat as lowest assurance unless proven otherwise |

Authentication-strength claims are not reliably present, so assurance is derived conservatively (absent means lowest), or raised by SPT-Txn's own passkey step-up.

## Per-transaction approval (step-up)

There is no third-party, per-transaction step-up at the IdP. When policy returns ESCALATE, SPT-Txn runs its own WebAuthn flow: the human signs the hash of the canonical transaction record (amount, asset, payee, expiry) with a passkey. That also gives the dynamic linking that sign-in alone cannot.

## Agents and workloads

- **Service accounts:** signed ID tokens with a custom audience, exchanged into a CAT with the agent as subject.
- **Workload Identity Federation:** external workloads obtain Google-issued identity, then exchange it the same way.
- Attenuation and revocation are enforced by SPT-Txn, not by Google IAM.

## AP2 interop (to be designed)

| AP2 concept | SPT-Txn mapping |
| --- | --- |
| Intent mandate (user-signed limits) | Input to CAT or CT issuance; limits become scope and cumulative budget |
| Cart mandate (specific purchase) | Input to the TXN intent hash |
| Payment mandate (to network) | Carried alongside the SPT-Txn receipt as evidence |

SPT-Txn adds multi-hop attenuation, regulatory predicates (Travel Rule ZK proofs), assurance-level human anchors, and non-commerce flows. The mapping belongs in the commerce profile, not the core spec.

## Security considerations

- **Google access tokens are opaque** and not verifiable offline; accept only ID tokens with the SPT-Txn audience.
- **Consumer accounts vs Workspace:** without an `hd` pin, any consumer account is accepted as a root. Pin domains for enterprise deployments.
- **Email reassignment:** addresses can be recycled; anchor on `sub` only.
- **JWKS rotation:** refresh on unknown `kid`, fail closed.
- **Root compromise:** a compromised account yields valid identity; mandate caps and receipts bound the damage but do not prevent it.

## Validation plan

1. Google Cloud project with an OAuth client; one Workspace test user and one service account.
2. Add an ID-token input path to `idp-bridge`, then run it with `SPT_IDP_OIDC_ISSUER=https://accounts.google.com`.
3. Prove: human ID token to CAT, service account to CAT, wrong audience and wrong domain rejected, CAT verified offline.
4. Publish the conformance run before listing Google as a supported identity root.
