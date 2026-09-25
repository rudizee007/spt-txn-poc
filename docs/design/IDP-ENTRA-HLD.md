# SPT-Txn x Microsoft Entra ID: High-Level Design

**Status:** High-level design, not implemented. No live Entra tenant run yet. The same OIDC + RFC 8693 bridge is proven live against Keycloak and PingOne, so this is a configuration and claim-mapping exercise, not a new architecture.

## Purpose

Entra authenticates the human or agent and issues a token. SPT-Txn turns that into a per-transaction, attenuating, offline-verifiable authorization. Entra secures identity and sign-in; SPT-Txn secures the action.

Posture: Entra is one identity root among many. There is no Entra-only edition and no dependency on Microsoft.

## The gap an IdP alone leaves open

| Gap | IdP token today | SPT-Txn adds |
| --- | --- | --- |
| Standing authority | Conditional Access token is valid for the session, not the action | Single-use TXN token bound to one intent |
| Resource enforcement | An agent using an API key bypasses the IdP and Conditional Access | PEP at the resource enforces regardless of how the agent authenticated |
| Intent binding | Scopes and roles, not amount and payee | Intent hash over amount, asset, payee, expiry |
| Third-party evidence | Sign-in logs inside the tenant | Signed receipt any auditor or counterparty verifies offline |
| Multi-hop delegation | On-Behalf-Of per hop, no attenuation proof | CAT to CT to TXN, strictly narrowing |

## Flow

1. The human (or agent) signs in to Entra and obtains an access token for a **custom SPT-Txn API app registration** (not Microsoft Graph).
2. The client calls the SPT-Txn `idp-bridge` RFC 8693 token-exchange endpoint with that token.
3. The bridge verifies the token against Entra's OIDC discovery and JWKS (issuer `https://login.microsoftonline.com/{tenant-id}/v2.0`, RS256).
4. The bridge maps claims to a humanAnchor and assurance level, then issues a CAT.
5. Delegation proceeds CAT to CT to TXN as today; verification at the PEP is offline.

## Claim mapping

| Entra claim | SPT-Txn use |
| --- | --- |
| `tid` + `oid` | humanAnchor subject (stable per tenant and user; never `email` or `upn`) |
| `iss` (tenant-specific) | Identity-root binding; pin allowed tenant IDs |
| `aud` | Must equal the SPT-Txn API app ID URI |
| `amr` / `acrs` | Assurance level (MFA, phishing-resistant, authentication context) |
| `appid` / `azp` | Agent or workload identity for M2M and agent tokens |
| Verified ID credential (optional) | Identity-proofing level (IAL) |

Absent assurance claims mean lowest assurance.

## Per-transaction approval (step-up)

When policy returns ESCALATE, two options:

- **Entra authentication context:** a Conditional Access policy tied to an `acrs` value forces passkey re-authentication; the bridge requires that `acrs` in the fresh token. This binds the person, but not the transaction details.
- **SPT-Txn WebAuthn (preferred):** the human signs the hash of the canonical transaction record with a passkey. This gives dynamic linking to amount and payee, which IdP step-up alone does not.

Where the IdP does not offer CIBA, decoupled push approval uses the SPT-Txn flow.

## Agent identities

- **Entra Agent ID and service principals:** client-credentials tokens exchanged into a CAT with the agent as subject, the same pattern as the live PingOne AI agent integration.
- **On-Behalf-Of chains:** Entra OBO is not RFC 8693; the bridge accepts the OBO result as input and records the chain, but attenuation is enforced by SPT-Txn, not by the IdP.

## Security considerations

- **Multi-tenant issuer trap:** never accept the `common` or `organizations` issuer generically; pin tenant IDs and validate `iss` against `tid`.
- **Graph tokens are not verifiable by third parties;** always request a token for the SPT-Txn API audience.
- **Key rollover:** signing keys rotate; the bridge must refresh JWKS on unknown `kid`, and fail closed.
- **Tenant compromise:** an attacker with Global Admin can mint valid identities. SPT-Txn limits the blast radius through mandate caps and receipts but does not prevent a compromised root.

## Validation plan

1. Entra developer tenant; register the SPT-Txn API and a client app.
2. Run `idp-bridge` with `SPT_IDP_OIDC_ISSUER` set to the tenant v2.0 issuer and `SPT_IDP_AUDIENCE` set.
3. Prove: human token to CAT, service principal to CAT, tampered token rejected, CAT verified offline.
4. Publish the conformance run before listing Entra as a supported identity root.
