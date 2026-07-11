# Identity-provider integration — the proof

An existing OpenID Connect identity provider mints SPT-Txn credentials over
**standard OAuth 2.0 Token Exchange (RFC 8693)** — no rip-and-replace. Proven
end-to-end against **Keycloak**; the same flow targets Okta / Auth0 / Ping
unchanged.

## The flow

```
  alice ──login──▶ Keycloak (IdP)  ──OIDC access token──▶  idp-bridge
                                                              │  RFC 8693 token exchange
                                                              │  (verify token via JWKS, map claims)
                                                              ▼
                                                         SPT-Txn CAT  ──▶  verifies OFFLINE
                                                                            (no IdP contact)
                                                                            ──▶ delegated to an
                                                                                AI agent (CAT→CT→TXN)
```

## Standards it rides (all published RFCs)

| Standard | Role here |
|---|---|
| **RFC 8693 Token Exchange** | the grant that turns an IdP token into a CAT |
| **OIDC Discovery + JWKS** | how the bridge verifies the IdP token (`internal/oidc`) |
| **RFC 9449 DPoP** | binds the CAT to the holder/agent key (`internal/dpop`) |
| **RFC 9396 RAR** / custom `spt_scope` claim | source of the capability scope |
| RFC 7519 JWT (EdDSA) | the CAT is a standard compact JWT |

Nothing bespoke on the ingress — an IdP architect sees only OAuth they recognise.

## Components

| Piece | What it does |
|---|---|
| `internal/oidc` | OIDC discovery + JWKS + RS256 token verification (stdlib-only) |
| `cmd/idp-bridge` | RFC 8693 `/token` endpoint: verify IdP token → issue CAT → RFC 8693 response |
| `cmd/idp-verify` | offline CAT verification + tamper test (the portability proof) |
| `cmd/agentdemo` | CAT → CT → transaction-bound token, attenuation, offline revocation |
| `deploy/keycloak/` | one-command Keycloak (`docker compose`) + realm import |
| `scripts/idp-demo.sh` | runs the whole proof, 7 printed steps |

> Production note: `idp-bridge` is standalone so the proof runs anywhere. In
> production this logic folds into `cmd/catsvc` (the hardened, pledge/unveil CAT
> issuer) — it is the same `cattoken.Issue` call behind a different ingress.

## Run it

```sh
# 0. deps: docker, go, curl, jq, openssl
go test ./internal/oidc/                       # verify the OIDC verifier (no Keycloak needed)

# 1. start Keycloak (first boot ~30s)
(cd deploy/keycloak && docker compose up -d)

# 2. start the bridge (separate terminal)
go run ./cmd/idp-bridge

# 3. run the proof
sh scripts/idp-demo.sh
```

Expected: a Keycloak token is exchanged for a CAT; the CAT verifies **offline**;
a tampered CAT is rejected; the agent-delegation engine runs `ALLOW`/`DENY`.

## Pointing it at Okta / Auth0 / Ping (no code change)

Set the bridge to the provider's issuer and (in production) its audience:

```sh
SPT_IDP_OIDC_ISSUER="https://<tenant>.okta.com/oauth2/default" \
SPT_IDP_AUDIENCE="api://spt" \
SPT_IDP_CAT_SEED_HEX="<pinned 32-byte issuer seed>" \
go run ./cmd/idp-bridge
```

Because the ingress is OIDC discovery + JWKS + RFC 8693, any conformant provider
works; only the issuer URL and audience change.

## Honest boundaries

- **Keycloak *authenticates*; SPT-Txn *attests capability*.** The exchange binds an
  IdP-authenticated identity to a compliance/capability attestation — it does not
  turn the IdP into a KYC provider. In production the KYC/compliance issuer is the
  trusted party; here the bridge plays that role to demonstrate the flow.
- **RS256 only** in this build (Keycloak's default). ES256 is a small, marked
  extension point in `internal/oidc`.
- **Audience check is optional and off by default** for the local demo (Keycloak's
  default `aud` is `account`). **Set `SPT_IDP_AUDIENCE` in production** and add an
  audience mapper in the IdP.
- **DPoP is a documented POC subset.** The demo binds the CAT to a presented holder
  key; production binds the DPoP key the client actually proves.
- **Claims→scope mapping is deployment-specific.** The demo uses request `scope` >
  `spt_scope` claim > a default. Real deployments define their own (e.g. RFC 9396
  authorization_details).
- This is a **reference integration**, not a hardened commercial Okta/Ping connector
  — it proves interoperability and the flow.

## The claim it earns

> Your existing identity provider issues SPT-Txn compliance credentials through
> standard OAuth 2.0 Token Exchange (RFC 8693) — no migration. The credential then
> verifies offline anywhere, carries a privacy-preserving human anchor, and an AI
> agent can act under it with authority that can only narrow and can be revoked
> instantly. Demonstrated end-to-end against Keycloak.
