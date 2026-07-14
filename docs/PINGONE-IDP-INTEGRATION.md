# PingOne / PingFederate — IdP integration runbook

Run `cmd/idp-bridge` against a **live Ping** tenant, exactly as already
demonstrated against Keycloak and Auth0: a Ping-authenticated identity (a human
SSO login or an M2M / agent client) is exchanged over OAuth 2.0 Token Exchange
(RFC 8693) into a human-anchored Capability Token that then verifies **offline**,
with no Ping contact.

Hermetic proof that the bridge handles Ping's token shape is in
`cmd/idp-bridge` (`TestIDPExchange_PingOneCompatibility`). This runbook is the
live end-to-end.

## Why it works unchanged

The bridge's `internal/oidc` verifier consumes any standards-compliant OIDC
provider: discovery at `<issuer>/.well-known/openid-configuration`, JWKS fetch,
RS256 verification, exact `iss`, and `aud`/`azp` audience binding. Ping is
standards-compliant, with two quirks the verifier already handles:

- **Multi-key JWKS.** PingFederate publishes the signing key under multiple
  `kid`/`alg` entries; the verifier resolves strictly by `kid`.
- **`aud` array + `azp`.** PingOne tokens carry `aud` as an array plus an
  `azp` (authorized party); the audience check accepts either.

Use real TLS — do **not** set `SPT_IDP_INSECURE_SKIP_VERIFY` against Ping.

## PingOne (cloud)

1. **Create a free PingOne trial** and an Environment. Note the **region** and
   **Environment ID**; the issuer is
   `https://auth.pingone.<region>/<environmentId>/as`
   (e.g. `.com`, `.eu`, `.ca`, `.asia`).
2. **Add an application.**
   - *Agent / M2M:* a **Worker** app (or any client with the client-credentials
     grant), so a non-human agent identity gets a token — the closest analog to
     an attested agent.
   - *Human:* a Web app with OIDC SSO.
   Configure the access token as a **signed JWT (RS256)** and set its
   **audience** (the value you will give the bridge as `SPT_IDP_AUDIENCE`).
3. **Get a token.** For the Worker app, client-credentials against the PingOne
   token endpoint:
   ```sh
   curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
     -d 'grant_type=client_credentials' \
     "https://auth.pingone.<region>/<environmentId>/as/token" | jq -r .access_token
   ```
4. **Configure and run the bridge:**
   ```sh
   export SPT_IDP_OIDC_ISSUER="https://auth.pingone.<region>/<environmentId>/as"
   export SPT_IDP_AUDIENCE="<the token's aud>"
   export SPT_IDP_PERMITTED_SCOPE='{"action":"transfer","max_amount":10000,"currency":"USD"}'
   go run ./cmd/idp-bridge
   ```
5. **Exchange** (dry-run first to preview the decision, then live):
   ```sh
   HOLDER=<64-hex Ed25519 public key of the agent/holder>
   curl -s http://127.0.0.1:8090/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d subject_token="$PING_ACCESS_TOKEN" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
     -d holder_key_hex="$HOLDER" \
     -d dry_run=true            # then rerun without dry_run to mint the CAT
   ```
6. **Verify offline.** Take the returned `access_token` (the CAT) and check it
   with `cmd/idp-verify` (or the offline verifier) — no Ping contact.

**Success = the same result as Keycloak/Auth0:** a Ping identity exchanged into
a human-anchored CAT that verifies offline and delegates to a sub-agent with
attenuating, revocable authority.

**Machine / agent tokens have no `sub`.** A PingOne Worker-app
(`client_credentials`) token — the M2M / agent case — carries `client_id`
instead of `sub`, and its `aud` is `["https://api.pingone.com"]`. Set
`SPT_IDP_AUDIENCE=https://api.pingone.com`; the bridge uses the verified
`client_id` as the subject (the agent identity). For a real deployment, define a
custom **Resource** with your own audience and grant it to the app, so the token
is bound to *your* exchange endpoint rather than the PingOne API — that restores
the cross-service-replay defense the audience check provides.

## PingFederate (self-hosted / on-prem)

Same flow. Issuer is the PingFederate base (e.g. `https://<pf-host>` or a
configured OAuth base); discovery is at `<issuer>/.well-known/openid-configuration`.
Configure an OAuth client + an Access Token Manager that issues RS256 JWTs, and
point `SPT_IDP_OIDC_ISSUER` at the base and `SPT_IDP_AUDIENCE` at the token's
audience. PingFederate also *offers* RFC 8693 token exchange itself — not
required here (the bridge is the exchange endpoint), but it confirms Ping speaks
the same protocol, so interop is native.

## After a successful live run

Only then update the public claims (site + outreach) from "targets Ping
unchanged" to "demonstrated against Keycloak, Auth0, and Ping" — keeping the
same honesty bar applied to every other claim.
