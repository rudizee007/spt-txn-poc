#!/bin/sh
# idp-demo.sh — the definitive identity-provider proof, end to end.
#
# Proves: an existing IdP (Keycloak) mints an SPT-Txn CAT over standard RFC 8693
# Token Exchange; the CAT verifies OFFLINE with no IdP contact; a tampered CAT is
# rejected; and the same CAT format feeds the agent-delegation engine.
#
# Prerequisites: docker, go, curl, jq, openssl.
#
# Run (from the repo root):
#   1) start Keycloak:   (cd deploy/keycloak && docker compose up -d)   # wait ~30s
#   2) start the bridge: go run ./cmd/idp-bridge                        # separate terminal
#   3) run this:         sh scripts/idp-demo.sh
set -eu

# Always run from the repo root, so `go run ./cmd/...` resolves regardless of
# where this script was invoked from.
cd "$(dirname "$0")/.."

KC="${KC:-http://localhost:8080}"
REALM="${REALM:-spt}"
BRIDGE="${BRIDGE:-http://127.0.0.1:8090}"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

say "1. Identity provider reachable?"
if curl -sf "$KC/realms/$REALM/.well-known/openid-configuration" >/dev/null; then
  echo "  Keycloak realm '$REALM' is up at $KC"
else
  echo "  Keycloak not reachable. Start it:  (cd deploy/keycloak && docker compose up -d)"
  echo "  (first boot takes ~30s; watch 'docker compose logs -f')"
  exit 1
fi

say "2. Bridge reachable?"
if curl -sf "$BRIDGE/health" >/dev/null; then
  echo "  idp-bridge is up at $BRIDGE"
else
  echo "  Bridge not reachable. Start it:  go run ./cmd/idp-bridge"
  exit 1
fi

say "3. Authenticate alice at Keycloak (standard OIDC password grant)"
TOK=$(curl -sf -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=spt-agent \
  -d username=alice -d password=alice | jq -r .access_token)
if [ -z "$TOK" ] || [ "$TOK" = null ]; then echo "  auth failed"; exit 1; fi
echo "  got a Keycloak access token (${#TOK} chars) — the unmodified IdP doing its normal job"

say "4. Generate an agent holder key (32-byte Ed25519 public key)"
HOLDER=$(openssl rand -hex 32)
echo "  holder key: ${HOLDER%${HOLDER#????????}}…"

say "5. RFC 8693 Token Exchange: Keycloak token  ->  SPT-Txn CAT"
RESP=$(curl -sf -X POST "$BRIDGE/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOK" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "holder_key_hex=$HOLDER")
CAT=$(echo "$RESP" | jq -r .access_token)
echo "  issued_token_type: $(echo "$RESP" | jq -r .issued_token_type)"
echo "  human_anchor:      $(echo "$RESP" | jq -r .human_anchor)"
echo "  CAT issued (${#CAT} chars)"
ISSKEY=$(curl -sf "$BRIDGE/issuer" | jq -r .public_key_hex)

say "6. Verify the CAT OFFLINE (no Keycloak, no bridge) + tamper test"
go run ./cmd/idp-verify -cat "$CAT" -issuer-key "$ISSKEY"

say "7. The delegation mechanics an IdP-issued CAT feeds into"
echo "  (agentdemo shows CAT -> CT -> transaction-bound token, attenuation, and"
echo "   offline revocation cascade — the agent authority an IdP identity flows into)"
go run ./cmd/agentdemo

printf '\n\033[1mPROOF COMPLETE:\033[0m an existing identity provider (Keycloak) minted an\n'
printf 'SPT-Txn credential over standard OAuth Token Exchange; it verified offline,\n'
printf 'rejected tampering, and feeds attenuating, revocable agent authority.\n'
