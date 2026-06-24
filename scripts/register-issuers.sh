#!/bin/ksh
# scripts/register-issuers.sh — re-register the real issuer keys in the Trust
# Registry after a trsvc (re)start.
#
# WHY THIS EXISTS: the mock Trust Registry seeds REVOKED all-zero placeholders on
# every start and does NOT persist real registrations (no on-disk DB). So after
# any `rcctl restart trsvc` the real keys are gone and fail-closed services like
# catsvc (ct_issuer) refuse to start. This script re-applies the real keys.
#
# Run as root (the admin socket /var/spt-txn/sockets/tr-admin.sock is owner-only):
#   doas sh scripts/register-issuers.sh
#
# (iss, role) targets come from the registry's own seeded placeholders, which are
# the pairs trsvc expects to be filled. Only ct_issuer is required by the
# currently-deployed services (catsvc); the rest are registered when present so
# tts/audit/escrow services work if enabled.
#
# PROPER FIX (tracked): make the registry persist registrations across restarts,
# which removes the need for this script entirely. See docs/SECURITY-REVIEW.md.

REGKEY="${REGKEY:-/usr/local/bin/regkey}"
[ -x "$REGKEY" ] || REGKEY=/tmp/regkey

reg() { # iss role pubfile
	if [ -f "$3" ]; then
		echo "+ register $1 / $2  <- $3"
		"$REGKEY" -iss "$1" -role "$2" -pub "$3" || echo "  ! failed $1/$2"
	else
		echo "- skip $1 / $2 (no key at $3)"
	fi
}

reg domain-a.authorg ct_issuer  /var/spt-txn/a/keys/ct-issuer.pub
reg domain-b.execorg tts_issuer /var/spt-txn/a/keys/tts-issuer.pub
reg domain-b.execorg audit      /var/spt-txn/b/keys/audit.pub

# escrow is an X25519 key; set ESCROW_PUB to its path when the escrow service is
# deployed (regkey emits key_type=X25519 for role=escrow):
[ -n "$ESCROW_PUB" ] && reg domain-a.authorg escrow "$ESCROW_PUB"

echo
echo "verify active registrations:"
echo "  curl -s http://127.0.0.1:8081/tr/list | grep -E '\"role\"|\"status\"'"
