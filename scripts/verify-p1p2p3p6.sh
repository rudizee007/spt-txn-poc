#!/bin/sh
# verify-p1p2p3p6.sh — host-side verification for the P1/P2/P3/P6 build
# (delegation TTL + intent binding + MCP PEP; receipts + transparency log;
# gateway skins; crypto-agility). Run from the repo root on the Mac:
#
#   sh scripts/verify-p1p2p3p6.sh
#
# Optional PQC leg (fetches filippo.io/mldsa, runs the real ML-DSA-65 tests):
#
#   MLDSA=1 sh scripts/verify-p1p2p3p6.sh
set -eu

echo "== go version =="
go version

echo "== vet (new + touched packages) =="
go vet ./internal/jcs/ ./internal/intent/ ./internal/decision/ \
       ./internal/mcppep/ ./internal/receipt/ ./internal/suite/ \
       ./internal/attest/ ./internal/statuslist/ ./internal/controlmap/ ./internal/conformance/ \
       ./internal/identityroot/ ./internal/zkdidmock/ ./internal/civicpass/ \
       ./internal/cttoken/ ./internal/txntoken/ ./internal/verifier/ \
       ./cmd/receiptverify/ ./cmd/extauthz/ ./cmd/opashim/ ./cmd/workload-bridge/ ./cmd/receiptexport/ ./cmd/civicdemo/

echo "== unit + property tests =="
go test ./internal/jcs/ ./internal/intent/ ./internal/decision/ \
        ./internal/mcppep/ ./internal/receipt/ ./internal/suite/ \
        ./internal/attest/ ./internal/statuslist/ ./internal/controlmap/ ./internal/conformance/ \
        ./internal/identityroot/ ./internal/zkdidmock/ ./internal/civicpass/ \
        ./internal/cttoken/ ./internal/txntoken/ ./internal/verifier/ \
        ./internal/audit/ ./internal/tbac/

echo "== canonicalizer fuzz (30s smoke; run longer before releases) =="
go test -run=^$ -fuzz=FuzzRoundTrip -fuzztime=30s ./internal/jcs/

echo "== full build =="
go build ./...

echo "== full test =="
go test ./...

if [ "${MLDSA:-0}" = "1" ]; then
  echo "== ML-DSA hybrid leg =="
  go get filippo.io/mldsa
  go vet -tags mldsa ./internal/suite/
  go test -tags mldsa ./internal/suite/
fi

echo "== govulncheck (blocking) =="
if command -v govulncheck >/dev/null 2>&1; then
  govulncheck ./...
else
  echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"
  exit 1
fi

echo "ALL GREEN"
