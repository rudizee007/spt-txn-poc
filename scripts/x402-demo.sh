#!/bin/sh
# x402-demo.sh — run the SPT-Txn agentic x402 loop end to end, on any chain.
#
# Starts gatesvc (the authority) + merchantsvc (the metered resource), waits for
# both to be healthy, runs the agent through the loop, then tears the servers
# down. Builds real binaries and frees ports 8401/8402 before/after so repeated
# runs never hit "address already in use".
#
# Usage:
#   ./scripts/x402-demo.sh allow      # gate ALLOW, dry-pay (loop only, no settle)
#   ./scripts/x402-demo.sh deny       # gate DENY (price > ceiling), agent refuses
#   SPT_XRPL_SEED=sEd... ./scripts/x402-demo.sh real                 # XRPL testnet settle
#   CHAIN=hedera HEDERA_OPERATOR_ID=0.0.x HEDERA_OPERATOR_KEY=302e… \
#     MERCHANT_ADDR=0.0.y ./scripts/x402-demo.sh real                # Hedera testnet settle
#
# Config via env (with defaults):
#   CHAIN          xrpl | hedera                          (default xrpl)
#   AGENT_ADDR     payer address (auto-derived from creds when a key is set)
#   MERCHANT_ADDR  destination address
#   CEILING        agent spend ceiling (drops / tinybars) (default 5000)
#   ENDPOINT       XRPL only: mainnet JSON-RPC URL for P4 (real money)

set -eu
MODE="${1:-allow}"
CHAIN="${CHAIN:-xrpl}"
CEILING="${CEILING:-5000}"

case "$CHAIN" in
  xrpl)
    PAY_DIR="clients/xrpl-pay"; PAY_BIN="clients/xrpl-pay/xrpl-pay"
    CURRENCY="${CURRENCY:-XRP}"
    AGENT_ADDR="${AGENT_ADDR:-rB99P58Gn3bHeBzmZhJHeDU4uTYGVQdHRV}"
    MERCHANT_ADDR="${MERCHANT_ADDR:-rLNVi6bfZxhgUkZvZsh44pdvkMEpgC1Udx}"
    CRED="${SPT_XRPL_SEED:-}"; CRED_NAME="SPT_XRPL_SEED" ;;
  hedera)
    PAY_DIR="clients/hedera-pay"; PAY_BIN="clients/hedera-pay/hedera-pay"
    CURRENCY="${CURRENCY:-HBAR}"
    AGENT_ADDR="${AGENT_ADDR:-0.0.0}"
    MERCHANT_ADDR="${MERCHANT_ADDR:-0.0.0}"
    CRED="${HEDERA_OPERATOR_ID:-}"; CRED_NAME="HEDERA_OPERATOR_ID (+ HEDERA_OPERATOR_KEY)" ;;
  *) echo "unknown CHAIN '$CHAIN' (want xrpl|hedera)"; exit 1 ;;
esac

case "$MODE" in
  allow|real) PRICE=1000 ;;   # under the ceiling -> ALLOW
  deny)       PRICE=9000 ;;   # over the ceiling  -> DENY
  *) echo "usage: [CHAIN=…] $0 {allow|deny|real}"; exit 1 ;;
esac

# Run from the repo root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

freeport() { pids=$(lsof -ti tcp:"$1" 2>/dev/null || true); [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true; }
cleanup()  { freeport 8401; freeport 8402; }
trap cleanup EXIT INT TERM
freeport 8401; freeport 8402

BIN=$(mktemp -d)
echo "== building servers ($CHAIN) =="
go build -o "$BIN/gatesvc"     ./cmd/gatesvc
go build -o "$BIN/merchantsvc" ./cmd/merchantsvc
go build -o "$BIN/agent"       ./cmd/agent

# If credentials are present, build the pay backend and derive the agent address
# from it so the gate is provisioned for the actual payer (context-hash binding).
if [ -n "$CRED" ]; then
  ( cd "$PAY_DIR" && go build -o "$(basename "$PAY_BIN")" . )
  AGENT_ADDR=$("$PAY_BIN" -whoami)
  echo "== agent address derived from credentials: $AGENT_ADDR =="
fi

echo "== gate:     chain=$CHAIN ceiling=$CEILING $CURRENCY, agent $AGENT_ADDR =="
"$BIN/gatesvc" -chain "$CHAIN" -currency "$CURRENCY" -ceiling "$CEILING" -agent "$AGENT_ADDR" >/tmp/gatesvc.log 2>&1 &
echo "== merchant: price $PRICE $CURRENCY -> $MERCHANT_ADDR =="
"$BIN/merchantsvc" -price "$PRICE" -currency "$CURRENCY" -network "$CHAIN" -payto "$MERCHANT_ADDR" >/tmp/merchantsvc.log 2>&1 &

echo "== waiting for services =="
g="" ; m=""
for _ in $(seq 1 30); do
  g=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:8401/gate/health 2>/dev/null || true)
  m=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:8402/health 2>/dev/null || true)
  if [ "$g" = "200" ] && [ "$m" = "200" ]; then break; fi
  sleep 1
done
if [ "$g" != "200" ] || [ "$m" != "200" ]; then
  echo "!! services did not come up (gate=$g merchant=$m). Recent logs:"
  echo "--- gatesvc ---";     tail -n 15 /tmp/gatesvc.log     2>/dev/null || true
  echo "--- merchantsvc ---"; tail -n 15 /tmp/merchantsvc.log 2>/dev/null || true
  exit 1
fi
echo "== services up; running agent (mode: $MODE) =="
echo

if [ "$MODE" = "real" ]; then
  [ -n "$CRED" ] || { echo "set $CRED_NAME for a real settle"; exit 1; }
  ( cd "$PAY_DIR" && go build -o "$(basename "$PAY_BIN")" . )
  # XRPL only: ENDPOINT selects the ledger; a non-testnet URL is REAL money (P4).
  if [ "$CHAIN" = "xrpl" ] && [ -n "${ENDPOINT:-}" ]; then
    if ! echo "$ENDPOINT" | grep -qE 'altnet|rippletest|devnet'; then
      printf "\n⚠  REAL MAINNET settle: %s drops from %s on %s\n   type 'yes' to proceed: " "$PRICE" "$AGENT_ADDR" "$ENDPOINT"
      read -r confirm
      [ "$confirm" = "yes" ] || { echo "aborted."; exit 1; }
    fi
    echo "== settling on: $ENDPOINT =="
    "$BIN/agent" -pay-bin "$PAY_BIN" -pay-endpoint "$ENDPOINT"
  else
    "$BIN/agent" -pay-bin "$PAY_BIN"
  fi
else
  "$BIN/agent" -dry-pay
fi
