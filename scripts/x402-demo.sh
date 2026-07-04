#!/bin/sh
# x402-demo.sh — run the SPT-Txn agentic x402 loop end to end (P1).
#
# Starts gatesvc (the authority) + merchantsvc (the metered resource), waits for
# both to be healthy, runs the agent through the loop, then tears the servers
# down. No terminal juggling.
#
# It builds real binaries and tracks their PIDs (rather than `go run`, whose
# compiled child keeps holding the port after the parent is killed), and frees
# ports 8401/8402 before and after — so repeated runs never hit "address already
# in use".
#
# Usage:
#   ./scripts/x402-demo.sh allow      # gate ALLOW, dry-pay (loop only, no settle)
#   ./scripts/x402-demo.sh deny       # gate DENY (price > ceiling), agent refuses
#   SPT_XRPL_SEED=sEd... ./scripts/x402-demo.sh real   # ALLOW + real testnet settle
#
# Config via env (with defaults):
#   AGENT_ADDR     payer XRPL address        (default rB99…)
#   MERCHANT_ADDR  merchant XRPL address     (default rLNVi…)
#   CEILING        agent spend ceiling drops (default 5000)

set -eu
MODE="${1:-allow}"
AGENT_ADDR="${AGENT_ADDR:-rB99P58Gn3bHeBzmZhJHeDU4uTYGVQdHRV}"
MERCHANT_ADDR="${MERCHANT_ADDR:-rLNVi6bfZxhgUkZvZsh44pdvkMEpgC1Udx}"
CEILING="${CEILING:-5000}"

case "$MODE" in
  allow|real) PRICE=1000 ;;   # under the ceiling -> ALLOW
  deny)       PRICE=9000 ;;   # over the ceiling  -> DENY
  *) echo "usage: $0 {allow|deny|real}"; exit 1 ;;
esac

# Run from the repo root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

freeport() { pids=$(lsof -ti tcp:"$1" 2>/dev/null || true); [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true; }
cleanup()  { freeport 8401; freeport 8402; }
trap cleanup EXIT INT TERM

# Pre-clean any stale listeners from a previous run.
freeport 8401; freeport 8402

BIN=$(mktemp -d)
echo "== building servers =="
go build -o "$BIN/gatesvc"     ./cmd/gatesvc
go build -o "$BIN/merchantsvc" ./cmd/merchantsvc
go build -o "$BIN/agent"       ./cmd/agent

# If a seed is present, derive the agent address FROM it so the gate is
# provisioned for the actual payer (the context hash binds the real originator).
if [ -n "${SPT_XRPL_SEED:-}" ]; then
  ( cd clients/xrpl-pay && go build -o xrpl-pay . )
  AGENT_ADDR=$(clients/xrpl-pay/xrpl-pay -whoami)
  echo "== agent address derived from seed: $AGENT_ADDR =="
fi

echo "== gate:     ceiling $CEILING, agent $AGENT_ADDR =="
"$BIN/gatesvc" -ceiling "$CEILING" -agent "$AGENT_ADDR" >/tmp/gatesvc.log 2>&1 &
echo "== merchant: price $PRICE drops -> $MERCHANT_ADDR =="
"$BIN/merchantsvc" -price "$PRICE" -payto "$MERCHANT_ADDR" >/tmp/merchantsvc.log 2>&1 &

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
  : "${SPT_XRPL_SEED:?set SPT_XRPL_SEED to the payer seed (s… secret for $AGENT_ADDR) for a real settle}"
  [ -x clients/xrpl-pay/xrpl-pay ] || ( cd clients/xrpl-pay && go build -o xrpl-pay . )
  "$BIN/agent" -pay-bin clients/xrpl-pay/xrpl-pay
else
  "$BIN/agent" -dry-pay
fi
