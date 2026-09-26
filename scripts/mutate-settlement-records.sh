#!/usr/bin/env bash
# Mutation check for the gate/settler record split in the verifier.
#
# Each control is reverted and the named test must fail:
#
#   S-A  settler token record uses the gate's kind
#   S-B  settler slice record uses the gate's kind
#   S-C  the settler role builds the gate's keys in consumeOnAllow
#   S-D  a caller that names no role is allowed to record
#   S-E  the settler path consumes under the gate role
#
# One file is mutated. It is backed up, restored before every mutation and once
# on exit, and compared byte for byte with its backup; the backup is kept if a
# restore does not match. An interrupt stops the run, and further signals are
# ignored while the file is restored.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
E=internal/verifier/engine.go
FILES=("$E")

SETTLE_TXN='return recordKey{kind: recordSettleTxn, id: jti}'
SETTLE_SLICE='return recordKey{kind: recordSettleSlice, scope: root, leg: leg}'
ROLE_SETTLE_BRANCH='txnKey, sliceKeyFor = settleTxnRecord(jti), settleSliceRecord'
DEFAULT_GUARD='return fmt.Errorf("consumeOnAllow: no consuming role given")'
SETTLE_CALL='e.consumeOnAllow(roleSettle, txClaims, ctClaims)'

leftover=0
for anchor in "$SETTLE_TXN" "$SETTLE_SLICE" "$ROLE_SETTLE_BRANCH" "$DEFAULT_GUARD" "$SETTLE_CALL"; do
  [ "$(grep -cF -- "$anchor" "$E")" -eq 1 ] || leftover=1
done
if [ "$leftover" -ne 0 ]; then
  echo "REFUSED   the tree does not match the unmutated controls. Restore it first."
  exit 1
fi

BAK=$(mktemp)
cp "$E" "$BAK" || { echo "could not back up $E"; exit 1; }
restore() { cp "$BAK" "$E" || { echo "RESTORE FAILED: could not copy $E back"; exit 1; }; }
cleanup() {
  trap '' INT TERM
  cp "$BAK" "$E" 2>/dev/null
  if cmp -s "$BAK" "$E"; then rm -f "$BAK"; else echo "RESTORE FAILED: $E does not match its backup ($BAK kept)"; fi
}
trap cleanup EXIT
trap 'echo "INTERRUPTED: stopping; the file is restored on exit"; exit 130' INT
trap 'echo "TERMINATED: stopping; the file is restored on exit"; exit 143' TERM

# run_mutation NAME TEST FROM TO
run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  restore
  if ! go test ./internal/verifier/ -run "^${want_test}\$" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree"
    return 1
  fi
  if ! python3 - "$E" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(a) != 1:
    sys.exit(f"anchor appears {s.count(a)} times")
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly once; nothing was written"
    return 1
  fi
  if ! go build ./internal/verifier/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile; rewrite it, do not skip it"
    return 1
  fi
  if ! go test ./internal/verifier/ -run '^$' -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: the package's tests do not build under this mutation"
    return 1
  fi
  if go test ./internal/verifier/ -run "^${want_test}\$" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name: $want_test still passes"
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "S-A settler token record uses the gate's kind" \
  "TestGateAndSettlerRecordKindsAreDisjoint" \
  "$SETTLE_TXN" 'return recordKey{kind: recordTxn, id: jti}' || rc=1

run_mutation "S-B settler slice record uses the gate's kind" \
  "TestGateAndSettlerRecordKindsAreDisjoint" \
  "$SETTLE_SLICE" 'return recordKey{kind: recordSlice, scope: root, leg: leg}' || rc=1

run_mutation "S-C settler role builds the gate's keys" \
  "TestSingleUse_GateAndSettlerDoNotShareARecord" \
  "$ROLE_SETTLE_BRANCH" 'txnKey, sliceKeyFor = txnRecord(jti), sliceRecord' || rc=1

run_mutation "S-D a role-less consume is allowed" \
  "TestConsumeOnAllowRefusesRoleNone" \
  "$DEFAULT_GUARD" 'txnKey, sliceKeyFor = txnRecord(jti), sliceRecord' || rc=1

run_mutation "S-E settler path consumes under the gate role" \
  "TestSingleUse_GateAndSettlerDoNotShareARecord" \
  "$SETTLE_CALL" 'e.consumeOnAllow(roleGate, txClaims, ctClaims)' || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "All mutations killed."
else
  echo "PROBLEM: a control can be removed with its test still green. Fix the test, not this script."
fi
exit "$rc"
