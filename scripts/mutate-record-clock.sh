#!/usr/bin/env bash
# Mutation check for the single-use record's two-clock lifetime.
#
# Each control is reverted and the named test must fail:
#
#   C-A  a record is pruned once its monotonic budget passes, ignoring the wall expiry
#   C-B  a record is pruned once its wall expiry passes, ignoring the monotonic budget
#   C-C  the token record is not stamped with the artefact's wall expiry
#
# One file is mutated. It is backed up, restored before every mutation and once
# on exit, and compared byte for byte with its backup; the backup is kept if a
# restore does not match. An interrupt stops the run, and further signals are
# ignored while the file is restored.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
E=internal/verifier/engine.go

MONO_GUARD='if now.Before(e.mono) {'
WALL_GUARD='if !e.wall.IsZero() && now.Before(e.wall) {'
TXN_WALL='consumption{key: txnKey, ttl: ttlUntil(exp, now), wallExp: time.Unix(exp, 0)}'

leftover=0
for anchor in "$MONO_GUARD" "$WALL_GUARD" "$TXN_WALL"; do
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

# C-A: drop the monotonic hold, so a record is pruned the instant its wall expiry
# passes even if its real-elapsed budget has not. Removing the mono guard means
# expired() returns as soon as the wall check does.
run_mutation "C-A monotonic hold dropped" \
  "TestRecordHeldWhileEitherClockIsLive" \
  "$MONO_GUARD" 'if false && now.Before(e.mono) {' || rc=1

# C-B: drop the wall hold, so a record is pruned once its monotonic budget passes
# even while its wall expiry (and thus the artefact's acceptance) is in the future.
run_mutation "C-B wall hold dropped" \
  "TestConsumeAllHoldsARecordWhoseWallExpiryIsStillFuture" \
  "$WALL_GUARD" 'if false && !e.wall.IsZero() && now.Before(e.wall) {' || rc=1

# C-C: stamp the token record with no wall expiry, so it is held on the monotonic
# budget alone and no longer shares the acceptance check's wall bound.
run_mutation "C-C token record loses its wall expiry" \
  "TestConsumeOnAllowStampsTheArtefactWallExpiry" \
  "$TXN_WALL" 'consumption{key: txnKey, ttl: ttlUntil(exp, now)}' || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "All mutations killed."
else
  echo "PROBLEM: a control can be removed with its test still green. Fix the test, not this script."
fi
exit "$rc"
