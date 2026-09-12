#!/usr/bin/env bash
# Mutation check for the verifier's single-use records and the DPoP freshness
# window their lifetime is derived from.
#
# Each control is reverted and the named test must fail:
#
#   R-A  proof record key: kind
#   R-B  proof record key: key thumbprint
#   R-C  proof record: placement after the sender-constraint check
#   R-D  proof record lifetime: skew
#   R-E  consumeAll: zero kind
#   R-F  slice record key: leg
#   R-G  SPT-Txn record key: jti
#   R-H  R-B with R-C, checked end to end
#   R-I  dpop forward tolerance
#   R-J  proof record lifetime: boundary second
#   R-K  proof record lifetime: value used at step 5
#   R-L  proof max age: value used at step 5
#
# R-C on its own is checked white-box, by record count.
#
# Two files are mutated. Both are backed up, restored before every mutation and
# once on exit, and compared byte for byte with their backups; the backups are
# kept if a restore does not match. An interrupt stops the run, and further
# signals are ignored while the files are restored.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
E=internal/verifier/engine.go
D=internal/dpop/dpop.go
FILES=("$E" "$D")

PROOF_KEY='return recordKey{kind: recordProof, scope: jkt, id: jti}'
TXN_KEY='return recordKey{kind: recordTxn, id: jti}'
SLICE_KEY='return recordKey{kind: recordSlice, scope: root, leg: leg}'
NO_KIND='if it.key.kind == recordNone {'
TTL='proofRecordTTL = proofMaxAge + dpop.MaxFutureSkew + time.Second'
STEP5_TTL='proofRecord(jkt, jti), ttl: proofRecordTTL}'
STEP5_AGE='dpop.Verify(proof, htm, htu, ath, proofMaxAge)'
SKEW='if age < -MaxFutureSkew {'
ORDERED=$'\tif err := txntoken.CheckSenderConstraint(txClaims, jkt); err != nil {\n\t\treturn err\n\t}\n\tif !e.replay.consumeAll(consumption{key: proofRecord(jkt, jti), ttl: proofRecordTTL}) {\n\t\treturn fmt.Errorf("DPoP proof replayed (jti already presented)")\n\t}\n'
SWAPPED=$'\tif !e.replay.consumeAll(consumption{key: proofRecord(jkt, jti), ttl: proofRecordTTL}) {\n\t\treturn fmt.Errorf("DPoP proof replayed (jti already presented)")\n\t}\n\tif err := txntoken.CheckSenderConstraint(txClaims, jkt); err != nil {\n\t\treturn err\n\t}\n'

# Refuse to run on a tree that still carries a mutation: a backup taken now
# would preserve it, and every later run would restore it. Every mutation below
# removes one of these anchors or reorders the step-5 lines.
leftover=0
for anchor in "$PROOF_KEY" "$TXN_KEY" "$SLICE_KEY" "$NO_KIND" "$TTL" "$STEP5_TTL" "$STEP5_AGE"; do
  [ "$(grep -cF -- "$anchor" "$E")" -eq 1 ] || leftover=1
done
[ "$(grep -cF -- "$SKEW" "$D")" -eq 1 ] || leftover=1
possession=$(grep -nF 'txntoken.CheckSenderConstraint(txClaims, jkt)' "$E" | head -1 | cut -d: -f1)
record=$(grep -nF 'proofRecord(jkt, jti), ttl:' "$E" | head -1 | cut -d: -f1)
if [ -z "$possession" ] || [ -z "$record" ] || [ "$record" -lt "$possession" ]; then leftover=1; fi
if [ "$leftover" -ne 0 ]; then
  echo "REFUSED   the tree does not match the unmutated controls. Restore it first."
  exit 1
fi

BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do
  mkdir -p "$BAKDIR/$(dirname "$f")"
  cp "$f" "$BAKDIR/$f" || { echo "could not back up $f"; exit 1; }
done

restore() {
  for f in "${FILES[@]}"; do
    cp "$BAKDIR/$f" "$f" || { echo "RESTORE FAILED: could not copy $f back from $BAKDIR"; exit 1; }
  done
}
cleanup() {
  # A second signal must not cut the restore short.
  trap '' INT TERM
  local bad=0
  for f in "${FILES[@]}"; do
    cp "$BAKDIR/$f" "$f" 2>/dev/null
    if ! cmp -s "$BAKDIR/$f" "$f"; then
      echo "RESTORE FAILED: $f does not match its backup"
      bad=1
    fi
  done
  if [ "$bad" -eq 0 ]; then
    rm -rf "$BAKDIR"
  else
    echo "Backups kept in $BAKDIR"
  fi
}
trap cleanup EXIT
trap 'echo "INTERRUPTED: stopping; files are restored on exit"; exit 130' INT
trap 'echo "TERMINATED: stopping; files are restored on exit"; exit 143' TERM

# run_mutation NAME PACKAGE TEST FILE FROM TO [FILE FROM TO ...]
run_mutation() {
  local name="$1" pkg="$2" want_test="$3"
  shift 3
  restore
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # killed: a false green. Require it to pass first.
  if ! go test "$pkg" -run "^${want_test}\$" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree"
    return 1
  fi
  # Every anchor is checked before anything is written.
  if ! python3 - "$@" <<'PY'
import sys
args = sys.argv[1:]
assert len(args) % 3 == 0, "anchors come in FILE FROM TO triples"
contents = {}
for i in range(0, len(args), 3):
    path, a, b = args[i:i + 3]
    s = contents.setdefault(path, open(path).read())
    if s.count(a) != 1:
        sys.exit(f"{path}: anchor appears {s.count(a)} times")
    contents[path] = s.replace(a, b)
for path, s in contents.items():
    open(path, "w").write(s)
PY
  then
    echo "FAIL      $name: an anchor did not match exactly once; nothing was written"
    return 1
  fi
  if ! go build ./internal/verifier/ ./internal/dpop/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile; rewrite it, do not skip it"
    return 1
  fi
  # The package's tests must still build, so a failure below is an assertion.
  if ! go test "$pkg" -run '^$' -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: the package's tests do not build under this mutation"
    return 1
  fi
  if go test "$pkg" -run "^${want_test}\$" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name: $want_test still passes"
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "R-A proof record key: kind" ./internal/verifier/ \
  "TestRecordKeysOfDifferentKindsNeverCompareEqual" \
  "$E" "$PROOF_KEY" 'return recordKey{kind: recordTxn, id: jti}' || rc=1

run_mutation "R-B proof record key: key thumbprint" ./internal/verifier/ \
  "TestRecordKeysIdentifyExactlyOneRecord" \
  "$E" "$PROOF_KEY" 'return recordKey{kind: recordProof, id: jti}' || rc=1

run_mutation "R-C proof record: placement after the sender-constraint check" ./internal/verifier/ \
  "TestProofIsRecordedOnlyAfterPossessionIsEstablished" \
  "$E" "$ORDERED" "$SWAPPED" || rc=1

run_mutation "R-D proof record lifetime: skew" ./internal/verifier/ \
  "TestProofRecordOutlivesTheProofsAcceptance" \
  "$E" "$TTL" 'proofRecordTTL = proofMaxAge' || rc=1

run_mutation "R-E consumeAll: zero kind" ./internal/verifier/ \
  "TestConsumeAllRefusesARecordWithNoKind" \
  "$E" "$NO_KIND" 'if false && it.key.kind == recordNone {' || rc=1

run_mutation "R-F slice record key: leg" ./internal/verifier/ \
  "TestRecordKeysIdentifyExactlyOneRecord" \
  "$E" "$SLICE_KEY" 'return recordKey{kind: recordSlice, scope: root}' || rc=1

run_mutation "R-G SPT-Txn record key: jti" ./internal/verifier/ \
  "TestRecordKeysIdentifyExactlyOneRecord" \
  "$E" "$TXN_KEY" 'return recordKey{kind: recordTxn}' || rc=1

run_mutation "R-H R-B with R-C, checked end to end" ./internal/verifier/ \
  "TestSingleUse_ProofRecordsAreScopedToTheSigningKey" \
  "$E" "$PROOF_KEY" 'return recordKey{kind: recordProof, id: jti}' \
  "$E" "$ORDERED" "$SWAPPED" || rc=1

run_mutation "R-I dpop forward tolerance" ./internal/dpop/ \
  "TestVerify_IatBeyondMaxFutureSkewIsRefused" \
  "$D" "$SKEW" 'if age < -2*MaxFutureSkew {' || rc=1

run_mutation "R-J proof record lifetime: boundary second" ./internal/verifier/ \
  "TestProofRecordTTLCoversTheAcceptanceWindow" \
  "$E" "$TTL" 'proofRecordTTL = proofMaxAge + dpop.MaxFutureSkew' || rc=1

run_mutation "R-K proof record lifetime: value used at step 5" ./internal/verifier/ \
  "TestProofRecordOutlivesTheProofsAcceptance" \
  "$E" "$STEP5_TTL" 'proofRecord(jkt, jti), ttl: proofMaxAge}' || rc=1

run_mutation "R-L proof max age: value used at step 5" ./internal/verifier/ \
  "TestStep5AppliesProofMaxAge" \
  "$E" "$STEP5_AGE" 'dpop.Verify(proof, htm, htu, ath, 10*time.Minute)' || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "All mutations killed."
else
  echo "PROBLEM: a control can be removed with its test still green. Fix the test, not this script."
fi
exit "$rc"
