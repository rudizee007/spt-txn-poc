#!/usr/bin/env bash
# Mutation check for the scope-dimension kind registry on the ISSUANCE path.
#
# The registry records, per dimension, whether a transaction is compared against
# it or whether it only narrows delegation. The guards below are what stop that
# record from being absent, defaulted, or untrue:
#
#   K-A  the guard is removed, so an unclassified dimension seals anyway
#   K-B  the registry acquires a default, so every unknown name reads as decided
#   K-C  a dimension is classified execution-asserted that TxnScope does not
#        project, so the registry asserts something the code does not do
#   K-D  a numeric dimension keeps its direction but loses its kind
#   K-E  kindOf answers by naming convention instead of by declaration
#   K-F  the guard is narrowed to top-level dimensions, so nested leaves seal
#   K-G  TxnScope projects a dimension registered delegation-only
#   K-H  a list element escapes validation entirely
#   K-I  the registry gains an entry nobody acknowledged
#
# K-C and K-G are the two that matter most, and they are different directions of the
# same property. K-C catches a registry entry that claims a projection which does not
# exist; K-G catches a projection that exists and is not claimed. An earlier version
# of this script had only K-C, and an adversarial review defeated the guard through
# the gap: K-E and K-F are the two weakenings it used.
#
# Each mutation must turn at least one NAMED test red. A mutation that does not
# compile, or whose anchor is not found, is a bug in THIS script — never a pass.
#
# Run this on a CLEAN checkout of the branch. An untracked package that adds a
# numericDirection entry without a kind makes K-D's test fail before any mutation
# is applied, and the clean-tree check below will say so rather than scoring it.
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

# EVERY file any mutation below touches must be listed here. restore() only reverts
# what it backed up, so a mutation applied to an unlisted file is left behind in the
# working tree -- and K-G mutates scope.go. That happened once: an injected
# `jurisdiction` projection survived a run and made TxnScope assert a delegation-only
# dimension, which is the exact defect K-G exists to catch.
FILES=(
  internal/tbac/dimensions.go
  internal/tbac/issuance.go
  internal/tbac/scope.go
)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do
  cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"
done
restore() {
  for f in "${FILES[@]}"; do
    cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"
  done
}
# Verify the restore actually happened rather than trusting that it did: a silent
# failure here leaves a mutation in the tree, which is worse than any survived
# mutation because it looks like working code.
verify_restored() {
  local f rc=0
  for f in "${FILES[@]}"; do
    if ! cmp -s "$BAKDIR/$(echo "$f" | tr / _)" "$f"; then
      echo "ERROR: $f was NOT restored -- a mutation is still in your working tree." >&2
      rc=1
    fi
  done
  return "$rc"
}
trap 'restore; verify_restored; rm -rf "$BAKDIR"' EXIT INT TERM

run_mutation() {
  local name="$1" pkg="$2" want_test="$3" file="$4" from="$5" to="$6" want_n="${7:-1}"
  restore
  # Captured, not piped: `grep -q` exits on first match, go test takes SIGPIPE, and
  # `set -o pipefail` then reports the pipeline as failed. The check would report
  # every test as missing -- a FAIL that looks like a mapping bug and is not.
  local listed
  listed=$(go test "$pkg" -list "$want_test" 2>/dev/null)
  if ! grep -qx "$want_test" <<<"$listed"; then
    echo "FAIL      $name: $want_test does not exist -- the mapping is wrong"
    return 1
  fi
  # A test that fails on the CLEAN tree also fails under mutation and would score
  # as "killed": a false green in the reassuring direction.
  if ! go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the tree, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$file"; then
    echo "FAIL      $name: anchor not found in $file — the mutation was never applied"
    return 1
  fi
  if ! python3 - "$file" "$from" "$to" "$want_n" <<'PY'
import sys
p, a, b, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = open(p).read()
assert s.count(a) == n, f"anchor appears {s.count(a)} times, expected {n}"
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly the expected number of"
    echo "          times -- the mutation was NOT applied, so a pass below would"
    echo "          mean nothing. Re-anchor the mutation."
    return 1
  fi
  if ! go build -o /dev/null ./internal/... >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "K-A guard neutered, unclassified dimension seals" \
  ./internal/tbac/ "TestValidateIssuance_RefusesUnregisteredDimension" \
  internal/tbac/issuance.go \
  "func requireKind(dim, name string) error {
	if _, declared := kindOf(dim); declared {
		return nil
	}" \
  "func requireKind(dim, name string) error {
	if true {
		return nil
	}" || rc=1

run_mutation "K-B registry acquires a default" \
  ./internal/tbac/ "TestValidateIssuance_RefusesUnregisteredDimension" \
  internal/tbac/dimensions.go \
  "	k, ok := dimensionKind[dim]
	return k, ok" \
  "	k, ok := dimensionKind[dim]
	_ = ok
	return k, true" || rc=1

run_mutation "K-C classified execution-asserted but never projected" \
  ./internal/tbac/ "TestExecutionAssertedDimensionsAreProjectedByTxnScope" \
  internal/tbac/dimensions.go \
  "	\"action\": kindDelegationOnly," \
  "	\"action\": kindExecutionAsserted," || rc=1

# "tier" rather than "max": deleting "max" also breaks the accepts-the-vocabulary
# smoke test via its limits:{max:10} fixture, so the mutation would be killed by
# something other than the property K-D names.
run_mutation "K-D numeric dimension loses its kind" \
  ./internal/tbac/ "TestEveryNumericDimensionIsAlsoClassified" \
  internal/tbac/dimensions.go \
  "	\"tier\": kindDelegationOnly," \
  "" || rc=1

run_mutation "K-E kindOf answers by naming convention" \
  ./internal/tbac/ "TestKindOfIsALookupNotANamingConvention" \
  internal/tbac/dimensions.go \
  "	k, ok := dimensionKind[dim]
	return k, ok" \
  "	if len(dim) > 4 && dim[:4] == \"max_\" {
		return kindExecutionAsserted, true
	}
	k, ok := dimensionKind[dim]
	return k, ok" || rc=1

run_mutation "K-F guard narrowed to top-level dimensions" \
  ./internal/tbac/ "TestValidateIssuance_RefusesUnregisteredNestedDimension" \
  internal/tbac/issuance.go \
  "	if _, declared := kindOf(dim); declared {
		return nil
	}" \
  "	if _, declared := kindOf(dim); declared || name != dim {
		return nil
	}" || rc=1

run_mutation "K-G TxnScope projects a delegation-only dimension" \
  ./internal/tbac/ "TestTxnScopeProjectsOnlyRegisteredExecutionAssertedDimensions" \
  internal/tbac/scope.go \
  "	if _, ok := parent[\"currency\"]; ok {
		out[\"currency\"] = tc.Currency
	}" \
  "	if _, ok := parent[\"currency\"]; ok {
		out[\"currency\"] = tc.Currency
	}
	if _, ok := parent[\"jurisdiction\"]; ok {
		out[\"jurisdiction\"] = \"EU-DORA\"
	}" || rc=1

run_mutation "K-H list elements are not walked" \
  ./internal/tbac/ "TestValidateIssuance_WalksListElements" \
  internal/tbac/issuance.go \
  "		if items, ok := v.([]any); ok {" \
  "		if items, ok := v.([]any); ok && false {" || rc=1

run_mutation "K-I an unacknowledged entry is added" \
  ./internal/tbac/ "TestDimensionKindIsPinnedToAnExplicitSet" \
  internal/tbac/dimensions.go \
  "	\"tier\": kindDelegationOnly," \
  "	\"tier\":   kindDelegationOnly,
	\"banana\": kindDelegationOnly," || rc=1

echo
if [ "$rc" -eq 0 ]; then
  echo "All dimension-kind mutations killed."
else
  echo "At least one mutation survived or could not be applied. Read the lines above:"
  echo "a SURVIVED line is a bug in the test; a FAIL line is a bug in this script or"
  echo "in the tree it was run against."
fi
exit "$rc"
