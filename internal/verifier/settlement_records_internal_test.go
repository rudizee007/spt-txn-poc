package verifier

// White-box tests that the gate and a settler record a token's use under
// different kinds, and that consumeOnAllow refuses a caller that names no role.
// scripts/mutate-settlement-records.sh reverts each control and requires the
// named test to fail.

import (
	"testing"
	"testing/quick"
	"time"
)

// TestGateAndSettlerRecordKindsAreDisjoint: a settler's record of a token or
// slice is never equal to the gate's record of the same token or slice, and
// neither equals the others.
func TestGateAndSettlerRecordKindsAreDisjoint(t *testing.T) {
	prop := func(jti, root string, leg int64) bool {
		return settleTxnRecord(jti) != txnRecord(jti) &&
			settleSliceRecord(root, leg) != sliceRecord(root, leg) &&
			settleTxnRecord(jti) != settleSliceRecord(root, leg) &&
			settleTxnRecord(jti) != proofRecord(root, jti) &&
			settleSliceRecord(root, leg) != txnRecord(jti)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "0", "id", "id-1"} {
		if settleTxnRecord(v) == txnRecord(v) || settleSliceRecord(v, 0) == sliceRecord(v, 0) {
			t.Fatalf("a settler record equals the gate record for identifier %q", v)
		}
	}
}

// claimsWithJTIExp is the part of an SPT-Txn's claims consumeOnAllow reads.
func claimsWithJTIExp(jti string) map[string]any {
	return map[string]any{"jti": jti, "exp": float64(time.Now().Add(time.Minute).Unix())}
}

// TestConsumeOnAllowRefusesRoleNone: a caller that names no enforcement point
// records nothing and is refused. Deny-by-default for the record's role.
func TestConsumeOnAllowRefusesRoleNone(t *testing.T) {
	e := &Engine{replay: newReplayCache()}
	if err := e.consumeOnAllow(roleNone, claimsWithJTIExp("j"), nil); err == nil {
		t.Fatal("consumeOnAllow recorded a use for a caller that named no role")
	}
	if n := len(e.replay.seen); n != 0 {
		t.Fatalf("a refused role-less consume left %d record(s)", n)
	}
}

// TestConsumeOnAllowRoleUsesTheMatchingKind: the gate role records under
// recordTxn, the settler role under recordSettleTxn, and they do not interfere.
func TestConsumeOnAllowRoleUsesTheMatchingKind(t *testing.T) {
	e := &Engine{replay: newReplayCache()}
	if err := e.consumeOnAllow(roleGate, claimsWithJTIExp("j"), nil); err != nil {
		t.Fatalf("gate consume refused: %v", err)
	}
	// The settler role for the same jti is a different record, so it is allowed.
	if err := e.consumeOnAllow(roleSettle, claimsWithJTIExp("j"), nil); err != nil {
		t.Fatalf("settler consume was blocked by the gate's record: %v", err)
	}
	if _, ok := e.replay.seen[txnRecord("j")]; !ok {
		t.Fatal("gate did not record under recordTxn")
	}
	if _, ok := e.replay.seen[settleTxnRecord("j")]; !ok {
		t.Fatal("settler did not record under recordSettleTxn")
	}
	// Each role is still single-use within its own kind.
	if err := e.consumeOnAllow(roleGate, claimsWithJTIExp("j"), nil); err == nil {
		t.Fatal("the gate recorded the same token twice")
	}
	if err := e.consumeOnAllow(roleSettle, claimsWithJTIExp("j"), nil); err == nil {
		t.Fatal("the settler recorded the same token twice")
	}
}
