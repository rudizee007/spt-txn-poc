package verifier

// White-box tests for how a single-use record's lifetime is judged against the
// two clocks. scripts/mutate-record-clock.sh reverts each control and requires
// the named test to fail.

import (
	"testing"
	"time"
)

// TestRecordHeldWhileEitherClockIsLive: a record is pruned only once both its
// monotonic budget and its wall expiry have passed; while either is still in the
// future the record is held.
func TestRecordHeldWhileEitherClockIsLive(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	cases := []struct {
		name        string
		e           recordExpiry
		wantExpired bool
	}{
		{"both future", recordExpiry{mono: future, wall: future}, false},
		{"mono past, wall future", recordExpiry{mono: past, wall: future}, false},
		{"mono future, wall past", recordExpiry{mono: future, wall: past}, false},
		{"both past", recordExpiry{mono: past, wall: past}, true},
		{"no wall, mono future", recordExpiry{mono: future}, false},
		{"no wall, mono past", recordExpiry{mono: past}, true},
	}
	for _, c := range cases {
		if got := c.e.expired(now); got != c.wantExpired {
			t.Errorf("%s: expired=%v, want %v", c.name, got, c.wantExpired)
		}
	}
}

// TestConsumeAllHoldsARecordWhoseWallExpiryIsStillFuture: a record whose
// monotonic budget has been exhausted but whose wall expiry is still in the
// future is NOT pruned, and still refuses a second consume of the same key. The
// acceptance checks bound the artefact by that same wall expiry, so the record
// must outlast a spent monotonic budget for as long as the wall expiry says.
func TestConsumeAllHoldsARecordWhoseWallExpiryIsStillFuture(t *testing.T) {
	c := newReplayCache()
	key := txnRecord("j")
	// A monotonic budget already spent (negative ttl), but a wall expiry a minute out.
	if !c.consumeAll(consumption{key: key, ttl: -time.Second, wallExp: time.Now().Add(time.Minute)}) {
		t.Fatal("first consume refused")
	}
	if c.consumeAll(consumption{key: key, ttl: -time.Second, wallExp: time.Now().Add(time.Minute)}) {
		t.Fatal("a record still within its wall expiry was pruned and re-consumed")
	}
}

// TestConsumeOnAllowStampsTheArtefactWallExpiry: the token and slice records are
// stamped with the artefact's own signed expiry, so the record and the
// acceptance checks (step 2, step 6) share one wall bound.
func TestConsumeOnAllowStampsTheArtefactWallExpiry(t *testing.T) {
	e := &Engine{replay: newReplayCache()}
	exp := time.Now().Add(30 * time.Second).Unix()
	claims := map[string]any{"jti": "j", "exp": float64(exp)}
	if err := e.consumeOnAllow(roleGate, claims, nil); err != nil {
		t.Fatalf("consume refused: %v", err)
	}
	rec, ok := e.replay.seen[txnRecord("j")]
	if !ok {
		t.Fatal("no token record written")
	}
	if !rec.wall.Equal(time.Unix(exp, 0)) {
		t.Fatalf("token record wall expiry = %v, want the token's exp %v", rec.wall, time.Unix(exp, 0))
	}
}
