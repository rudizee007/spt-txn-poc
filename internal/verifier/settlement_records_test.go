package verifier_test

// End to end: on one engine serving both roles, a settler's record of a token
// does not occupy the gate's record of it, and vice versa; each role stays
// single-use within its own kind. scripts/mutate-settlement-records.sh requires
// these to fail under the matching mutation.

import (
	"context"
	"testing"
)

// TestSingleUse_GateAndSettlerDoNotShareARecord: the gate and a settler record
// a token's use independently, so on one engine a presentation at one role
// leaves the other role's presentation allowed, in either order.
func TestSingleUse_GateAndSettlerDoNotShareARecord(t *testing.T) {
	t.Run("settle then gate", func(t *testing.T) {
		h := build(t)
		if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); !d.Allow {
			t.Fatalf("settle refused a good chain: step %d %s", d.Step, d.Reason)
		}
		if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
			t.Fatalf("gate refused after a prior settlement; the roles must record independently: step %d %s", d.Step, d.Reason)
		}
	})
	t.Run("gate then settle", func(t *testing.T) {
		h := build(t)
		if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
			t.Fatalf("gate refused a good chain: step %d %s", d.Step, d.Reason)
		}
		if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); !d.Allow {
			t.Fatalf("settle refused after a prior gate presentation; the roles must record independently: step %d %s", d.Step, d.Reason)
		}
	})
	t.Run("slice: settle then gate", func(t *testing.T) {
		w := buildBudgetWorld(t, true)
		slices := w.slices(t)
		if _, d := w.eng.VerifyForSettlement(context.Background(), w.mintTxn(t, slices[0].Token, "10")); !d.Allow {
			t.Fatalf("settle refused a live slice: step %d %s", d.Step, d.Reason)
		}
		if d := w.eng.Verify(context.Background(), w.mintTxn(t, slices[0].Token, "10")); !d.Allow {
			t.Fatalf("gate refused a slice after a prior settlement; the roles must record independently: step %d %s", d.Step, d.Reason)
		}
	})
}

// TestSingleUse_SettlerRoleStaysSingleUse: within the settler role, a token and
// its slice are still consumed once — the split of kinds must not weaken that.
func TestSingleUse_SettlerRoleStaysSingleUse(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		h := build(t)
		if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); !d.Allow {
			t.Fatalf("first settlement refused: %v", d)
		}
		if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); d.Allow {
			t.Fatal("the same token was settled twice")
		}
	})
	t.Run("slice", func(t *testing.T) {
		w := buildBudgetWorld(t, true)
		slices := w.slices(t)
		if _, d := w.eng.VerifyForSettlement(context.Background(), w.mintTxn(t, slices[0].Token, "10")); !d.Allow {
			t.Fatalf("first slice settlement refused: %v", d)
		}
		if _, d := w.eng.VerifyForSettlement(context.Background(), w.mintTxn(t, slices[0].Token, "10")); d.Allow {
			t.Fatal("the same slice was settled twice")
		}
	})
}
