package tbac

import "testing"

// Values are float64 to mirror the JSON-decoded scopes the issuer bridges pass.

func TestIntersect_NumericNarrower(t *testing.T) {
	permitted := Scope{"max_amount": float64(10000)}
	got, err := Intersect(permitted, Scope{"max_amount": float64(5000)})
	if err != nil {
		t.Fatal(err)
	}
	if got["max_amount"] != float64(5000) {
		t.Fatalf("max_amount = %v, want 5000", got["max_amount"])
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatalf("result not contained in permitted: %v", err)
	}
}

func TestIntersect_NumericWiderClamped(t *testing.T) {
	permitted := Scope{"max_amount": float64(10000)}
	got, err := Intersect(permitted, Scope{"max_amount": float64(1e9)})
	if err != nil {
		t.Fatal(err)
	}
	if got["max_amount"] != float64(10000) {
		t.Fatalf("SECURITY: request above ceiling not clamped: %v", got["max_amount"])
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatal(err)
	}
}

// The critical root-issuance property: a request that omits a permitted ceiling
// must NOT drop it — the root has no ancestor to inherit it from.
func TestIntersect_DroppedCeilingStillAsserted(t *testing.T) {
	permitted := Scope{"action": "transfer", "max_amount": float64(10000), "currency": "USD"}
	got, err := Intersect(permitted, Scope{"action": "transfer"})
	if err != nil {
		t.Fatal(err)
	}
	if got["max_amount"] != float64(10000) {
		t.Fatal("SECURITY: root dropped the max_amount ceiling")
	}
	if got["currency"] != "USD" {
		t.Fatal("SECURITY: root dropped the currency constraint")
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatal(err)
	}
}

func TestIntersect_UnpermittedDimensionRejected(t *testing.T) {
	permitted := Scope{"action": "transfer"}
	if _, err := Intersect(permitted, Scope{"action": "transfer", "admin": true}); err == nil {
		t.Fatal("SECURITY: request introduced an unpermitted dimension without error")
	}
}

func TestIntersect_StringConflictRejected(t *testing.T) {
	permitted := Scope{"currency": "USD"}
	if _, err := Intersect(permitted, Scope{"currency": "EUR"}); err == nil {
		t.Fatal("want error for a currency the policy does not permit")
	}
}

func TestIntersect_ListSetIntersection(t *testing.T) {
	permitted := Scope{"methods": []any{"read", "write", "list"}}
	got, err := Intersect(permitted, Scope{"methods": []any{"write", "list", "delete"}})
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := got["methods"].([]any)
	if len(ms) != 2 {
		t.Fatalf("methods = %v, want the 2-element intersection", ms)
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatalf("list result not a subset of permitted: %v", err)
	}
}

func TestIntersect_NestedObjectNarrowed(t *testing.T) {
	permitted := Scope{"limits": map[string]any{"max": float64(100), "currency": "USD"}}
	got, err := Intersect(permitted, Scope{"limits": map[string]any{"max": float64(50)}})
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := got["limits"].(map[string]any)
	if inner["max"] != float64(50) {
		t.Fatalf("nested max not narrowed: %v", inner)
	}
	if inner["currency"] != "USD" {
		t.Fatal("nested currency ceiling dropped")
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatal(err)
	}
}

// Omitting the request entirely yields exactly the permitted ceiling.
func TestIntersect_EmptyRequestYieldsCeiling(t *testing.T) {
	permitted := Scope{"action": "transfer", "max_amount": float64(10000)}
	got, err := Intersect(permitted, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if got["action"] != "transfer" || got["max_amount"] != float64(10000) {
		t.Fatalf("empty request should yield the full ceiling, got %v", got)
	}
}
