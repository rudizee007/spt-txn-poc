package tbac_test

import (
	"encoding/json"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

func TestContains_EqualScope(t *testing.T) {
	parent := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	child := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("equal scope should be contained: %v", err)
	}
}

func TestContains_Subset(t *testing.T) {
	parent := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	// Child omits currency (more restrictive) and lowers the ceiling.
	child := tbac.Scope{"action": "payment", "max_amount": 5000}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("subset scope should be contained: %v", err)
	}
}

func TestContains_NumericOverCeiling(t *testing.T) {
	parent := tbac.Scope{"max_amount": 10000}
	child := tbac.Scope{"max_amount": 10001}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("child exceeding numeric ceiling must be rejected")
	}
}

func TestContains_DimensionNotInParent(t *testing.T) {
	parent := tbac.Scope{"action": "payment"}
	child := tbac.Scope{"action": "payment", "refund": true}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("child requesting a dimension absent from parent must be rejected")
	}
}

func TestContains_StringMismatch(t *testing.T) {
	parent := tbac.Scope{"currency": "USD"}
	child := tbac.Scope{"currency": "EUR"}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("disjoint string value must be rejected")
	}
}

func TestContains_ListSubset(t *testing.T) {
	parent := tbac.Scope{"methods": []any{"ach", "wire", "card"}}
	ok := tbac.Scope{"methods": []any{"ach", "wire"}}
	if err := tbac.Contains(parent, ok); err != nil {
		t.Errorf("list subset should be contained: %v", err)
	}
	bad := tbac.Scope{"methods": []any{"ach", "crypto"}}
	if err := tbac.Contains(parent, bad); err == nil {
		t.Error("list with an element absent from parent must be rejected")
	}
}

// TestContains_JSONRoundtrip ensures containment holds after a token round-trips
// through JSON (all numbers become float64), which is how parent scope arrives
// at the downstream issuer.
func TestContains_JSONRoundtrip(t *testing.T) {
	original := tbac.Scope{"max_amount": 10000, "currency": "USD"}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var parent tbac.Scope
	if err := json.Unmarshal(b, &parent); err != nil {
		t.Fatal(err)
	}
	child := tbac.Scope{"max_amount": 7500, "currency": "USD"}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("containment must survive JSON roundtrip: %v", err)
	}
}

// TestContains_LargeAmountPrecision: 2^53 and 2^53+1 are indistinguishable as
// float64; the exact big.Rat comparison must still reject the over-by-one value.
func TestContains_LargeAmountPrecision(t *testing.T) {
	parent := tbac.Scope{"max_amount": json.Number("9007199254740992")}    // 2^53
	overByOne := tbac.Scope{"max_amount": json.Number("9007199254740993")} // 2^53 + 1
	if err := tbac.Contains(parent, overByOne); err == nil {
		t.Error("amount exceeding the ceiling by 1 (beyond float64 precision) must be rejected")
	}
	exact := tbac.Scope{"max_amount": json.Number("9007199254740992")}
	if err := tbac.Contains(parent, exact); err != nil {
		t.Errorf("an equal large amount must be contained: %v", err)
	}
}

func TestAttenuate_ReturnsIndependentCopy(t *testing.T) {
	parent := tbac.Scope{"max_amount": 10000}
	req := tbac.Scope{"max_amount": 5000}
	out, err := tbac.Attenuate(parent, req)
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	out["max_amount"] = 999999 // mutate the returned copy
	if v, _ := req["max_amount"].(int); v != 5000 {
		t.Error("Attenuate must return an independent copy, not alias the request")
	}
}
