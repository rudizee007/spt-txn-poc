package tbac

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

// A dimension whose kind nobody has decided cannot be sealed into a token: the
// registry has no default, so an unknown name has no classification to act on.
func TestValidateIssuance_RefusesUnregisteredDimension(t *testing.T) {
	s := Scope{"currency": "USD", "max_amount": json.Number("100"), "banana": "yes"}
	err := ValidateIssuance(s)
	if err == nil {
		t.Fatal("a scope carrying an unregistered dimension must not be issuable")
	}
	if !errors.Is(err, ErrUnregisteredDimension) {
		t.Errorf("err = %v, want ErrUnregisteredDimension", err)
	}
}

// Seeding is behaviour-neutral: the vocabulary already in use must still issue.
func TestValidateIssuance_AcceptsTheRegisteredVocabulary(t *testing.T) {
	s := Scope{
		"max_amount":   json.Number("5000"),
		"currency":     "USD",
		"action":       "payment",
		"tier":         json.Number("1"),
		"jurisdiction": "CIMA",
		"region":       map[string]any{"tier": json.Number("2")},
		"limits":       map[string]any{"max": json.Number("10")},
	}
	if err := ValidateIssuance(s); err != nil {
		t.Fatalf("the vocabulary in use must remain issuable, got: %v", err)
	}
}

// Nested dimensions are registered under their own leaf name, because containment
// and intersection recurse per dimension. A name used ONLY as an object container
// needs no entry, because validateIssuance recurses into it and classifies its
// members instead.
func TestDimensionKind_NestedResolvesByLeafName(t *testing.T) {
	if _, ok := kindOf("tier"); !ok {
		t.Fatal("tier must be registered; region.tier resolves to it")
	}
	if _, ok := kindOf("limits"); ok {
		t.Error("limits is only ever an object container and needs no kind of its own")
	}
	// A container whose members are classified must still be issuable.
	if err := ValidateIssuance(Scope{"limits": Scope{"max": 3}}); err != nil {
		t.Errorf("a classified container must be issuable: %v", err)
	}
}

// The registry must not acquire a default: an unknown name reports no kind.
func TestDimensionKind_HasNoDefault(t *testing.T) {
	if k, ok := kindOf("definitely-not-a-dimension"); ok {
		t.Errorf("an unknown dimension reported kind %v; there must be no default", k)
	}
}

// Every dimension registered execution-asserted must ACTUALLY be projected by
// TxnScope. This keeps the registry a statement about the code rather than about
// someone's intention.
func TestExecutionAssertedDimensionsAreProjectedByTxnScope(t *testing.T) {
	tc := ledger.TxnContext{Chain: "none", Originator: "a", Beneficiary: "b",
		Amount: "1", Currency: "USD", Timestamp: 1}
	for dim, k := range dimensionKind {
		if k != kindExecutionAsserted {
			continue
		}
		parent := Scope{"currency": "USD", dim: json.Number("100")}
		if dim == "currency" {
			parent = Scope{"currency": "USD"}
		}
		got, err := TxnScope(parent, tc)
		if err != nil {
			t.Fatalf("TxnScope(%q): %v", dim, err)
		}
		if _, projected := got[dim]; !projected {
			t.Errorf("%q is registered execution-asserted but TxnScope does not project it", dim)
		}
	}
}

// A numeric dimension needs both registries: a direction and a kind. One without
// the other is a half-classified dimension.
func TestEveryNumericDimensionIsAlsoClassified(t *testing.T) {
	for dim := range numericDirection {
		if _, ok := kindOf(dim); !ok {
			t.Errorf("%q has a numeric direction but no registered kind", dim)
		}
	}
}

// Money ceilings are validated in their own earlier pass and `continue` past the
// per-dimension sweep, so the kind check never sees them. Both entries are
// registered today; this asserts that a future addition to moneyCeilings cannot
// quietly acquire an exemption from classification by virtue of where it is
// validated.
func TestEveryMoneyCeilingIsAlsoClassified(t *testing.T) {
	for dim := range moneyCeilings {
		k, ok := kindOf(dim)
		if !ok {
			t.Errorf("%q is a money ceiling but has no registered kind; it skips the kind check in validateIssuance", dim)
			continue
		}
		if k != kindExecutionAsserted {
			t.Errorf("%q is a money ceiling registered %v; a ceiling TxnScope projects is execution-asserted", dim, k)
		}
	}
}
