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

// Nested dimensions are registered under their own LEAF name, because containment
// and intersection recurse per dimension. Container names are registered too: a
// container is a dimension like any other, so "limits" needs its own entry and is
// not exempted by the fact that its members have theirs.
func TestDimensionKind_RegistersContainersAndResolvesNestedByLeafName(t *testing.T) {
	for _, dim := range []string{"tier", "limits", "region", "route"} {
		if _, ok := kindOf(dim); !ok {
			t.Errorf("%q must be registered", dim)
		}
	}
	// A container and its members both classified: issuable.
	if err := ValidateIssuance(Scope{"limits": Scope{"max": 3}}); err != nil {
		t.Errorf("a classified container must be issuable: %v", err)
	}
	// region.tier resolves to the "tier" entry, not to "region.tier".
	if err := ValidateIssuance(Scope{"region": Scope{"tier": json.Number("2")}}); err != nil {
		t.Errorf("a nested dimension must resolve by its leaf name: %v", err)
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

// The converse of TestExecutionAssertedDimensionsAreProjectedByTxnScope, and the
// half with teeth: whatever TxnScope projects MUST be registered
// kindExecutionAsserted. Without this, a projection added later silently makes a
// dimension enforced while the registry and SCOPE-DIMENSIONS.md §2 still tell a
// second implementation it is not — divergent evaluation of the same claim.
//
// The scope is seeded with every registered dimension AND every ledger.TxnContext
// field name, because a projection can only be derived from a TxnContext field, so
// those are the candidate names a new one would use.
func TestTxnScopeProjectsOnlyRegisteredExecutionAssertedDimensions(t *testing.T) {
	parent := Scope{"currency": "USD"}
	for dim := range dimensionKind {
		if dim == "currency" {
			continue
		}
		parent[dim] = json.Number("100")
	}
	for _, field := range []string{"chain", "originator", "beneficiary", "amount", "timestamp", "memo"} {
		if _, taken := parent[field]; !taken {
			parent[field] = json.Number("100")
		}
	}

	got, err := TxnScope(parent, ledger.TxnContext{Chain: "none", Originator: "a",
		Beneficiary: "b", Amount: "1", Currency: "USD", Timestamp: 1})
	if err != nil {
		t.Fatalf("TxnScope: %v", err)
	}
	for dim := range got {
		k, ok := kindOf(dim)
		if !ok {
			t.Errorf("TxnScope projects %q, which is not registered at all", dim)
			continue
		}
		if k != kindExecutionAsserted {
			t.Errorf("TxnScope projects %q but it is registered %v", dim, k)
		}
	}
}

// The registry must be a declaration, not a naming convention. A convention
// ("anything starting max_ is a ceiling") is the exact anti-pattern the package
// comment forbids, and it would let kindOf answer for dimensions nobody classified.
func TestKindOfIsALookupNotANamingConvention(t *testing.T) {
	for _, dim := range []string{
		"max_slippage", "max_banana", "max_", "currency_code",
		"action_kind", "tier_two", "region_name", "definitely-not-a-dimension",
	} {
		if k, ok := kindOf(dim); ok {
			t.Errorf("kindOf(%q) = %v, true — an unregistered name must have no kind", dim, k)
		}
	}
}

// An unregistered dimension nested inside a container is still unregistered. This
// defends against the guard being narrowed to top-level dimensions only.
func TestValidateIssuance_RefusesUnregisteredNestedDimension(t *testing.T) {
	err := ValidateIssuance(Scope{"limits": map[string]any{"banana": "yes"}})
	if !errors.Is(err, ErrUnregisteredDimension) {
		t.Errorf("err = %v, want ErrUnregisteredDimension for a nested unregistered dimension", err)
	}
}

// A container name is itself a dimension: Contains evaluates it, and a child
// dropping the whole object drops the constraint. An EMPTY container is the case
// that has no members to classify in its place, so it is the one that would slip
// through a check placed after the recursion.
func TestValidateIssuance_RefusesUnregisteredContainerIncludingEmpty(t *testing.T) {
	for name, s := range map[string]Scope{
		"empty container":     {"banana": map[string]any{}},
		"nested empty":        {"banana": map[string]any{"kiwi": map[string]any{}}},
		"alongside valid":     {"currency": "USD", "max_amount": json.Number("100"), "evil": map[string]any{}},
		"populated container": {"banana": map[string]any{"tier": json.Number("1")}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIssuance(s); !errors.Is(err, ErrUnregisteredDimension) {
				t.Errorf("err = %v, want ErrUnregisteredDimension", err)
			}
		})
	}
}
