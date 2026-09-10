package cattoken_test

import (
	"errors"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// The kind registry must hold at a real seal path, not only in tbac's own tests.
// Every guard in ValidateIssuance is worth what its weakest caller is worth, and
// nothing previously asserted that this caller consults it at all: narrowing the
// tbac.ValidateIssuance call here to a money-ceilings-only helper left tbac's suite
// and its mutation script entirely green.
func TestIssue_RefusesUnregisteredScopeDimension(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	for name, scope := range map[string]cattoken.CapabilityScope{
		"unregistered leaf":          {"action": "transfer", "banana": "yes"},
		"unregistered empty object":  {"action": "transfer", "banana": map[string]any{}},
		"unregistered nested leaf":   {"action": "transfer", "limits": map[string]any{"banana": "yes"}},
		"unregistered inside a list": {"action": "transfer", "actions": []any{map[string]any{"banana": "yes"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cattoken.Issue(cattoken.IssueRequest{
				Issuer:             "domain-a.authorg",
				Subject:            "alice",
				PrincipalName:      "alice",
				Scope:              scope,
				DelegationDepthMax: 3,
				TTL:                time.Hour,
				HolderPublicKey:    holderPub,
			}, issuerPriv)
			if err == nil {
				t.Fatal("a CAT carrying an unclassified scope dimension was issued")
			}
			if !errors.Is(err, tbac.ErrUnregisteredDimension) {
				t.Errorf("want ErrUnregisteredDimension through the seal path, got: %v", err)
			}
		})
	}
}

// And it must not over-deny: the registered vocabulary still issues.
func TestIssue_AcceptsRegisteredScopeDimensions(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	_, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             "domain-a.authorg",
		Subject:            "alice",
		PrincipalName:      "alice",
		Scope:              cattoken.CapabilityScope{"action": "transfer", "max_amount": 10000, "currency": "USD", "methods": []any{"ach"}},
		DelegationDepthMax: 3,
		TTL:                time.Hour,
		HolderPublicKey:    holderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("the registered vocabulary must still issue: %v", err)
	}
}
