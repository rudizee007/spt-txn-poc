package sdjwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/sdjwt"
)

func issuerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func ivmsClaims() map[string]any {
	return map[string]any{
		"originator_name":    "Alice Smith",
		"originator_account": "rOriginatorWallet111111111111",
		"originator_country": "KY",
		"beneficiary_name":   "Bob Jones",
		"amount":             5000,
	}
}

func TestSelectiveDisclosure(t *testing.T) {
	pub, priv := issuerKey(t)
	combined, err := sdjwt.Issue("did:web:authorg", ivmsClaims(), priv, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Disclose only the two fields the counterparty is entitled to.
	pres, err := sdjwt.Present(combined, []string{"beneficiary_name", "originator_country"})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	got, err := sdjwt.Verify(pres, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["beneficiary_name"] != "Bob Jones" {
		t.Errorf("beneficiary_name = %v", got["beneficiary_name"])
	}
	if got["originator_country"] != "KY" {
		t.Errorf("originator_country = %v", got["originator_country"])
	}
	// Undisclosed fields must NOT be present.
	for _, hidden := range []string{"originator_name", "originator_account", "amount"} {
		if _, ok := got[hidden]; ok {
			t.Errorf("field %q must remain hidden but was disclosed", hidden)
		}
	}
}

func TestVerify_WrongIssuerKey(t *testing.T) {
	_, priv := issuerKey(t)
	otherPub, _ := issuerKey(t)
	combined, _ := sdjwt.Issue("did:web:authorg", ivmsClaims(), priv, time.Hour)
	pres, _ := sdjwt.Present(combined, []string{"beneficiary_name"})
	if _, err := sdjwt.Verify(pres, otherPub); err == nil {
		t.Error("verification under the wrong issuer key must fail")
	}
}

func TestVerify_ForgedDisclosureRejected(t *testing.T) {
	pub, priv := issuerKey(t)
	combined, _ := sdjwt.Issue("did:web:authorg", ivmsClaims(), priv, time.Hour)
	pres, _ := sdjwt.Present(combined, []string{"beneficiary_name"})

	// Forge an extra disclosure whose digest is not in the signed _sd set.
	forged, err := sdjwt.NewDisclosure("originator_account", "rATTACKER999999999999999999999")
	if err != nil {
		t.Fatal(err)
	}
	// Splice the forged disclosure in before the trailing '~'.
	tampered := strings.TrimSuffix(pres, "~") + "~" + forged.Encoded + "~"
	if _, err := sdjwt.Verify(tampered, pub); err == nil {
		t.Error("a disclosure not in the signed _sd set must be rejected")
	}
}

func TestVerify_Expired(t *testing.T) {
	pub, priv := issuerKey(t)
	combined, _ := sdjwt.Issue("did:web:authorg", ivmsClaims(), priv, -1*time.Second)
	pres, _ := sdjwt.Present(combined, []string{"beneficiary_name"})
	if _, err := sdjwt.Verify(pres, pub); err == nil {
		t.Error("expired SD-JWT must be rejected")
	}
}
