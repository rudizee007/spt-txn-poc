package ivms101_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ivms101"
)

func sample() ivms101.IdentityPayload {
	return ivms101.IdentityPayload{
		Originator: ivms101.Originator{
			OriginatorPersons: []ivms101.Person{ivms101.PersonOf("Smith", "Alice", "KY",
				&ivms101.NationalIdentification{NationalIdentifier: "P1234567", NationalIdentifierType: ivms101.IDPassport, CountryOfIssue: "KY"})},
			AccountNumber: []string{"rAliceWallet"},
		},
		Beneficiary: ivms101.Beneficiary{
			BeneficiaryPersons: []ivms101.Person{ivms101.PersonOf("Jones", "Bob", "US", nil)},
			AccountNumber:      []string{"rBobWallet"},
		},
	}
}

func TestValidate_OK(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
}

func TestValidate_FATFMinimums(t *testing.T) {
	noAcct := sample()
	noAcct.Originator.AccountNumber = nil
	if err := noAcct.Validate(); err == nil {
		t.Error("missing originator account must be rejected")
	}

	noName := sample()
	noName.Beneficiary.BeneficiaryPersons = []ivms101.Person{ivms101.PersonOf("", "", "US", nil)}
	if err := noName.Validate(); err == nil {
		t.Error("missing beneficiary primaryIdentifier must be rejected")
	}

	noExtra := sample()
	noExtra.Originator.OriginatorPersons = []ivms101.Person{ivms101.PersonOf("Smith", "Alice", "", nil)} // no country/natId/dob
	if err := noExtra.Validate(); err == nil {
		t.Error("originator with none of country/natID/DOB must be rejected")
	}
}

func TestFlatten_FieldGranular(t *testing.T) {
	flat := sample().Flatten()

	want := map[string]string{
		"originator.name.primary":   "Smith",
		"originator.name.secondary": "Alice",
		"originator.name.type":      "LEGL",
		"originator.country":        "KY",
		"originator.natId.id":       "P1234567",
		"originator.natId.type":     "CCPT",
		"originator.natId.country":  "KY",
		"originator.account":        "rAliceWallet",
		"beneficiary.name.primary":  "Jones",
		"beneficiary.account":       "rBobWallet",
	}
	for k, v := range want {
		if flat[k] != v {
			t.Errorf("flat[%q] = %v, want %v", k, flat[k], v)
		}
	}
	// Absent fields are not disclosable (beneficiary has no national ID).
	for _, absent := range []string{"beneficiary.natId.id", "beneficiary.dob.date"} {
		if _, ok := flat[absent]; ok {
			t.Errorf("absent field %q must not be emitted", absent)
		}
	}
}
