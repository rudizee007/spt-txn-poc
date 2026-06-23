// Package ivms101 implements a FATF-aligned subset of the interVASP Messaging
// Standard 101 (IVMS101) — the data model TRISA and TRP use for Travel Rule
// payloads. Structuring SPT-Txn's originator/beneficiary identity per IVMS101 is
// what lets the privacy-preserving (SD-JWT + ZK) layer interoperate with existing
// Travel Rule networks rather than inventing a parallel schema.
//
// Scope (POC): natural-person identity with the FATF Recommendation 16 required
// elements — name, account number, and at least one of country/national-ID/DOB —
// plus a selective-disclosure flattening so individual fields can be revealed or
// hidden in the SD-JWT. Legal persons, full geographic addresses, and phonetic/
// local name representations are stubbed for now.
package ivms101

import "fmt"

// NameIdentifierType per IVMS101 (subset).
type NameIdentifierType string

const (
	NameLegal  NameIdentifierType = "LEGL" // legal name
	NameBirth  NameIdentifierType = "BIRT" // name at birth
	NameMaiden NameIdentifierType = "MAID" // maiden name
	NameAlias  NameIdentifierType = "ALIA" // alias
)

// NationalIdentifierType per IVMS101 (subset).
type NationalIdentifierType string

const (
	IDPassport NationalIdentifierType = "CCPT" // passport
	IDNational NationalIdentifierType = "NIDN" // national identity number
	IDDriver   NationalIdentifierType = "DRLC" // driver's license
	IDTax      NationalIdentifierType = "TXID" // tax identification number
	IDLEI      NationalIdentifierType = "LEIX" // legal entity identifier
)

// NaturalPersonNameID is one name representation (IVMS101 naturalPersonNameId).
type NaturalPersonNameID struct {
	PrimaryIdentifier   string             `json:"primaryIdentifier"`             // surname / family name
	SecondaryIdentifier string             `json:"secondaryIdentifier,omitempty"` // given names
	NameIdentifierType  NameIdentifierType `json:"nameIdentifierType"`
}

// NationalIdentification (IVMS101 nationalIdentification).
type NationalIdentification struct {
	NationalIdentifier     string                 `json:"nationalIdentifier"`
	NationalIdentifierType NationalIdentifierType `json:"nationalIdentifierType"`
	CountryOfIssue         string                 `json:"countryOfIssue,omitempty"`
}

// DateAndPlaceOfBirth (IVMS101 dateAndPlaceOfBirth).
type DateAndPlaceOfBirth struct {
	DateOfBirth  string `json:"dateOfBirth"` // YYYY-MM-DD
	PlaceOfBirth string `json:"placeOfBirth"`
}

// NaturalPerson (IVMS101 naturalPerson, subset).
type NaturalPerson struct {
	Name                   []NaturalPersonNameID   `json:"name"`
	CountryOfResidence     string                  `json:"countryOfResidence,omitempty"`
	NationalIdentification *NationalIdentification `json:"nationalIdentification,omitempty"`
	DateAndPlaceOfBirth    *DateAndPlaceOfBirth    `json:"dateAndPlaceOfBirth,omitempty"`
	CustomerIdentification string                  `json:"customerIdentification,omitempty"`
}

// Person is a natural or legal person (legal stubbed for the POC).
type Person struct {
	NaturalPerson *NaturalPerson `json:"naturalPerson,omitempty"`
}

// Originator (IVMS101 originator).
type Originator struct {
	OriginatorPersons []Person `json:"originatorPersons"`
	AccountNumber     []string `json:"accountNumber,omitempty"`
}

// Beneficiary (IVMS101 beneficiary).
type Beneficiary struct {
	BeneficiaryPersons []Person `json:"beneficiaryPersons"`
	AccountNumber      []string `json:"accountNumber,omitempty"`
}

// IdentityPayload is the IVMS101 originator + beneficiary message.
type IdentityPayload struct {
	Originator  Originator  `json:"originator"`
	Beneficiary Beneficiary `json:"beneficiary"`
}

// PersonOf is a convenience constructor for a natural person with a legal name.
func PersonOf(primary, secondary, country string, natID *NationalIdentification) Person {
	return Person{NaturalPerson: &NaturalPerson{
		Name:                   []NaturalPersonNameID{{PrimaryIdentifier: primary, SecondaryIdentifier: secondary, NameIdentifierType: NameLegal}},
		CountryOfResidence:     country,
		NationalIdentification: natID,
	}}
}

// Flatten projects the IVMS101 payload onto dotted-path claim keys for
// selective disclosure in the SD-JWT (e.g. "beneficiary.name.primary"). Only
// present fields are emitted, so absent fields are simply not disclosable. Uses
// the first natural person on each side (POC simplification).
func (p IdentityPayload) Flatten() map[string]any {
	out := map[string]any{}
	flattenSide(out, "originator", firstNatural(p.Originator.OriginatorPersons), p.Originator.AccountNumber)
	flattenSide(out, "beneficiary", firstNatural(p.Beneficiary.BeneficiaryPersons), p.Beneficiary.AccountNumber)
	return out
}

// Validate enforces the FATF Recommendation 16 minimum data set.
func (p IdentityPayload) Validate() error {
	o := firstNatural(p.Originator.OriginatorPersons)
	if o == nil || len(o.Name) == 0 || o.Name[0].PrimaryIdentifier == "" {
		return fmt.Errorf("ivms101: originator name (primaryIdentifier) required")
	}
	if firstAccount(p.Originator.AccountNumber) == "" {
		return fmt.Errorf("ivms101: originator accountNumber required")
	}
	// FATF: originator needs at least one of address / national-ID / DOB.
	if o.CountryOfResidence == "" && o.NationalIdentification == nil && o.DateAndPlaceOfBirth == nil {
		return fmt.Errorf("ivms101: originator needs one of countryOfResidence / nationalIdentification / dateAndPlaceOfBirth")
	}
	b := firstNatural(p.Beneficiary.BeneficiaryPersons)
	if b == nil || len(b.Name) == 0 || b.Name[0].PrimaryIdentifier == "" {
		return fmt.Errorf("ivms101: beneficiary name (primaryIdentifier) required")
	}
	if firstAccount(p.Beneficiary.AccountNumber) == "" {
		return fmt.Errorf("ivms101: beneficiary accountNumber required")
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func firstNatural(ps []Person) *NaturalPerson {
	for _, x := range ps {
		if x.NaturalPerson != nil {
			return x.NaturalPerson
		}
	}
	return nil
}

func firstAccount(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

func flattenSide(out map[string]any, side string, np *NaturalPerson, accounts []string) {
	if np != nil {
		if len(np.Name) > 0 {
			n := np.Name[0]
			set(out, side+".name.primary", n.PrimaryIdentifier)
			set(out, side+".name.secondary", n.SecondaryIdentifier)
			set(out, side+".name.type", string(n.NameIdentifierType))
		}
		set(out, side+".country", np.CountryOfResidence)
		if id := np.NationalIdentification; id != nil {
			set(out, side+".natId.id", id.NationalIdentifier)
			set(out, side+".natId.type", string(id.NationalIdentifierType))
			set(out, side+".natId.country", id.CountryOfIssue)
		}
		if dob := np.DateAndPlaceOfBirth; dob != nil {
			set(out, side+".dob.date", dob.DateOfBirth)
			set(out, side+".dob.place", dob.PlaceOfBirth)
		}
	}
	set(out, side+".account", firstAccount(accounts))
}

func set(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}
