package ledger

import "fmt"

// Generic is the chain-neutral default adapter, registered as "none". It binds
// an SPT-Txn Token to a transfer described purely in TxnContext's common
// fields, with no chain-specific semantics. Use it for off-ledger or
// chain-undecided flows, and as the reference for what every adapter must do.
type Generic struct{}

func (Generic) Name() string { return "none" }

func (Generic) Validate(tc TxnContext) error {
	if tc.Beneficiary == "" {
		return fmt.Errorf("beneficiary required")
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required")
	}
	return nil
}

func (Generic) Canonicalize(tc TxnContext) ([]byte, error) {
	return canonicalEncode([][2]string{
		{"chain", "none"},
		{"originator", tc.Originator},
		{"beneficiary", tc.Beneficiary},
		{"amount", tc.Amount},
		{"currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Generic{}) }
