package ledger

import (
	"fmt"
	"strings"
)

// XRPL is the XRP Ledger adapter. It binds an SPT-Txn Token to a specific XRPL
// Payment without the core token packages ever importing it — selection is by
// TxnContext.Chain == "xrpl".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of an XRPL Payment: Account (originator),
//     Destination (beneficiary), Amount, Currency, and optional DestinationTag.
//   - Optionally references the on-ledger identity anchor introduced by the
//     XRPL Credentials amendment (activated 2025-09-04) and the DID standard,
//     carried in Extra under "credential" and/or "did". This is how the
//     off-ledger SPT-Txn attestation links to XRPL's native, privacy-preserving
//     KYC layer — complementing it, not duplicating it.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission and on-ledger verification belong to
// a separate client outside the authorization core.
type XRPL struct{}

func (XRPL) Name() string { return "xrpl" }

func (XRPL) Validate(tc TxnContext) error {
	if !looksLikeXRPLAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a classic r-address or X-address", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeXRPLAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid XRPL address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (XRP, or an issued-currency code)")
	}
	// DestinationTag, when present, must be a non-negative integer string.
	if tag, ok := tc.Extra["DestinationTag"]; ok && !isUint32(tag) {
		return fmt.Errorf("DestinationTag %q must be a uint32", tag)
	}
	return nil
}

func (XRPL) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the signed fields of an XRPL Payment that the
	// authorization is meant to bind. Keeping it explicit (not reflection)
	// makes the binding auditable.
	return canonicalEncode([][2]string{
		{"chain", "xrpl"},
		{"TransactionType", "Payment"},
		{"Account", tc.Originator},
		{"Destination", tc.Beneficiary},
		{"Amount", tc.Amount},
		{"Currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(XRPL{}) }

// ── helpers (shape checks only; no base58 checksum validation in POC) ────────

func looksLikeXRPLAddress(s string) bool {
	if strings.HasPrefix(s, "r") && len(s) >= 25 && len(s) <= 35 {
		return true // classic address
	}
	if strings.HasPrefix(s, "X") && len(s) >= 25 {
		return true // X-address (address + tag)
	}
	return false
}

func isUint32(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) <= 10 // up to 4294967295
}
