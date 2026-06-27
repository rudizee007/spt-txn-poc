package ledger

import (
	"fmt"
	"strings"
)

// XDC is the XDC Network (XinFin) adapter. XDC is EVM-compatible (XDPoS), so the
// transfer shape mirrors Ethereum, with two differences: addresses are commonly
// written with an "xdc" prefix instead of "0x" (the underlying 20-byte value is
// identical), and the native coin is XDC. Selection is by TxnContext.Chain == "xdc".
//
// XDC's relevance to SPT-Txn is the ISO 20022 / trade-finance / RWA positioning:
// the Travel Rule attestation rides alongside an XRC-20 or native value transfer.
//
// Scope of this adapter (POC):
//   - Canonicalizes sender (originator), receiver (beneficiary), amount, and asset
//     ("XDC" or an XRC-20 token contract address). Addresses are "xdc"+40hex or
//     "0x"+40hex (20 bytes); checksum is not enforced (shape only).
//   - No transaction memo; the SPT-Txn attestation root anchors via an anchor
//     contract / event (the EVM Solidity anchor deploys on XDC too).
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage.
type XDC struct{}

func (XDC) Name() string { return "xdc" }

func (XDC) Validate(tc TxnContext) error {
	if !looksLikeXDCAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not an XDC address (xdc/0x + 40 hex, 20 bytes)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeXDCAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid XDC address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (XDC or an XRC-20 token contract address)")
	}
	if tc.Currency != "XDC" && !looksLikeXDCAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be XDC or an XRC-20 token contract address (xdc/0x…)", tc.Currency)
	}
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (XDC) Canonicalize(tc TxnContext) ([]byte, error) {
	// "xdc" chain tag in the preimage prevents collision with the Ethereum adapter
	// even though both accept 0x-hex addresses.
	return canonicalEncode([][2]string{
		{"chain", "xdc"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(XDC{}) }

// looksLikeXDCAddress accepts "xdc"/"0x" (case-insensitive) + exactly 40 hex
// chars. Reuses isHexStr from starknet.go.
func looksLikeXDCAddress(s string) bool {
	low := strings.ToLower(s)
	var h string
	switch {
	case strings.HasPrefix(low, "xdc"):
		h = s[3:]
	case strings.HasPrefix(low, "0x"):
		h = s[2:]
	default:
		return false
	}
	if len(h) != 40 {
		return false
	}
	return isHexStr(h)
}
