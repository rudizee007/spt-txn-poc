package ledger

import (
	"fmt"
)

// Algorand is the Algorand (AVM) adapter. Algorand is non-EVM: addresses are
// 58-character base32 strings (a 32-byte public key + 4-byte checksum), the
// native unit is ALGO, and other assets are Algorand Standard Assets (ASAs)
// identified by an integer asset ID. Selection is by TxnContext.Chain == "algorand".
//
// Algorand's native transaction "note" field (up to ~1 KB) carries the SPT-Txn
// attestation root for anchoring (analogous to the Solana SPL memo). ASA freeze
// /clawback and did:algo are the chain-native compliance primitives the Travel
// Rule attestation complements.
//
// Scope of this adapter (POC):
//   - Canonicalizes sender (originator), receiver (beneficiary), amount, and asset
//     ("ALGO" or a numeric ASA ID). Addresses are checked for shape only (length
//     58, base32 alphabet) — no checksum verification in the POC.
//   - Optional anchor_hash (32-byte root, 64 hex) carried in the note field.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage.
type Algorand struct{}

func (Algorand) Name() string { return "algorand" }

func (Algorand) Validate(tc TxnContext) error {
	if !looksLikeAlgorandAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not an Algorand address (58-char base32)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeAlgorandAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Algorand address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (ALGO or a numeric ASA asset ID)")
	}
	if tc.Currency != "ALGO" && !isASAID(tc.Currency) {
		return fmt.Errorf("currency %q must be ALGO or a numeric ASA asset ID", tc.Currency)
	}
	// Optional on-chain anchor carried in the note field: a 32-byte root (64 hex).
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Algorand) Canonicalize(tc TxnContext) ([]byte, error) {
	return canonicalEncode([][2]string{
		{"chain", "algorand"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"asset", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Algorand{}) }

// ── helpers (shape checks only) ──────────────────────────────────────────────

// looksLikeAlgorandAddress accepts a 58-character string in the base32 alphabet
// (A–Z and 2–7). A real address is base32(pubkey||checksum); the POC checks
// length and alphabet, not the checksum.
func looksLikeAlgorandAddress(s string) bool {
	if len(s) != 58 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}

// isASAID reports whether s is a positive integer Algorand asset ID (no leading
// zero, all digits, not "0").
func isASAID(s string) bool {
	if s == "" || s == "0" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
