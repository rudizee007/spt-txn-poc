package ledger

import (
	"fmt"
	"strings"
)

// Stellar is the Stellar adapter. It binds an SPT-Txn Token to a specific Stellar
// payment (native XLM or an issued asset) without the core token packages ever
// importing it — selection is by TxnContext.Chain == "stellar".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Stellar Payment: source (originator),
//     destination (beneficiary), amount, asset ("XLM" or an asset code), and an
//     optional memo. Accounts are StrKey Ed25519 public keys ("G…", 56 chars) or
//     muxed accounts ("M…", 69 chars).
//   - Stellar's anchor model + SEP-31 (cross-border payments between anchors) is
//     the VASP-to-VASP Travel Rule corridor; the SPT-Txn attestation rides as the
//     payload, and its 32-byte hash anchors cleanly in a Stellar MEMO_HASH.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission and on-chain anchoring (a MEMO_HASH
// payment, or SEP-31 integration) belong to a separate client outside the
// authorization core (grant work).
type Stellar struct{}

func (Stellar) Name() string { return "stellar" }

func (Stellar) Validate(tc TxnContext) error {
	if !looksLikeStellarAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a Stellar account (G… 56 / M… 69, StrKey base32)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeStellarAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Stellar account", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (XLM, or an issued-asset code)")
	}
	if tc.Currency != "XLM" && !isAssetCode(tc.Currency) {
		return fmt.Errorf("asset code %q must be 1–12 alphanumeric chars", tc.Currency)
	}
	// A Stellar text memo (MEMO_TEXT) is capped at 28 bytes; a MEMO_HASH is 32
	// bytes (64 hex). Validate whichever is present.
	if memo, ok := tc.Extra["memo"]; ok && len(memo) > 28 {
		return fmt.Errorf("memo (MEMO_TEXT) exceeds the 28-byte Stellar limit (%d bytes)", len(memo))
	}
	if mh, ok := tc.Extra["memo_hash"]; ok && !isHex64(mh) {
		return fmt.Errorf("memo_hash (MEMO_HASH) must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Stellar) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the Payment fields the authorization binds.
	// Explicit (not reflection) keeps the binding auditable, and identical bytes
	// on any host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "stellar"},
		{"TransactionType", "Payment"},
		{"source", tc.Originator},
		{"destination", tc.Beneficiary},
		{"amount", tc.Amount},
		{"asset", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Stellar{}) }

// ── helpers (shape checks only; no StrKey CRC/curve validation in POC) ───────

// looksLikeStellarAddress accepts a StrKey account public key ("G" + 56 base32)
// or a muxed account ("M" + 69 base32). Shape only.
func looksLikeStellarAddress(s string) bool {
	if strings.HasPrefix(s, "G") && len(s) == 56 {
		return isBase32(s)
	}
	if strings.HasPrefix(s, "M") && len(s) == 69 {
		return isBase32(s)
	}
	return false
}

func isBase32(s string) bool {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}
	return true
}

func isAssetCode(s string) bool {
	if len(s) < 1 || len(s) > 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
