package ledger

import (
	"fmt"
	"strings"
)

// Starknet is the Starknet (StarkWare ZK-rollup) adapter. It binds an SPT-Txn
// Token to a specific Starknet transfer without the core token packages ever
// importing it — selection is by TxnContext.Chain == "starknet".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Starknet transfer: sender (originator),
//     receiver (beneficiary), amount, token ("ETH", "STRK", or an ERC-20 contract
//     address), and an optional anchor hash. Addresses are field elements (felt252)
//     written as 0x + up to 64 hex chars.
//   - Starknet has no native memo; the SPT-Txn attestation root anchors via a
//     Cairo contract (see cairo/attestation_anchor) rather than a tx field. With
//     native account abstraction, an agent's smart account can enforce its CT
//     scope on-chain — the agentic deliverable proposed in the grant.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, on-chain anchoring (Cairo contract),
// and the account-abstraction capability flow are grant work.
type Starknet struct{}

func (Starknet) Name() string { return "starknet" }

func (Starknet) Validate(tc TxnContext) error {
	if !looksLikeStarknetAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a Starknet address (0x + up to 64 hex, felt252)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeStarknetAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Starknet address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (ETH, STRK, or an ERC-20 token contract address)")
	}
	if tc.Currency != "ETH" && tc.Currency != "STRK" && !looksLikeStarknetAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be ETH, STRK, or a token contract address (0x…)", tc.Currency)
	}
	// Optional on-chain anchor: a 32-byte attestation root (64 hex). Stored as a
	// u256 by the Cairo anchor contract (a felt252 cannot hold a full 256-bit hash).
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Starknet) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer the authorization binds. Explicit
	// (not reflection) keeps the binding auditable, and identical bytes on any
	// host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "starknet"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Starknet{}) }

// ── helpers (shape checks only; no felt range / checksum validation in POC) ──

// looksLikeStarknetAddress accepts a 0x-prefixed hex field element: "0x" + 1..64
// hex chars (felt252 fits in 64 hex). Shape only.
func looksLikeStarknetAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	h := s[2:]
	if len(h) < 1 || len(h) > 64 {
		return false
	}
	return isHexStr(h)
}

func isHexStr(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
