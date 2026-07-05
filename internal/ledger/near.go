package ledger

import (
	"fmt"
	"regexp"
	"strings"
)

// Near is the NEAR Protocol adapter. It binds an SPT-Txn Token to a specific
// NEAR transfer (native NEAR or a NEP-141 fungible token) without the core token
// packages ever importing it — selection is by TxnContext.Chain == "near".
//
// NEAR is fully non-EVM: human-readable, hierarchical named accounts
// ("alice.near", "agent.alice.testnet") or 64-hex implicit accounts, amounts in
// yoctoNEAR (1 NEAR = 10^24 yocto), and Borsh-serialized transactions. This is a
// distinct address family from both the EVM adapters (0x-hex) and Solana (base58).
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a NEAR transfer: sender (originator), receiver
//     (beneficiary), amount (yoctoNEAR), currency ("NEAR" or a NEP-141 token
//     contract account id), and an optional memo (Extra["memo"]).
//   - A native NEAR Transfer action has no memo field, so — like Aptos — the
//     humanAnchor is bound cryptographically into the attestation (context hash,
//     verifier step 8), not written on-chain here. On-chain anchoring would use a
//     FunctionCall/log or a NEP-141 ft_transfer memo (grant work), mirroring the
//     Move anchor module on Aptos / the SPL Memo path on Solana.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission lives in clients/near-pay, outside the
// offline core (blockchain-agnostic invariant).
type Near struct{}

func (Near) Name() string { return "near" }

func (Near) Validate(tc TxnContext) error {
	if !looksLikeNearAccount(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a valid NEAR account id", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeNearAccount(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid NEAR account id", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (NEAR, or a NEP-141 token contract account id)")
	}
	// Currency is either native NEAR or a fungible-token contract account id.
	if !strings.EqualFold(tc.Currency, "NEAR") && !looksLikeNearAccount(tc.Currency) {
		return fmt.Errorf("currency %q must be NEAR or a NEP-141 token contract account id", tc.Currency)
	}
	return nil
}

func (Near) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer fields the authorization binds.
	// Explicit (not reflection) keeps the binding auditable, and identical bytes
	// on any host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "near"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Near{}) }

// ── helpers (shape checks only; no on-chain existence check in POC) ──

// nearNamedRe matches the NEAR named-account grammar (Nomicon): lowercase
// alphanumeric parts joined by '.', where '-'/'_' may separate alphanumerics
// within a part. Length bounds (2..64) are checked separately.
var nearNamedRe = regexp.MustCompile(`^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`)

// looksLikeNearAccount accepts either a 64-hex implicit account or a named
// account (2–64 chars) matching the Nomicon grammar. Shape only.
func looksLikeNearAccount(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	if len(s) == 64 && isLowerHex(s) { // implicit account (32-byte public key, hex)
		return true
	}
	return nearNamedRe.MatchString(s)
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
