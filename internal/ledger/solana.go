package ledger

import (
	"fmt"
	"strings"
)

// Solana is the Solana adapter. It binds an SPT-Txn Token to a specific Solana
// transfer (native SOL or an SPL / Token-2022 token) without the core token
// packages ever importing it — selection is by TxnContext.Chain == "solana".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Solana transfer: sender (originator),
//     receiver (beneficiary), amount, currency ("SOL" or an SPL/Token-2022 mint
//     address), and an optional memo (Extra["memo"], SPL Memo program).
//   - Accounts are base58 Ed25519 public keys (32–44 chars).
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, and anchoring the attestation hash /
// audit root on-chain (e.g. via the SPL Memo program or a small anchor program),
// belong to a separate client outside the authorization core (grant work). The
// Token-2022 confidential-transfer angle — proving amount-over-threshold, KYC and
// VASP-membership without revealing the encrypted amount — rides on the existing
// payload-level ZK attestation, off the on-chain critical path.
type Solana struct{}

func (Solana) Name() string { return "solana" }

func (Solana) Validate(tc TxnContext) error {
	if !looksLikeSolanaAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a base58 Solana address", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeSolanaAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid base58 Solana address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (SOL, or an SPL/Token-2022 mint address)")
	}
	// SPL Memo data is bounded by the transaction size; cap at 566 bytes.
	if memo, ok := tc.Extra["memo"]; ok && len(memo) > 566 {
		return fmt.Errorf("memo exceeds the 566-byte SPL Memo limit (%d bytes)", len(memo))
	}
	return nil
}

func (Solana) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer fields the authorization binds.
	// Explicit (not reflection) keeps the binding auditable, and identical bytes
	// on any host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "solana"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Solana{}) }

// ── helpers (shape checks only; no base58 checksum/curve validation in POC) ──

// looksLikeSolanaAddress accepts a base58-encoded Ed25519 public key (32 bytes
// → 32–44 base58 chars). Shape only; it does not verify the key is on-curve.
func looksLikeSolanaAddress(s string) bool {
	if len(s) < 32 || len(s) > 44 {
		return false
	}
	return isBase58(s)
}

func isBase58(s string) bool {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
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
