package ledger

import (
	"fmt"
	"strings"
)

// Cardano is the Cardano adapter. It binds an SPT-Txn Token to a specific
// Cardano transfer (ADA or a native asset) without the core token packages ever
// importing it — selection is by TxnContext.Chain == "cardano".
//
// Cardano is the natural home for the anchor pattern (mirroring the Sui/Aptos
// Move and Starknet Cairo footprints) because it supports native TRANSACTION
// METADATA: an SPT-Txn context hash / audit root can be written on-chain via a
// labelled metadatum with NO smart contract (no Plutus) — a getter-free, native
// tamper-evidence anchor. Cardano is also the parent chain of Midnight (its
// privacy partner chain) and the home of Project Catalyst, so a Cardano footprint
// underpins the Cardano/Midnight ecosystem story.
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Cardano transfer: sender (originator),
//     receiver (beneficiary), amount (lovelace, 1 ADA = 1e6), currency ("ADA" or
//     a native-asset id "policyId.assetName"), and an optional metadata anchor
//     (Extra["metadata"] / Extra["anchor_hash"]).
//   - Accounts are Shelley bech32 addresses (addr1… mainnet, addr_test1… test),
//     or legacy Byron addresses (base58, Ae2…/DdzFF…). Shape checks only.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission and on-chain metadata anchoring live in
// clients/cardano-anchor, outside the offline core (blockchain-agnostic invariant).
type Cardano struct{}

func (Cardano) Name() string { return "cardano" }

func (Cardano) Validate(tc TxnContext) error {
	if !looksLikeCardanoAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a valid Cardano address", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeCardanoAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Cardano address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (ADA, or a native asset id policyId.assetName)")
	}
	// Currency is native ADA or a native-asset id (56-hex policy id, optionally
	// with .assetName). Shape check only.
	if !strings.EqualFold(tc.Currency, "ADA") && !looksLikeNativeAsset(tc.Currency) {
		return fmt.Errorf("currency %q must be ADA or a native asset id (policyId or policyId.assetName)", tc.Currency)
	}
	// Transaction metadata (CBOR) is bounded; a single anchor metadatum is tiny,
	// but bound the string form so an oversized blob is rejected early.
	if md, ok := tc.Extra["metadata"]; ok && len(md) > 1024 {
		return fmt.Errorf("metadata exceeds the 1024-byte anchor bound (%d bytes)", len(md))
	}
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Cardano) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer fields the authorization binds.
	// Explicit (not reflection) keeps the binding auditable, and identical bytes
	// on any host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "cardano"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Cardano{}) }

// ── helpers (shape checks only; no bech32 checksum / era validation in POC) ──

// looksLikeCardanoAddress accepts a Shelley bech32 address (addr1… / addr_test1…)
// or a legacy Byron address (base58, Ae2…/DdzFF…). Shape only; no checksum.
func looksLikeCardanoAddress(s string) bool {
	if strings.HasPrefix(s, "addr1") || strings.HasPrefix(s, "addr_test1") {
		// bech32 body: length is well beyond the prefix, lowercase bech32 charset.
		if len(s) < 20 || len(s) > 130 {
			return false
		}
		return isBech32(s)
	}
	// Byron legacy: base58, starts with Ae2 or DdzFF, ~50–120 chars.
	if strings.HasPrefix(s, "Ae2") || strings.HasPrefix(s, "DdzFF") {
		return len(s) >= 40 && len(s) <= 130 && isBase58(s)
	}
	return false
}

// isBech32 reports whether s is composed only of characters valid in a Cardano
// bech32 address: the HRP ("addr" or "addr_test", note the underscore), the '1'
// separator, and the lowercase-alphanumeric data charset. Shape only, no checksum.
func isBech32(s string) bool {
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

// looksLikeNativeAsset accepts a 56-hex policy id, optionally followed by
// ".<assetName>" where assetName is hex (bounded). Shape only.
func looksLikeNativeAsset(s string) bool {
	policy := s
	if i := strings.IndexByte(s, '.'); i >= 0 {
		policy = s[:i]
		name := s[i+1:]
		if len(name) == 0 || len(name) > 64 || !isLowerOrHex(name) {
			return false
		}
	}
	return len(policy) == 56 && isLowerOrHex(policy)
}

func isLowerOrHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
