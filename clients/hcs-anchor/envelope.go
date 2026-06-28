package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AnchorType distinguishes what a message anchors.
type AnchorType string

const (
	// TypeContext anchors an spt_txn_context_hash (a single transaction binding).
	TypeContext AnchorType = "ctx"
	// TypeAudit anchors an audit-log Merkle root (a batch of events).
	TypeAudit AnchorType = "audit"
)

// EnvelopeVersion is the on-wire format version.
const EnvelopeVersion = 1

// Envelope is the canonical HCS message body. It is intentionally tiny and
// self-describing so a mirror-node reader (or the website, in JS) can interpret
// it without the Hedera SDK. NOTE: the authoritative anchoring TIME is the HCS
// consensus timestamp assigned by the network — Ts is only the submitter's wall
// clock, carried for convenience and never trusted for ordering.
//
// Marshaled field order is fixed by struct declaration (v, t, h, ts), so the
// bytes are canonical for a given content.
type Envelope struct {
	V    int        `json:"v"`
	Type AnchorType `json:"t"`
	Hash string     `json:"h"`
	Ts   int64      `json:"ts,omitempty"`
}

// NewEnvelope builds an envelope from a 32-byte hash in hex (a leading 0x is
// tolerated). It rejects anything that is not exactly 32 bytes so a malformed
// hash is never anchored.
func NewEnvelope(t AnchorType, hashHex string) (Envelope, error) {
	h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(hashHex)), "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return Envelope{}, fmt.Errorf("hash is not hex: %w", err)
	}
	if len(b) != 32 {
		return Envelope{}, fmt.Errorf("hash must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	if t != TypeContext && t != TypeAudit {
		return Envelope{}, fmt.Errorf("type must be %q or %q", TypeContext, TypeAudit)
	}
	return Envelope{V: EnvelopeVersion, Type: t, Hash: h, Ts: time.Now().Unix()}, nil
}

// Bytes is the exact HCS message payload: compact canonical JSON.
func (e Envelope) Bytes() ([]byte, error) {
	if e.V != EnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", e.V)
	}
	return json.Marshal(e)
}

// ParseEnvelope decodes an HCS message body back into an Envelope, rejecting
// unknown versions so an old reader never misinterprets a newer format.
func ParseEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return Envelope{}, fmt.Errorf("not a valid anchor envelope: %w", err)
	}
	if e.V != EnvelopeVersion {
		return Envelope{}, fmt.Errorf("unsupported envelope version %d", e.V)
	}
	return e, nil
}
