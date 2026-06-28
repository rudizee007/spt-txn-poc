package main

import "testing"

const sampleHash = "4b505b1f2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7"

func TestEnvelope_RoundTrip(t *testing.T) {
	e, err := NewEnvelope(TypeContext, "0x"+sampleHash)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	b, err := e.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	got, err := ParseEnvelope(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Hash != sampleHash {
		t.Errorf("hash round-trip: got %s want %s", got.Hash, sampleHash)
	}
	if got.Type != TypeContext {
		t.Errorf("type round-trip: got %s want %s", got.Type, TypeContext)
	}
	if got.V != EnvelopeVersion {
		t.Errorf("version: got %d want %d", got.V, EnvelopeVersion)
	}
}

func TestEnvelope_RejectsBadHash(t *testing.T) {
	cases := map[string]string{
		"too short": "abcd",
		"31 bytes":  sampleHash[:62],
		"not hex":   "zz" + sampleHash[2:],
	}
	for name, h := range cases {
		if _, err := NewEnvelope(TypeContext, h); err == nil {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}

func TestEnvelope_RejectsBadType(t *testing.T) {
	if _, err := NewEnvelope("bogus", "0x"+sampleHash); err == nil {
		t.Error("expected rejection of unknown anchor type")
	}
}
