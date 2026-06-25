package escrow

import (
	"bytes"
	"testing"
)

// TestDeriveKey_HKDF (ESC-2): the HKDF-SHA256 derivation is deterministic for a
// given shared secret (so Seal and Open agree) and produces a 32-byte AES-256
// key, while different shared secrets yield different keys.
func TestDeriveKey_HKDF(t *testing.T) {
	shared := []byte("x25519-ecdh-shared-secret-32bytes!!")

	k1, err := deriveKey(shared)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32 (AES-256)", len(k1))
	}

	k2, err := deriveKey(shared)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("HKDF derivation must be deterministic for the same shared secret")
	}

	other, err := deriveKey([]byte("a-different-shared-secret-value!!"))
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if bytes.Equal(k1, other) {
		t.Error("distinct shared secrets must derive distinct keys")
	}
}
