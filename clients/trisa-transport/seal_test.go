package trisatransport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// 2048 is enough for tests and fast; production uses the counterparty's
	// certificate key from GDS.
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	priv := key(t)
	msg := []byte(`{"identity":"<sd-jwt>","transaction":{"asset":"XRP","amount":"100"}}`)

	env, err := Seal(msg, &priv.PublicKey, "key-1")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !env.Sealed || env.EncryptionAlgorithm != EncryptionAESGCM {
		t.Fatalf("envelope metadata wrong: %+v", env)
	}
	if bytes.Contains(env.Payload, []byte("sd-jwt")) {
		t.Fatal("plaintext leaked into sealed payload")
	}

	got, err := Open(env, priv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: %q != %q", got, msg)
	}
}

func TestOpen_TamperedPayloadFailsHMAC(t *testing.T) {
	priv := key(t)
	env, _ := Seal([]byte("secret payload"), &priv.PublicKey, "")
	env.Payload[len(env.Payload)-1] ^= 0xFF // flip a ciphertext bit
	if _, err := Open(env, priv); !errors.Is(err, ErrHMACMismatch) {
		t.Fatalf("got %v, want ErrHMACMismatch", err)
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	priv := key(t)
	other := key(t)
	env, _ := Seal([]byte("secret payload"), &priv.PublicKey, "")
	if _, err := Open(env, other); err == nil {
		t.Fatal("expected failure opening with the wrong private key")
	}
}

func TestOpen_BadAlgorithmRejected(t *testing.T) {
	priv := key(t)
	env, _ := Seal([]byte("x"), &priv.PublicKey, "")
	env.EncryptionAlgorithm = "ROT13"
	if _, err := Open(env, priv); !errors.Is(err, ErrBadAlgorithm) {
		t.Fatalf("got %v, want ErrBadAlgorithm", err)
	}
}

func TestOpen_NotSealedRejected(t *testing.T) {
	priv := key(t)
	env, _ := Seal([]byte("x"), &priv.PublicKey, "")
	env.Sealed = false
	if _, err := Open(env, priv); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("got %v, want ErrNotSealed", err)
	}
}
