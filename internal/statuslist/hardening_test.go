package statuslist

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// F3: a status list token with no (or zero) exp must fail closed — a stale
// revocation snapshot must not be trusted forever.
func TestVerifyToken_RequiresExp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := New(1, 64)
	_ = l.Set(3, StatusInvalid)
	enc, _ := l.Encode()
	uri := "https://issuer.example/sl/9"

	// Craft a validly-signed token that omits exp.
	header := map[string]any{"alg": "EdDSA", "typ": TokenType}
	claims := map[string]any{
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": map[string]any{"bits": enc.Bits, "lst": enc.Lst},
		"spt_entries": l.entries,
		// no "exp"
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	tok := signingInput + "." + b64(ed25519.Sign(priv, []byte(signingInput)))

	if _, err := VerifyToken(tok, uri, pub, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("exp-less status list token accepted (err=%v); must fail closed", err)
	}

	// Control: the same token with a valid exp verifies.
	good, err := SignToken(l, uri, time.Now(), time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(good, uri, pub, time.Now()); err != nil {
		t.Fatalf("valid token with exp rejected: %v", err)
	}
}
