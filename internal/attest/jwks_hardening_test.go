package attest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func rawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, n *big.Int, e int) jwk {
	eb := big.NewInt(int64(e)).Bytes()
	return jwk{Kid: kid, Kty: "RSA", N: rawURL(n.Bytes()), E: rawURL(eb)}
}

// F2: ParseJWKS must reject forgeable/weak RSA keys.
func TestParseJWKS_RejectsWeakRSA(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// Valid 2048-bit e=65537 key is accepted.
	set := jwkSet{Keys: []jwk{rsaJWK("good", good.N, good.E)}}
	b, _ := json.Marshal(set)
	if keys, err := ParseJWKS(b); err != nil || keys["good"] == nil {
		t.Fatalf("valid RSA key rejected: %v", err)
	}

	// e == 1 (trivially forgeable) rejected.
	b, _ = json.Marshal(jwkSet{Keys: []jwk{rsaJWK("e1", good.N, 1)}})
	if _, err := ParseJWKS(b); err == nil {
		t.Fatal("RSA exponent 1 accepted")
	}

	// even exponent rejected.
	b, _ = json.Marshal(jwkSet{Keys: []jwk{rsaJWK("even", good.N, 4)}})
	if _, err := ParseJWKS(b); err == nil {
		t.Fatal("even RSA exponent accepted")
	}

	// sub-2048-bit modulus rejected.
	b, _ = json.Marshal(jwkSet{Keys: []jwk{rsaJWK("short", weak.N, weak.E)}})
	if _, err := ParseJWKS(b); err == nil {
		t.Fatal("1024-bit RSA modulus accepted")
	}
}

// F1: a fetch that yields zero usable keys must still count against the throttle,
// so an unknown-kid flood cannot hammer the JWKS URL on every request.
func TestJWKSKeySource_EmptyResultThrottled(t *testing.T) {
	var fetches int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fetches, 1)
		_, _ = w.Write([]byte(`{"keys":[]}`)) // no usable keys
	}))
	defer srv.Close()

	src := NewJWKSKeySource(srv.URL, WithMinRefreshInterval(time.Hour))
	for i := 0; i < 8; i++ {
		if _, err := src.Key(context.Background(), "any-kid", "EdDSA"); err == nil {
			t.Fatal("unknown kid resolved from an empty JWKS")
		}
	}
	if n := atomic.LoadInt64(&fetches); n != 1 {
		t.Fatalf("empty-result flood caused %d fetches; want 1 (throttled)", n)
	}
}
