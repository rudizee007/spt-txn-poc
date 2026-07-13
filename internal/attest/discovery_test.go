package attest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// metaController lets a test set the served OIDC metadata after the TLS server
// (and therefore its URL) exists. atomic.Value keeps it race-free under -race.
type metaController struct {
	v atomic.Value // openIDMetadata
}

func (m *metaController) set(md openIDMetadata) { m.v.Store(md) }
func (m *metaController) get() openIDMetadata   { return m.v.Load().(openIDMetadata) }

func newOIDCServer(t *testing.T, pub ed25519.PublicKey) (*httptest.Server, *metaController) {
	t.Helper()
	mc := &metaController{}
	mc.set(openIDMetadata{}) // initialise so an early request never nil-panics
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mc.get())
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{edJWK("k1", pub)}})
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, mc
}

func TestDiscoverOIDC_Success(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts, mc := newOIDCServer(t, pub)
	mc.set(openIDMetadata{Issuer: ts.URL, JWKSURI: ts.URL + "/jwks"}) // exact issuer match

	src, err := DiscoverOIDC(context.Background(), ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	got, err := src.Key(context.Background(), "k1", "EdDSA")
	if err != nil {
		t.Fatalf("key resolution via discovered JWKS failed: %v", err)
	}
	if !got.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("wrong key resolved from discovered JWKS")
	}
}

func TestDiscoverOIDC_IssuerMismatchRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts, mc := newOIDCServer(t, pub)
	// Document claims a DIFFERENT issuer than the one we configured — it is
	// describing someone else's trust domain. Must be rejected.
	mc.set(openIDMetadata{Issuer: "https://evil.example", JWKSURI: ts.URL + "/jwks"})

	_, err := DiscoverOIDC(context.Background(), ts.URL, ts.Client())
	if !errors.Is(err, ErrIssuer) {
		t.Fatalf("expected ErrIssuer on issuer mismatch, got %v", err)
	}
}

func TestDiscoverOIDC_InsecureIssuerRejected(t *testing.T) {
	_, err := DiscoverOIDC(context.Background(), "http://accounts.example", nil)
	if err == nil {
		t.Fatal("expected error for http:// issuer")
	}
}

func TestDiscoverOIDC_InsecureJWKSURIRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts, mc := newOIDCServer(t, pub)
	mc.set(openIDMetadata{Issuer: ts.URL, JWKSURI: "http://insecure.example/jwks"})

	_, err := DiscoverOIDC(context.Background(), ts.URL, ts.Client())
	if err == nil {
		t.Fatal("expected error for http:// jwks_uri")
	}
}

func TestDiscoverOIDC_MissingJWKSURIRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts, mc := newOIDCServer(t, pub)
	mc.set(openIDMetadata{Issuer: ts.URL, JWKSURI: ""})

	_, err := DiscoverOIDC(context.Background(), ts.URL, ts.Client())
	if err == nil {
		t.Fatal("expected error when discovery has no jwks_uri")
	}
}
