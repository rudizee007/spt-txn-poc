package wlapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintSVID builds a compact Ed25519-signed JWT-SVID. exp/nbf are set relative to
// now so the token verifies against attest's real clock (VerifySPIFFEJWTSVID
// uses time.Now()).
func mintSVID(t *testing.T, kid, sub string, aud []string, priv ed25519.PrivateKey, exp time.Time) string {
	t.Helper()
	now := time.Now()
	hb, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	cb, _ := json.Marshal(map[string]any{
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": exp.Unix(),
	})
	signingInput := b64(hb) + "." + b64(cb)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64(sig)
}

// jwksFor builds a one-key JWT trust bundle (JWKS) for an Ed25519 public key.
func jwksFor(kid string, pub ed25519.PublicKey) []byte {
	b, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64(pub)},
		},
	})
	return b
}

type fakeSource struct {
	svid      string
	jwks      []byte
	svidErr   error
	bundleErr error
}

func (f fakeSource) FetchJWTSVID(_ context.Context, _ string) (string, error) {
	return f.svid, f.svidErr
}

func (f fakeSource) FetchJWTBundles(_ context.Context, _ string) ([]byte, error) {
	return f.jwks, f.bundleErr
}

const spiffeSub = "spiffe://prod.example/ns/default/sa/api"

func TestVerifiedIdentity_Success(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	svid := mintSVID(t, "k1", spiffeSub, []string{"spt-txn-exchange"}, priv, time.Now().Add(time.Hour))
	src := fakeSource{svid: svid, jwks: jwksFor("k1", pub)}

	id, err := VerifiedIdentity(context.Background(), src, []string{"spt-txn-exchange"})
	if err != nil {
		t.Fatalf("VerifiedIdentity failed: %v", err)
	}
	if id.TrustDomain != "prod.example" {
		t.Fatalf("trust domain = %q", id.TrustDomain)
	}
	if id.Subject != spiffeSub {
		t.Fatalf("subject = %q", id.Subject)
	}
	if id.Method != attest.MethodSPIFFEJWTSVID {
		t.Fatalf("method = %q", id.Method)
	}
}

func TestVerifiedIdentity_FailClosed(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	goodSVID := mintSVID(t, "k1", spiffeSub, []string{"spt-txn-exchange"}, priv, time.Now().Add(time.Hour))

	t.Run("wrong_audience", func(t *testing.T) {
		svid := mintSVID(t, "k1", spiffeSub, []string{"someone-else"}, priv, time.Now().Add(time.Hour))
		src := fakeSource{svid: svid, jwks: jwksFor("k1", pub)}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); !errors.Is(err, attest.ErrAudience) {
			t.Fatalf("want ErrAudience, got %v", err)
		}
	})

	t.Run("wrong_key_in_bundle", func(t *testing.T) {
		otherPub, _, _ := ed25519.GenerateKey(nil)
		src := fakeSource{svid: goodSVID, jwks: jwksFor("k1", otherPub)} // kid matches, key doesn't
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); !errors.Is(err, attest.ErrSignature) {
			t.Fatalf("want ErrSignature, got %v", err)
		}
	})

	t.Run("kid_not_in_bundle", func(t *testing.T) {
		src := fakeSource{svid: goodSVID, jwks: jwksFor("different-kid", pub)}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); !errors.Is(err, attest.ErrKey) {
			t.Fatalf("want ErrKey, got %v", err)
		}
	})

	t.Run("non_spiffe_subject", func(t *testing.T) {
		svid := mintSVID(t, "k1", "https://not-spiffe.example/x", []string{"spt-txn-exchange"}, priv, time.Now().Add(time.Hour))
		src := fakeSource{svid: svid, jwks: jwksFor("k1", pub)}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); err == nil {
			t.Fatal("want error for non-SPIFFE subject")
		}
	})

	t.Run("malformed_svid", func(t *testing.T) {
		src := fakeSource{svid: "not-a-jwt", jwks: jwksFor("k1", pub)}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); err == nil {
			t.Fatal("want error for malformed SVID")
		}
	})

	t.Run("fetch_svid_error", func(t *testing.T) {
		src := fakeSource{svidErr: errors.New("socket down")}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); err == nil {
			t.Fatal("want error when SVID fetch fails")
		}
	})

	t.Run("fetch_bundle_error", func(t *testing.T) {
		src := fakeSource{svid: goodSVID, bundleErr: errors.New("bundle unavailable")}
		if _, err := VerifiedIdentity(ctx, src, []string{"spt-txn-exchange"}); err == nil {
			t.Fatal("want error when bundle fetch fails")
		}
	})

	t.Run("no_audience", func(t *testing.T) {
		src := fakeSource{svid: goodSVID, jwks: jwksFor("k1", pub)}
		if _, err := VerifiedIdentity(ctx, src, nil); err == nil {
			t.Fatal("want error when no audience is requested")
		}
	})
}
