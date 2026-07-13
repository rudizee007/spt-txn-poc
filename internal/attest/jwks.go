package attest

// jwks.go — a live JWKS-URL KeySource with caching and key-rotation handling.
// Most attested-identity trust domains (SPIFFE JWT-SVID bundles, K8s cluster
// OIDC, cloud IdPs) publish a JWKS; this source fetches it, caches keys by kid,
// and re-fetches on a cache miss (a rotated/new kid) subject to a minimum
// refresh interval so a flood of unknown-kid tokens cannot become a fetch DoS.
//
// It complements StaticKeySource (pinned bundles): use pinned bundles for
// SPIFFE trust domains you control, JWKS-URL for rotating cloud/K8s issuers.
//
// Standard library only: crypto/rsa, crypto/ed25519, net/http, encoding/json.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwk is one JSON Web Key (the subset we support: RSA and OKP/Ed25519).
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKS parses a JWKS document into a kid→key map. Keys without a usable
// type are skipped; a key whose material is malformed is an error (fail loud
// on a broken bundle rather than silently trusting a partial set).
func ParseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("attest: JWKS json: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
			if err != nil {
				return nil, fmt.Errorf("attest: JWKS RSA n: %w", err)
			}
			eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
			if err != nil {
				return nil, fmt.Errorf("attest: JWKS RSA e: %w", err)
			}
			e := 0
			for _, b := range eb {
				e = e<<8 | int(b)
			}
			// A public exponent of 0, 1, or an even value is degenerate — e==1
			// makes verification trivially forgeable (signature == message). And
			// a short modulus is a weak key. Reject rather than trust a JWKS that
			// serves one (a compromised or MITM'd endpoint could).
			if e < 3 || e%2 == 0 {
				return nil, fmt.Errorf("attest: JWKS RSA key %q has an invalid exponent %d", k.Kid, e)
			}
			n := new(big.Int).SetBytes(nb)
			if n.BitLen() < 2048 {
				return nil, fmt.Errorf("attest: JWKS RSA key %q modulus is %d bits (<2048)", k.Kid, n.BitLen())
			}
			out[k.Kid] = &rsa.PublicKey{N: n, E: e}
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
			if err != nil {
				return nil, fmt.Errorf("attest: JWKS OKP x: %w", err)
			}
			if len(xb) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("attest: JWKS OKP key %q wrong size", k.Kid)
			}
			out[k.Kid] = ed25519.PublicKey(xb)
		default:
			// Unsupported key type (EC, oct, …): skip; our alg allowlist is
			// RS256/EdDSA so these are never selected anyway.
		}
	}
	return out, nil
}

// JWKSKeySource resolves keys from a live JWKS URL with caching and rotation.
type JWKSKeySource struct {
	url         string
	hc          *http.Client
	minInterval time.Duration
	maxBody     int64

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	lastRefresh time.Time
}

// JWKSOption configures a JWKSKeySource.
type JWKSOption func(*JWKSKeySource)

// WithHTTPClient overrides the HTTP client (timeouts, transport, TLS policy).
func WithHTTPClient(hc *http.Client) JWKSOption { return func(s *JWKSKeySource) { s.hc = hc } }

// WithMinRefreshInterval bounds how often a cache miss may trigger a re-fetch.
func WithMinRefreshInterval(d time.Duration) JWKSOption {
	return func(s *JWKSKeySource) { s.minInterval = d }
}

// NewJWKSKeySource builds a source for the given JWKS URL. It does not fetch
// eagerly; the first Key lookup (or Refresh) populates the cache.
func NewJWKSKeySource(url string, opts ...JWKSOption) *JWKSKeySource {
	s := &JWKSKeySource{
		url:         url,
		hc:          &http.Client{Timeout: 10 * time.Second},
		minInterval: 5 * time.Minute,
		maxBody:     1 << 20,
		keys:        map[string]crypto.PublicKey{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Refresh fetches the JWKS and atomically replaces the cache. The attempt time
// is stamped up front so that both successful and FAILED fetches count against
// the throttle window — a persistently failing or empty JWKS URL therefore
// cannot be hammered on every request (recovery is delayed at most one
// minInterval).
func (s *JWKSKeySource) Refresh(ctx context.Context) error {
	s.mu.Lock()
	s.lastRefresh = time.Now()
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("attest: JWKS fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("attest: JWKS fetch status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody))
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = keys
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

// Key implements KeySource. On a cache miss it re-fetches once (rotation),
// throttled by minInterval so unknown-kid floods cannot become a fetch DoS.
func (s *JWKSKeySource) Key(ctx context.Context, kid, _ string) (crypto.PublicKey, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	last := s.lastRefresh
	s.mu.RUnlock()
	if ok {
		return k, nil
	}

	// Cache miss: refresh only if we have NEVER fetched, or the throttle window
	// has passed. The gate is "have we ever fetched" (lastRefresh.IsZero()), NOT
	// "is the cache empty": a fetch that yields zero usable keys (upstream blip,
	// or only unsupported key types) still counts, so an unknown-kid flood cannot
	// force a refresh on every request and become a fetch DoS on the JWKS URL.
	if last.IsZero() || time.Since(last) >= s.minInterval {
		if err := s.Refresh(ctx); err != nil {
			return nil, err
		}
		s.mu.RLock()
		k, ok = s.keys[kid]
		s.mu.RUnlock()
		if ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: kid %q not in JWKS", ErrKey, kid)
}
