// Package oidc is a small, dependency-light OpenID Connect / OAuth 2.0 token
// verifier used to accept an external identity provider's token (e.g. Keycloak,
// Okta, Auth0) as the subject_token of an RFC 8693 Token Exchange. It performs
// OIDC discovery, fetches and caches the JWKS, and verifies an RS256-signed JWT
// (issuer, expiry, and optionally audience). RS256 is Keycloak's default; this
// is deliberately stdlib-only (crypto/rsa) to match the project's minimal-deps
// posture. ES256 support is a small, marked extension point.
//
// Verification is issuance-time only — the JWKS is cached, so this never sits in
// the SPT-Txn hot path.
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Claims is a decoded JWT claim set.
type Claims map[string]any

// Str returns a string claim (empty if absent or not a string).
func (c Claims) Str(k string) string { s, _ := c[k].(string); return s }

// Verifier verifies OIDC ID/access tokens from a single issuer.
type Verifier struct {
	issuer    string
	audiences map[string]bool
	leeway    time.Duration
	hc        *http.Client

	jwksURI string
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey // kid -> RSA public key
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithAudience requires the token's aud (or azp) to match one of these values.
// If never set, the audience check is skipped (acceptable for a local demo;
// SET IT IN PRODUCTION).
func WithAudience(aud ...string) Option {
	return func(v *Verifier) {
		for _, a := range aud {
			if a != "" {
				v.audiences[a] = true
			}
		}
	}
}

// WithHTTPClient overrides the HTTP client (e.g. timeouts, a pinned CA pool).
func WithHTTPClient(hc *http.Client) Option { return func(v *Verifier) { v.hc = hc } }

// WithLeeway sets the clock-skew tolerance for exp/nbf (default 60s).
func WithLeeway(d time.Duration) Option { return func(v *Verifier) { v.leeway = d } }

// NewVerifier runs OIDC discovery against issuer and loads its JWKS.
func NewVerifier(ctx context.Context, issuer string, opts ...Option) (*Verifier, error) {
	v := &Verifier{
		issuer:    strings.TrimRight(issuer, "/"),
		audiences: map[string]bool{},
		leeway:    60 * time.Second,
		hc:        &http.Client{Timeout: 10 * time.Second},
		keys:      map[string]*rsa.PublicKey{},
	}
	for _, o := range opts {
		o(v)
	}
	if err := v.discover(ctx); err != nil {
		return nil, err
	}
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) discover(ctx context.Context) error {
	url := v.issuer + "/.well-known/openid-configuration"
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, url, &d); err != nil {
		return fmt.Errorf("oidc: discovery %s: %w", url, err)
	}
	if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != v.issuer {
		return fmt.Errorf("oidc: discovery issuer %q != configured %q", d.Issuer, v.issuer)
	}
	if d.JWKSURI == "" {
		return errors.New("oidc: discovery document has no jwks_uri")
	}
	v.jwksURI = d.JWKSURI
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Verifier) refreshJWKS(ctx context.Context) error {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := v.getJSON(ctx, v.jwksURI, &set); err != nil {
		return fmt.Errorf("oidc: fetch jwks %s: %w", v.jwksURI, err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue // ES256 keys (kty=EC) are a marked extension point
		}
		pub, err := rsaFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("oidc: no usable RSA signing keys in JWKS")
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

func rsaFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func (v *Verifier) keyFor(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

// Verify checks an RS256 JWT and returns its claims. It validates the signature
// against the issuer's JWKS, the exact issuer, expiry/not-before (with leeway),
// and (if configured) the audience.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed token (want 3 parts)")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("oidc: header json: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported alg %q (RS256 only in this build)", hdr.Alg)
	}
	pub := v.keyFor(hdr.Kid)
	if pub == nil { // key rotation — refresh once
		if err := v.refreshJWKS(ctx); err != nil {
			return nil, err
		}
		if pub = v.keyFor(hdr.Kid); pub == nil {
			return nil, fmt.Errorf("oidc: no signing key for kid %q", hdr.Kid)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: signature b64: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("oidc: signature invalid: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: payload b64: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, fmt.Errorf("oidc: payload json: %w", err)
	}
	if iss := claims.Str("iss"); strings.TrimRight(iss, "/") != v.issuer {
		return nil, fmt.Errorf("oidc: issuer %q != expected %q", iss, v.issuer)
	}
	now := time.Now()
	if exp, ok := numTime(claims["exp"]); ok && now.After(exp.Add(v.leeway)) {
		return nil, errors.New("oidc: token expired")
	}
	if nbf, ok := numTime(claims["nbf"]); ok && now.Add(v.leeway).Before(nbf) {
		return nil, errors.New("oidc: token not yet valid (nbf)")
	}
	if len(v.audiences) > 0 && !v.audienceOK(claims) {
		return nil, errors.New("oidc: audience mismatch")
	}
	return claims, nil
}

func (v *Verifier) audienceOK(c Claims) bool {
	if v.audiences[c.Str("azp")] {
		return true
	}
	switch a := c["aud"].(type) {
	case string:
		return v.audiences[a]
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && v.audiences[s] {
				return true
			}
		}
	}
	return false
}

// numTime converts a JSON numeric (float64) epoch-seconds claim to a time.
func numTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

func (v *Verifier) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}
