package attest

// discovery.go — OIDC issuer discovery: configure a trust domain by its ISSUER
// and derive the JWKS URL from the issuer's OpenID Provider Metadata
// (RFC 8414 / OpenID Connect Discovery, `/.well-known/openid-configuration`),
// rather than hand-wiring the JWKS URL. This is what lets the cloud-workload
// methods (AWS IRSA / GCP WIF / Azure FC / K8s OIDC) be configured with just the
// issuer the token carries.
//
// Trust model (spec, load-bearing — a mistake here is an authorization bypass):
//
//   - HTTPS ONLY. The metadata and JWKS documents are fetched over TLS; an
//     http:// issuer or jwks_uri is rejected. Without TLS a network attacker
//     substitutes signing keys and forges any assertion.
//   - EXACT issuer match. The `issuer` value inside the discovery document MUST
//     equal the configured issuer byte-for-byte. This is the anchor: we trust
//     the document's `jwks_uri` pointer precisely because the document was
//     served over TLS by the issuer and self-declares that same issuer. A
//     document claiming a different issuer is rejected (it is describing someone
//     else's trust domain).
//   - The `jwks_uri` MAY be on a different host than the issuer (this is normal:
//     Google's issuer is accounts.google.com while its JWKS lives on
//     googleapis.com), so host-equality is NOT required — only HTTPS. The
//     cross-host pointer is trusted solely because it arrived over TLS from the
//     authentic issuer metadata.
//   - Bounded fetch (size + timeout), fail-closed on any error.
//
// Key resolution after discovery reuses JWKSKeySource, so caching, rotation
// handling, throttle/anti-DoS, and RSA exponent/modulus validation are inherited
// unchanged. Discovery does one metadata fetch; JWKS keys are then fetched
// lazily on first use and fail closed if unresolvable.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// openIDMetadata is the subset of OpenID Provider Metadata we consume.
type openIDMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// requireHTTPSURL validates that raw is a well-formed absolute https URL with a
// host. Used for both the issuer and the discovered jwks_uri.
func requireHTTPSURL(raw, what string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("attest: %s is not a valid URL: %w", what, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("attest: %s must be https (got %q); refusing insecure key discovery", what, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("attest: %s has no host", what)
	}
	return nil
}

// DiscoverOIDC fetches the issuer's OpenID Provider Metadata, validates it, and
// returns a JWKSKeySource pointed at the discovered jwks_uri. `hc` may be nil
// (a default 10s-timeout client is used). Extra JWKSOptions configure the
// resulting key source (e.g. WithMinRefreshInterval); the same http client is
// applied to the key source unless overridden by an option.
//
// Fail-closed: any transport, decode, scheme, or issuer-mismatch error returns
// an error and no key source. The metadata fetch is bounded to 1 MiB.
func DiscoverOIDC(ctx context.Context, issuer string, hc *http.Client, opts ...JWKSOption) (*JWKSKeySource, error) {
	if issuer == "" {
		return nil, fmt.Errorf("%w: empty issuer", ErrIssuer)
	}
	if err := requireHTTPSURL(issuer, "issuer"); err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}

	metaURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attest: OIDC discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest: OIDC discovery status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var meta openIDMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("attest: OIDC discovery json: %w", err)
	}
	// Exact issuer match is the trust anchor — reject a document describing a
	// different trust domain.
	if meta.Issuer != issuer {
		return nil, fmt.Errorf("%w: discovery issuer %q != configured %q", ErrIssuer, meta.Issuer, issuer)
	}
	if meta.JWKSURI == "" {
		return nil, fmt.Errorf("attest: OIDC discovery has no jwks_uri")
	}
	if err := requireHTTPSURL(meta.JWKSURI, "jwks_uri"); err != nil {
		return nil, err
	}

	// Reuse the hardened JWKS source; apply the same client, then caller opts.
	srcOpts := append([]JWKSOption{WithHTTPClient(hc)}, opts...)
	return NewJWKSKeySource(meta.JWKSURI, srcOpts...), nil
}
