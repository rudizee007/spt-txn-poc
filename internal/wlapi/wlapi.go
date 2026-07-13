// Package wlapi is the SPIFFE Workload API ingress for attested identity: it
// fetches a JWT-SVID and its trust bundle from a local SPIRE agent (over the
// Workload API unix socket) and turns them into a VERIFIED attest.Identity.
//
// Design (deliberate): this package holds NO verification logic. All signature,
// issuer/trust-domain, audience, and temporal checks are delegated to
// internal/attest, which stays standard-library-only and hermetically testable.
// wlapi is pure orchestration — fetch, then hand to attest.VerifySPIFFEJWTSVID —
// so the trust boundary is not widened and the heavier SPIFFE/gRPC dependency is
// confined to the build-tagged adapter (see spiffe_workloadapi.go), never pulled
// into the verifier core or a default build.
//
// The Source interface lets the fetch side be a real Workload API client in
// production or an in-memory fake in tests, so the fetch→verify wiring is proven
// without a running SPIRE agent.
package wlapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
)

// Source fetches SPIFFE JWT material. Implementations MUST obtain it only from a
// trusted Workload API endpoint (the local SPIRE agent socket).
type Source interface {
	// FetchJWTSVID returns a signed JWT-SVID minted for the given audience.
	FetchJWTSVID(ctx context.Context, audience string) (token string, err error)
	// FetchJWTBundles returns the JWT trust bundle for trustDomain as a JWKS
	// document (the set of authorities that may sign SVIDs in that domain).
	FetchJWTBundles(ctx context.Context, trustDomain string) (jwksJSON []byte, err error)
}

// VerifiedIdentity fetches an SVID for the first audience, resolves the matching
// trust bundle, and verifies the SVID against it via attest. It fails closed on
// any fetch, parse, or verification error.
//
// The trust domain used to select the bundle is read from the SVID's subject
// BEFORE verification — this is safe because it only chooses which authority set
// to check against; attest then cryptographically binds the SVID to that
// authority set. A forged subject merely selects a bundle whose keys will not
// verify the forged token.
func VerifiedIdentity(ctx context.Context, src Source, audiences []string) (attest.Identity, error) {
	if src == nil {
		return attest.Identity{}, errors.New("wlapi: nil source")
	}
	if len(audiences) == 0 {
		return attest.Identity{}, errors.New("wlapi: at least one audience is required")
	}

	token, err := src.FetchJWTSVID(ctx, audiences[0])
	if err != nil {
		return attest.Identity{}, fmt.Errorf("wlapi: fetch JWT-SVID: %w", err)
	}

	td, err := unverifiedSPIFFETrustDomain(token)
	if err != nil {
		return attest.Identity{}, err
	}

	jwks, err := src.FetchJWTBundles(ctx, td)
	if err != nil {
		return attest.Identity{}, fmt.Errorf("wlapi: fetch JWT bundle for %q: %w", td, err)
	}
	keys, err := attest.ParseJWKS(jwks)
	if err != nil {
		return attest.Identity{}, fmt.Errorf("wlapi: parse JWT bundle: %w", err)
	}

	// All verification happens here, in attest.
	return attest.VerifySPIFFEJWTSVID(ctx, token, audiences, attest.NewStaticKeySource(keys))
}

// unverifiedSPIFFETrustDomain reads the (unverified) subject of a compact JWT and
// returns its SPIFFE trust domain. Used ONLY to select which trust bundle to
// fetch; it performs no trust decision.
func unverifiedSPIFFETrustDomain(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("wlapi: malformed JWT-SVID")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("wlapi: SVID payload b64: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return "", fmt.Errorf("wlapi: SVID payload json: %w", err)
	}
	u, err := url.Parse(claims.Sub)
	if err != nil || u.Scheme != "spiffe" || u.Hostname() == "" {
		return "", fmt.Errorf("wlapi: subject is not a SPIFFE ID: %q", claims.Sub)
	}
	return u.Hostname(), nil
}
