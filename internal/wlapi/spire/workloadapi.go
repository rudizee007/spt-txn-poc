// Package spire is the production SPIFFE Workload API adapter for internal/wlapi.
//
// It implements wlapi.Source by talking to a local SPIRE agent over the Workload
// API unix socket (SPIFFE_ENDPOINT_SOCKET), and offers VerifiedIdentity as a
// one-call convenience that fetches and then verifies via the parent's wlapi +
// attest packages. All signature/trust verification stays in attest; this
// package only does the SPIFFE I/O, and lives in its own module so go-spiffe's
// grpc/protobuf dependencies never enter the parent module's graph.
//
// Usage (requires a running SPIRE agent):
//
//	cd internal/wlapi/spire && go mod tidy && go build ./...
//	# SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
//	id, err := spire.VerifiedIdentity(ctx, []string{"spt-txn-exchange"})
package spire

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/wlapi"
)

// Source satisfies wlapi.Source using a SPIFFE Workload API client.
var _ wlapi.Source = (*Source)(nil)

// Source is a wlapi.Source backed by a SPIFFE Workload API client.
type Source struct {
	client *workloadapi.Client
}

// New dials the Workload API. With no options it uses SPIFFE_ENDPOINT_SOCKET;
// pass workloadapi.WithAddr("unix:///path/agent.sock") to override.
func New(ctx context.Context, opts ...workloadapi.ClientOption) (*Source, error) {
	c, err := workloadapi.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Source{client: c}, nil
}

// Close releases the Workload API connection.
func (s *Source) Close() error { return s.client.Close() }

// FetchJWTSVID implements wlapi.Source.
func (s *Source) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	svid, err := s.client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// FetchJWTBundles implements wlapi.Source: returns the JWKS for trustDomain.
func (s *Source) FetchJWTBundles(ctx context.Context, trustDomain string) ([]byte, error) {
	set, err := s.client.FetchJWTBundles(ctx)
	if err != nil {
		return nil, err
	}
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, err
	}
	b, err := set.GetJWTBundleForTrustDomain(td)
	if err != nil {
		return nil, err
	}
	return b.Marshal()
}

// VerifiedIdentity dials the Workload API, fetches an SVID for the first
// audience and its trust bundle, and returns a verified attest.Identity (all
// verification delegated to wlapi/attest). Fails closed on any error.
func VerifiedIdentity(ctx context.Context, audiences []string, opts ...workloadapi.ClientOption) (attest.Identity, error) {
	src, err := New(ctx, opts...)
	if err != nil {
		return attest.Identity{}, err
	}
	defer func() { _ = src.Close() }()
	return wlapi.VerifiedIdentity(ctx, src, audiences)
}
