package trisatransport

import (
	"context"
	"crypto/rsa"
)

// Counterparty is a resolved TRISA member: who they are and how to reach them.
type Counterparty struct {
	ID         string         // GDS / directory identifier (e.g. common name or UUID)
	CommonName string         // certificate common name
	Endpoint   string         // host:port of their TRISA node
	SealingKey *rsa.PublicKey // public key to seal envelopes to (from cert / KeyExchange)
}

// Transport is the network seam. The sealing core (Seal/Open) is transport-
// agnostic; a concrete implementation carries SecureEnvelopes over TRISA's gRPC
// with mutual-TLS and resolves counterparties via the Global Directory Service.
//
// That concrete implementation is intentionally NOT in this module: it requires
// the TRISA Go SDK, grpc, protobuf, an mTLS identity certificate registered at
// trisa.directory, and GDS access — none of which is needed to build, test, or
// reason about the sealing scheme. Implement this interface in a build-tagged or
// separate package once certificate onboarding is done.
type Transport interface {
	// KeyExchange fetches the counterparty's current sealing public key.
	KeyExchange(ctx context.Context, counterpartyID string) (*rsa.PublicKey, error)

	// Lookup resolves a counterparty via the directory (GDS).
	Lookup(ctx context.Context, query string) (*Counterparty, error)

	// Transfer sends a sealed envelope to the counterparty's TRISA node and
	// returns their sealed response envelope.
	Transfer(ctx context.Context, counterpartyID string, env *SecureEnvelope) (*SecureEnvelope, error)
}

// SendSealed is the high-level helper: resolve the counterparty's key, seal the
// payload to it, and send. It captures the correct ordering so callers can't
// accidentally send an unsealed payload.
func SendSealed(ctx context.Context, t Transport, counterpartyID string, payload []byte) (*SecureEnvelope, error) {
	pub, err := t.KeyExchange(ctx, counterpartyID)
	if err != nil {
		return nil, err
	}
	env, err := Seal(payload, pub, counterpartyID)
	if err != nil {
		return nil, err
	}
	return t.Transfer(ctx, counterpartyID, env)
}
