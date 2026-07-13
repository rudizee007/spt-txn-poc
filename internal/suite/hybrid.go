package suite

// hybrid.go — shared skeleton of the HYBRID-Ed25519-MLDSA65 suite. The
// classical half and all agility plumbing (signature counting, mode
// semantics, envelope shape) are always compiled and tested; only the
// post-quantum primitive itself is swapped by build tag:
//
//	go build            → mldsa_stub.go: PQ operations fail closed
//	go build -tags mldsa → mldsa_backend.go: filippo.io/mldsa (ML-DSA-65)
//
// Sigs order is fixed: [0] Ed25519, [1] ML-DSA-65. Both signatures are
// always PRESENT in a hybrid envelope; the verification Mode only governs
// acceptance, never shape.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// pqBackend is the tag-selected ML-DSA-65 implementation.
type pqBackend interface {
	// Available reports whether real PQ operations exist in this build.
	Available() bool
	Sign(signer any, input []byte) ([]byte, error)
	Verify(pub any, input []byte, sig []byte) error
}

type hybridSuite struct{ pq pqBackend }

func (hybridSuite) ID() string { return SuiteHybrid }

func (h hybridSuite) Sign(keys PrivateKeySet, input []byte) ([][]byte, error) {
	if !h.pq.Available() {
		return nil, fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, SuiteHybrid)
	}
	if len(keys.Ed25519) != ed25519.PrivateKeySize {
		return nil, errors.New("suite: hybrid: missing or malformed Ed25519 private key")
	}
	if keys.PQ == nil {
		return nil, errors.New("suite: hybrid: missing ML-DSA private key")
	}
	edSig := ed25519.Sign(keys.Ed25519, input)
	pqSig, err := h.pq.Sign(keys.PQ, input)
	if err != nil {
		return nil, fmt.Errorf("suite: hybrid: ML-DSA sign: %w", err)
	}
	return [][]byte{edSig, pqSig}, nil
}

func (h hybridSuite) Verify(keys PublicKeySet, input []byte, sigs [][]byte, mode Mode) error {
	// Shape first: a hybrid envelope ALWAYS carries both signatures. An
	// envelope missing one is malformed regardless of mode — otherwise
	// "either" mode would let an attacker simply omit the half they cannot
	// forge, which is a downgrade by subtraction.
	if len(sigs) != 2 {
		return fmt.Errorf("%w: hybrid expects exactly 2 signatures, got %d", ErrBadEnvelope, len(sigs))
	}
	if len(sigs[0]) == 0 || len(sigs[1]) == 0 {
		return fmt.Errorf("%w: hybrid signature missing", ErrBadEnvelope)
	}
	if !h.pq.Available() {
		return fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, SuiteHybrid)
	}

	classicalOK := len(keys.Ed25519) == ed25519.PublicKeySize &&
		len(sigs[0]) == ed25519.SignatureSize &&
		ed25519.Verify(keys.Ed25519, input, sigs[0])
	pqErr := h.pq.Verify(keys.PQ, input, sigs[1])

	switch mode {
	case ModeVerifyBoth:
		if !classicalOK || pqErr != nil {
			return ErrVerify
		}
		return nil
	case ModeVerifyEither:
		if classicalOK || pqErr == nil {
			return nil
		}
		return ErrVerify
	default:
		return ErrBadMode
	}
}
