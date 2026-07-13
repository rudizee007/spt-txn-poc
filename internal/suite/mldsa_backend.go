//go:build mldsa

package suite

// mldsa_backend.go — real ML-DSA-65 (FIPS 204) backend via filippo.io/mldsa,
// a pure-Go audited-lineage implementation (no cgo — CLAUDE.md §2 memory
// safety holds). Enable with:
//
//	go get filippo.io/mldsa
//	go build -tags mldsa ./...
//
// When crypto/mldsa lands in the Go standard library (public API targeted
// for Go 1.27) this file swaps imports without touching call sites.

import (
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

type pqReal struct{}

func (pqReal) Available() bool { return true }

func (pqReal) Sign(signer any, input []byte) ([]byte, error) {
	sk, ok := signer.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.New("ml-dsa: signer is not *mldsa.PrivateKey")
	}
	if sk.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, fmt.Errorf("ml-dsa: suite requires ML-DSA-65, key is %s", sk.PublicKey().Parameters())
	}
	// Hedged (randomized) signing per FIPS 204; context binds the suite use.
	return sk.Sign(nil, input, &mldsa.Options{Context: SuiteHybrid})
}

func (pqReal) Verify(pub any, input []byte, sig []byte) error {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return errors.New("ml-dsa: public key is not *mldsa.PublicKey")
	}
	if pk.Parameters() != mldsa.MLDSA65() {
		return fmt.Errorf("ml-dsa: suite requires ML-DSA-65, key is %s", pk.Parameters())
	}
	return mldsa.Verify(pk, input, sig, &mldsa.Options{Context: SuiteHybrid})
}

func init() { Register(hybridSuite{pq: pqReal{}}) }
