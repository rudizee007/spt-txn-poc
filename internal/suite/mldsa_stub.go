//go:build !mldsa

package suite

// mldsa_stub.go — default build: the hybrid suite is REGISTERED (so its
// identifier is allowlisted and its envelope shape parses and tests) but all
// PQ operations fail closed with ErrSuiteUnavailable. Callers map this to
// decision class `unavailable` — never a silent fallback to classical.
//
// Build with -tags mldsa (and `go get filippo.io/mldsa`) for the real
// backend; see mldsa_backend.go.

import "errors"

type pqStub struct{}

func (pqStub) Available() bool { return false }

func (pqStub) Sign(any, []byte) ([]byte, error) {
	return nil, errors.New("ml-dsa backend not compiled in")
}

func (pqStub) Verify(any, []byte, []byte) error {
	return errors.New("ml-dsa backend not compiled in")
}

func init() { Register(hybridSuite{pq: pqStub{}}) }
