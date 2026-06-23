package escrow

// vault.go — storage for escrow envelopes, keyed by humanAnchor. In the POC it
// is an in-memory map (consistent with the SQLite-free, pure-Go approach used
// elsewhere on OpenBSD); the interface is what a persistent backend would
// implement in production. The vault runs as a separate service under its own
// user (_sptesc) so the escrow private key is isolated from the issuers.

import (
	"errors"
	"sync"
)

// ErrNotFound is returned when no envelope exists for a humanAnchor.
var ErrNotFound = errors.New("escrow: no envelope for humanAnchor")

// ErrExists is returned when storing over an existing envelope.
var ErrExists = errors.New("escrow: envelope already exists for humanAnchor")

// Vault stores escrow envelopes keyed by humanAnchor.
type Vault struct {
	mu sync.RWMutex
	m  map[string]*Envelope
}

// NewVault creates an empty vault.
func NewVault() *Vault {
	return &Vault{m: make(map[string]*Envelope)}
}

// Store inserts an envelope. It refuses to overwrite an existing one — a second
// envelope for the same humanAnchor would be an integrity anomaly.
func (v *Vault) Store(env *Envelope) error {
	if env == nil || env.HumanAnchor == "" {
		return errors.New("escrow: envelope missing humanAnchor")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.m[env.HumanAnchor]; exists {
		return ErrExists
	}
	v.m[env.HumanAnchor] = env
	return nil
}

// Get returns the envelope for a humanAnchor.
func (v *Vault) Get(humanAnchor string) (*Envelope, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	env, ok := v.m[humanAnchor]
	if !ok {
		return nil, ErrNotFound
	}
	return env, nil
}

// Len reports how many envelopes are stored.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.m)
}
