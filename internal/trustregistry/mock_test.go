package trustregistry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func newTestRegistry(t *testing.T) *MockRegistry {
	t.Helper()
	r, err := NewMockRegistry(":memory:")
	if err != nil {
		t.Fatalf("NewMockRegistry: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func newEd25519PublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return pub
}

func TestRegister_AndLookup(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	pub := newEd25519PublicKey(t)
	rec := &Record{
		Iss:        "domain-a",
		Role:       RoleCTIssuer,
		PublicKey:  pub,
		KeyType:    "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(24 * time.Hour),
		Status:     StatusActive,
		Metadata:   map[string]string{"note": "test"},
	}

	if err := r.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.Lookup(ctx, "domain-a", RoleCTIssuer)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Iss != "domain-a" || got.Role != RoleCTIssuer {
		t.Errorf("Lookup returned wrong record: %+v", got)
	}
	if len(got.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32", len(got.PublicKey))
	}
	if got.Metadata["note"] != "test" {
		t.Errorf("Metadata not loaded: %v", got.Metadata)
	}
}

func TestLookup_NotFound(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	_, err := r.Lookup(ctx, "nope", RoleCTIssuer)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup unknown iss: got err = %v, want ErrNotFound", err)
	}
}

func TestRegister_Conflict(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	rec1 := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Register(ctx, rec1); err != nil {
		t.Fatalf("Register #1: %v", err)
	}

	rec2 := *rec1
	rec2.PublicKey = newEd25519PublicKey(t)
	err := r.Register(ctx, &rec2)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Register: got err = %v, want ErrConflict", err)
	}
}

func TestRevoke_ThenLookupFails(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	rec := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := r.Revoke(ctx, "domain-a", RoleCTIssuer, time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := r.Lookup(ctx, "domain-a", RoleCTIssuer)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup after Revoke: got err = %v, want ErrNotFound", err)
	}
}

func TestRevoke_NotFound(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	err := r.Revoke(ctx, "ghost", RoleCTIssuer, time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke missing: got err = %v, want ErrNotFound", err)
	}
}

func TestLookup_OutsideValidityWindow(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	// Future window.
	rec := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(time.Hour),
		ValidUntil: time.Now().Add(2 * time.Hour),
		Status:     StatusActive,
	}
	if err := r.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := r.Lookup(ctx, "domain-a", RoleCTIssuer)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup pre-window: got err = %v, want ErrNotFound", err)
	}
}

func TestList_FilterByRole(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	ct := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	tts := &Record{
		Iss: "domain-a", Role: RoleTTSIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Register(ctx, ct); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ctx, tts); err != nil {
		t.Fatal(err)
	}

	cts, err := r.List(ctx, RoleCTIssuer)
	if err != nil {
		t.Fatalf("List CTs: %v", err)
	}
	if len(cts) != 1 {
		t.Errorf("List(RoleCTIssuer) = %d records, want 1", len(cts))
	}

	all, err := r.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List(all) = %d records, want 2", len(all))
	}
}

func TestValidate_RejectsInvalidRecords(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	cases := []struct {
		name string
		rec  *Record
	}{
		{"empty iss", &Record{
			Role: RoleCTIssuer, PublicKey: make([]byte, 32), KeyType: "Ed25519",
			ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}},
		{"unknown role", &Record{
			Iss: "x", Role: "made-up", PublicKey: make([]byte, 32), KeyType: "Ed25519",
			ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}},
		{"wrong key length", &Record{
			Iss: "x", Role: RoleCTIssuer, PublicKey: make([]byte, 16), KeyType: "Ed25519",
			ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}},
		{"invalid window", &Record{
			Iss: "x", Role: RoleCTIssuer, PublicKey: make([]byte, 32), KeyType: "Ed25519",
			ValidFrom: time.Now().Add(time.Hour), ValidUntil: time.Now(),
		}},
		{"unsupported key type", &Record{
			Iss: "x", Role: RoleCTIssuer, PublicKey: make([]byte, 32), KeyType: "RSA",
			ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := r.Register(ctx, c.rec)
			if !errors.Is(err, ErrInvalidRecord) {
				t.Errorf("Register: got err = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

// TestReplace_SupersedesActive confirms Replace revokes the prior active
// record and installs the new one, leaving exactly one active record
// (security review SVC-1). Unlike Register, Replace must not return
// ErrConflict on an existing active record.
func TestReplace_SupersedesActive(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	old := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Register(ctx, old); err != nil {
		t.Fatalf("Register old: %v", err)
	}

	newPub := newEd25519PublicKey(t)
	newRec := &Record{
		Iss: "domain-a", Role: RoleCTIssuer,
		PublicKey: newPub, KeyType: "Ed25519",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Replace(ctx, newRec); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := r.Lookup(ctx, "domain-a", RoleCTIssuer)
	if err != nil {
		t.Fatalf("Lookup after Replace: %v", err)
	}
	if string(got.PublicKey) != string(newPub) {
		t.Errorf("active key after Replace is not the new key")
	}

	all, err := r.List(ctx, RoleCTIssuer)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	active := 0
	for _, rec := range all {
		if rec.Status == StatusActive {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active records after Replace = %d, want 1", active)
	}
}

// TestReplace_OnEmptyJustRegisters confirms Replace works when no prior record
// exists (it simply installs the new active record).
func TestReplace_OnEmptyJustRegisters(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	rec := &Record{
		Iss: "fresh", Role: RoleTTSIssuer,
		PublicKey: newEd25519PublicKey(t), KeyType: "Ed25519",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
		Status: StatusActive,
	}
	if err := r.Replace(ctx, rec); err != nil {
		t.Fatalf("Replace on empty: %v", err)
	}
	if _, err := r.Lookup(ctx, "fresh", RoleTTSIssuer); err != nil {
		t.Fatalf("Lookup after Replace on empty: %v", err)
	}
}

// TestValidate_RejectsUnsupportedPQKeyTypes confirms ML-DSA/ML-KEM key types
// are rejected: they are not yet supported and were removed from validKeyTypes
// to avoid advertising types the length check cannot honestly admit (SVC-6).
func TestValidate_RejectsUnsupportedPQKeyTypes(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	for _, kt := range []string{"ML-DSA-44", "ML-DSA-65", "ML-KEM-768"} {
		t.Run(kt, func(t *testing.T) {
			rec := &Record{
				Iss: "x", Role: RoleCTIssuer,
				PublicKey: make([]byte, 32), KeyType: kt,
				ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
				Status: StatusActive,
			}
			if err := r.Register(ctx, rec); !errors.Is(err, ErrInvalidRecord) {
				t.Errorf("Register %s: got err = %v, want ErrInvalidRecord", kt, err)
			}
		})
	}
}

// TestIsCurrentlyValid covers Record.IsCurrentlyValid in isolation.
func TestIsCurrentlyValid(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		rec  *Record
		want bool
	}{
		{"active in window", &Record{
			Status:    StatusActive,
			ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}, true},
		{"revoked even in window", &Record{
			Status:    StatusRevoked,
			ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}, false},
		{"active but before window", &Record{
			Status:    StatusActive,
			ValidFrom: now.Add(time.Hour), ValidUntil: now.Add(2 * time.Hour),
		}, false},
		{"active but after window", &Record{
			Status:    StatusActive,
			ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(-time.Hour),
		}, false},
		{"active at exact ValidFrom", &Record{
			Status:    StatusActive,
			ValidFrom: now, ValidUntil: now.Add(time.Hour),
		}, true},
		{"active at exact ValidUntil (exclusive)", &Record{
			Status:    StatusActive,
			ValidFrom: now.Add(-time.Hour), ValidUntil: now,
		}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rec.IsCurrentlyValid(now); got != c.want {
				t.Errorf("IsCurrentlyValid = %v, want %v", got, c.want)
			}
		})
	}
}
