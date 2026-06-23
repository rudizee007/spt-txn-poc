package vaspregistry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/vaspregistry"
)

func TestRegistry_MembershipRootSign(t *testing.T) {
	members := []string{"vasp:violet-sky", "vasp:beneficiary-bank", "vasp:acme-exchange"}
	reg, err := vaspregistry.FromMembers(members)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Has("vasp:beneficiary-bank") {
		t.Error("a registered member must be present")
	}
	if reg.Has("vasp:not-registered") {
		t.Error("a non-member must be absent")
	}
	if reg.Count() != 3 {
		t.Errorf("count = %d, want 3", reg.Count())
	}

	// Same members -> same root (so two parties share one registry view).
	reg2, _ := vaspregistry.FromMembers(members)
	if reg.Root().Cmp(reg2.Root()) != 0 {
		t.Error("identical membership must yield the same root")
	}
	// Different membership -> different root.
	reg3, _ := vaspregistry.FromMembers([]string{"vasp:violet-sky", "vasp:acme-exchange"})
	if reg.Root().Cmp(reg3.Root()) == 0 {
		t.Error("different membership must yield a different root")
	}

	// Signed root verifies under the authority key only.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sr := reg.Publish(priv)
	if sr.Root != reg.Root().Text(10) {
		t.Error("published root value mismatch")
	}
	if !vaspregistry.VerifyRoot(sr, pub) {
		t.Error("signed root must verify with the authority key")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if vaspregistry.VerifyRoot(sr, other) {
		t.Error("signed root must not verify with a different key")
	}
}

func TestRegistry_LoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reg.json")
	if err := os.WriteFile(path, []byte(`{"vasps":["vasp:a","vasp:beneficiary-bank","vasp:c"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := vaspregistry.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reg.Has("vasp:beneficiary-bank") || reg.Count() != 3 {
		t.Errorf("loaded registry wrong: has=%v count=%d", reg.Has("vasp:beneficiary-bank"), reg.Count())
	}
}
