package escrow_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/escrow"
)

func TestEnvelope_SealOpenRoundtrip(t *testing.T) {
	esk, err := escrow.NewEscrowKey()
	if err != nil {
		t.Fatal(err)
	}
	identity := []byte("did:zk:alice-real-identity")
	env, err := escrow.Seal(identity, esk.PublicKey(), "anchor-hex-1", "domain-a.authorg", time.Now().Unix())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := env.Open(esk)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(identity) {
		t.Errorf("roundtrip mismatch: got %q", got)
	}
}

func TestEnvelope_AADTamperDetected(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)
	env.HumanAnchor = "anchor-2" // re-point the envelope at a different anchor
	if _, err := env.Open(esk); err == nil {
		t.Error("a tampered AAD field must make Open fail")
	}
}

func TestEnvelope_WrongKeyFails(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	other, _ := escrow.NewEscrowKey()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)
	if _, err := env.Open(other); err == nil {
		t.Error("opening with the wrong escrow key must fail")
	}
}

func TestDeanon_Flow(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	vault := escrow.NewVault()
	identity := []byte("did:zk:alice")
	env, _ := escrow.Seal(identity, esk.PublicKey(), "anchor-A", "domain-a.authorg", time.Now().Unix())
	if err := vault.Store(env); err != nil {
		t.Fatal(err)
	}
	// Storing a second envelope for the same anchor is refused.
	if err := vault.Store(env); err != escrow.ErrExists {
		t.Errorf("duplicate store: want ErrExists, got %v", err)
	}

	h := escrow.NewHandler(vault, esk)
	reqPub, reqPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.AddSigner("regulator-1", reqPub)

	// Authorized + signed + lawful basis -> recovers the identity.
	good := &escrow.Request{HumanAnchor: "anchor-A", Requester: "regulator-1", LawfulBasis: "court-order-42", IssuedAt: time.Now().Unix()}
	good.Sign(reqPriv)
	got, err := h.Deanonymize(good)
	if err != nil {
		t.Fatalf("authorized deanon: %v", err)
	}
	if string(got) != string(identity) {
		t.Errorf("recovered %q, want %q", got, identity)
	}

	// Unauthorized requester.
	un := &escrow.Request{HumanAnchor: "anchor-A", Requester: "unknown", LawfulBasis: "x", IssuedAt: time.Now().Unix()}
	un.Sign(reqPriv)
	if _, err := h.Deanonymize(un); err != escrow.ErrUnauthorized {
		t.Errorf("unauthorized: want ErrUnauthorized, got %v", err)
	}

	// No lawful basis.
	nb := &escrow.Request{HumanAnchor: "anchor-A", Requester: "regulator-1", LawfulBasis: "", IssuedAt: time.Now().Unix()}
	nb.Sign(reqPriv)
	if _, err := h.Deanonymize(nb); err != escrow.ErrNoLawfulBasis {
		t.Errorf("no basis: want ErrNoLawfulBasis, got %v", err)
	}

	// Signature by a non-authorized key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	bad := &escrow.Request{HumanAnchor: "anchor-A", Requester: "regulator-1", LawfulBasis: "court-order", IssuedAt: time.Now().Unix()}
	bad.Sign(otherPriv)
	if _, err := h.Deanonymize(bad); err != escrow.ErrBadSignature {
		t.Errorf("bad sig: want ErrBadSignature, got %v", err)
	}

	// Unknown anchor.
	miss := &escrow.Request{HumanAnchor: "anchor-MISSING", Requester: "regulator-1", LawfulBasis: "court-order", IssuedAt: time.Now().Unix()}
	miss.Sign(reqPriv)
	if _, err := h.Deanonymize(miss); err != escrow.ErrNotFound {
		t.Errorf("missing anchor: want ErrNotFound, got %v", err)
	}
}

func TestDeanon_ReplayAndStaleRejected(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	vault := escrow.NewVault()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-R", "iss", time.Now().Unix())
	if err := vault.Store(env); err != nil {
		t.Fatal(err)
	}
	h := escrow.NewHandler(vault, esk)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.AddSigner("reg", pub)

	// A fresh, valid request succeeds once.
	r := &escrow.Request{HumanAnchor: "anchor-R", Requester: "reg", LawfulBasis: "court-order", IssuedAt: time.Now().Unix()}
	r.Sign(priv)
	if _, err := h.Deanonymize(r); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// The exact same signed request replayed must be rejected.
	if _, err := h.Deanonymize(r); err != escrow.ErrReplay {
		t.Errorf("replay: want ErrReplay, got %v", err)
	}

	// A request with a stale timestamp must be rejected.
	stale := &escrow.Request{HumanAnchor: "anchor-R", Requester: "reg", LawfulBasis: "court-order", IssuedAt: time.Now().Add(-1 * time.Hour).Unix()}
	stale.Sign(priv)
	if _, err := h.Deanonymize(stale); err != escrow.ErrStaleRequest {
		t.Errorf("stale: want ErrStaleRequest, got %v", err)
	}
}
