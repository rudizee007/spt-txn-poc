//go:build mldsa

package suite

// Real-backend hybrid tests. Run with:
//
//	go get filippo.io/mldsa && go test -tags mldsa ./internal/suite/

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"filippo.io/mldsa"
)

func TestHybridRealRoundTrip(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	env, err := Seal(SuiteHybrid, []byte("payload"), PrivateKeySet{Ed25519: edPriv, PQ: sk})
	if err != nil {
		t.Fatal(err)
	}
	keys := PublicKeySet{Ed25519: edPub, PQ: sk.PublicKey()}

	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := Verify(env, keys, m, nil, ""); err != nil {
			t.Fatalf("mode %v: valid hybrid rejected: %v", m, err)
		}
	}

	// Tamper with payload → both modes reject.
	bad := *env
	bad.Payload = []byte("payl0ad")
	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := Verify(&bad, keys, m, nil, ""); err == nil {
			t.Fatalf("mode %v: tampered hybrid verified", m)
		}
	}

	// Downgrade: rewriting the outer suite to classical must fail — the
	// signing input committed to the hybrid identifier, and shape (2 sigs)
	// no longer matches EdDSA.
	down := *env
	down.Suite = SuiteEdDSA
	if err := Verify(&down, keys, ModeVerifyEither, nil, ""); err == nil {
		t.Fatal("downgraded envelope verified")
	}

	// Wrong parameter set rejected.
	sk44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(SuiteHybrid, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk44}); err == nil {
		t.Fatal("ML-DSA-44 key accepted by an ML-DSA-65 suite")
	}
}

func TestHybridRealFloorStrict(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(nil)
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	floors := Floors{"CNSA2": {SuiteHybrid}}

	env, err := Seal(SuiteHybrid, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, PublicKeySet{Ed25519: edPub, PQ: sk.PublicKey()}, ModeVerifyBoth, floors, "CNSA2"); err != nil {
		t.Fatalf("hybrid under hybrid floor rejected: %v", err)
	}

	classical, _ := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: edPriv})
	if err := Verify(classical, PublicKeySet{Ed25519: edPub}, ModeVerifyBoth, floors, "CNSA2"); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("classical under CNSA2 floor: %v", err)
	}
}
