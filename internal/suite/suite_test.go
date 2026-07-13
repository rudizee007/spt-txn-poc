package suite

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

func edKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// ── test-only fake PQ backend ───────────────────────────────────────────
// Exercises the agility PLUMBING (modes, shape, downgrade) in builds without
// the mldsa tag. It is an HMAC tag, not a signature scheme, lives only in
// _test.go, and can never ship: hybridSuite instances built here are used
// directly, not registered.

type fakePQKey struct{ secret []byte }

func (k fakePQKey) Public() crypto.PublicKey { return k }
func (k fakePQKey) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	m := hmac.New(sha256.New, k.secret)
	m.Write(msg)
	return m.Sum(nil), nil
}

type fakePQ struct{ broken bool }

func (fakePQ) Available() bool { return true }
func (f fakePQ) Sign(signer any, input []byte) ([]byte, error) {
	k := signer.(fakePQKey)
	return k.Sign(nil, input, nil)
}
func (f fakePQ) Verify(pub any, input []byte, sig []byte) error {
	if f.broken {
		return errors.New("fake pq: forced failure")
	}
	k, ok := pub.(fakePQKey)
	if !ok {
		return errors.New("fake pq: wrong key type")
	}
	want, _ := k.Sign(nil, input, nil)
	if !hmac.Equal(want, sig) {
		return errors.New("fake pq: tag mismatch")
	}
	return nil
}

// ── Ed25519 suite ───────────────────────────────────────────────────────

func TestEdDSARoundTrip(t *testing.T) {
	pub, priv := edKeys(t)
	env, err := Seal(SuiteEdDSA, []byte("payload"), PrivateKeySet{Ed25519: priv})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, nil, ""); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	// Payload tamper.
	env.Payload = []byte("payl0ad")
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, nil, ""); err == nil {
		t.Fatal("tampered payload verified")
	}
}

// TestSuiteIDCoveredBySignature is the §4.3 downgrade test: rewriting the
// outer suite identifier must invalidate the envelope, because the verifier
// reconstructs the signing input from the outer id.
func TestSuiteIDCoveredBySignature(t *testing.T) {
	pub, priv := edKeys(t)
	env, err := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: priv})
	if err != nil {
		t.Fatal(err)
	}
	env.Suite = SuiteHybrid // attacker rewrites dispatch field
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyEither, nil, ""); err == nil {
		t.Fatal("suite-rewritten envelope verified")
	}
	// And the reverse: signing input for one suite never verifies as another.
	in1 := SigningInput(SuiteEdDSA, []byte("p"))
	in2 := SigningInput(SuiteHybrid, []byte("p"))
	if bytes.Equal(in1, in2) {
		t.Fatal("signing inputs not domain-separated by suite")
	}
	// Injectivity across the suite/payload boundary.
	if bytes.Equal(SigningInput("A", []byte("Bp")), SigningInput("AB", []byte("p"))) {
		t.Fatal("suite/payload boundary not injective")
	}
}

func TestUnknownSuiteRejected(t *testing.T) {
	pub, priv := edKeys(t)
	env, _ := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: priv})
	env.Suite = "NONE"
	err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, nil, "")
	if !errors.Is(err, ErrUnknownSuite) && !errors.Is(err, ErrVerify) {
		// Allowlist rejection (unknown id) is the expected path.
		t.Fatalf("got %v", err)
	}
	if err == nil {
		t.Fatal("unknown suite accepted")
	}
}

func TestModeMustBeConfigured(t *testing.T) {
	pub, priv := edKeys(t)
	env, _ := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: priv})
	if err := Verify(env, PublicKeySet{Ed25519: pub}, 0, nil, ""); !errors.Is(err, ErrBadMode) {
		t.Fatalf("zero mode accepted (err=%v); modes are never inferred", err)
	}
}

// ── jurisdiction floors ─────────────────────────────────────────────────

func TestFloorRejectsBeforeSignatureDispatch(t *testing.T) {
	pub, priv := edKeys(t)
	env, err := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: priv})
	if err != nil {
		t.Fatal(err)
	}
	floors := Floors{"EU-STRICT": {SuiteHybrid}, "GLOBAL": {SuiteEdDSA, SuiteHybrid}}

	// Valid classical signature, but the profile demands hybrid: violation.
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, floors, "EU-STRICT"); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("classical accepted under hybrid floor (err=%v)", err)
	}
	// Permissive profile accepts it.
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, floors, "GLOBAL"); err != nil {
		t.Fatalf("GLOBAL profile rejected valid EdDSA: %v", err)
	}
	// Unknown profile fails closed.
	if err := Verify(env, PublicKeySet{Ed25519: pub}, ModeVerifyBoth, floors, "NO-SUCH"); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("unknown profile did not fail closed (err=%v)", err)
	}
}

// ── hybrid plumbing via fake PQ backend ─────────────────────────────────

func TestHybridModes(t *testing.T) {
	edPub, edPriv := edKeys(t)
	pqKey := fakePQKey{secret: []byte("k")}
	good := hybridSuite{pq: fakePQ{}}

	input := SigningInput(SuiteHybrid, []byte("p"))
	sigs, err := good.Sign(PrivateKeySet{Ed25519: edPriv, PQ: pqKey}, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("hybrid produced %d sigs", len(sigs))
	}
	keys := PublicKeySet{Ed25519: edPub, PQ: pqKey}

	// Both valid → both modes pass.
	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := good.Verify(keys, input, sigs, m); err != nil {
			t.Fatalf("mode %v rejected fully valid hybrid: %v", m, err)
		}
	}

	// PQ half broken → either passes, both fails (transition semantics).
	broken := hybridSuite{pq: fakePQ{broken: true}}
	if err := broken.Verify(keys, input, sigs, ModeVerifyEither); err != nil {
		t.Fatalf("verify-either rejected valid classical half: %v", err)
	}
	if err := broken.Verify(keys, input, sigs, ModeVerifyBoth); err == nil {
		t.Fatal("verify-both accepted with failing PQ half")
	}

	// Classical half corrupted → either still passes via PQ; both fails.
	badEd := [][]byte{append([]byte{}, sigs[0]...), sigs[1]}
	badEd[0][0] ^= 1
	if err := good.Verify(keys, input, badEd, ModeVerifyEither); err != nil {
		t.Fatalf("verify-either rejected valid PQ half: %v", err)
	}
	if err := good.Verify(keys, input, badEd, ModeVerifyBoth); err == nil {
		t.Fatal("verify-both accepted with corrupted classical half")
	}

	// Downgrade by subtraction: omitting a signature is malformed in EVERY
	// mode — "either" must not mean "whichever half the attacker kept".
	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := good.Verify(keys, input, sigs[:1], m); !errors.Is(err, ErrBadEnvelope) {
			t.Fatalf("mode %v: single-sig hybrid not rejected as malformed (err=%v)", m, err)
		}
		if err := good.Verify(keys, input, [][]byte{sigs[0], nil}, m); !errors.Is(err, ErrBadEnvelope) {
			t.Fatalf("mode %v: empty PQ sig not rejected as malformed (err=%v)", m, err)
		}
	}
}

// ── stub behavior in default builds ─────────────────────────────────────

func TestHybridUnavailableFailsClosed(t *testing.T) {
	impl, err := lookup(SuiteHybrid)
	if err != nil {
		t.Fatalf("hybrid suite not registered: %v", err)
	}
	_, edPriv := edKeys(t)
	input := SigningInput(SuiteHybrid, []byte("p"))

	if _, ok := impl.(hybridSuite); ok && !impl.(hybridSuite).pq.Available() {
		// Default build: both operations must fail closed as UNAVAILABLE
		// (never fall back to classical-only).
		if _, err := impl.Sign(PrivateKeySet{Ed25519: edPriv}, input); !errors.Is(err, ErrSuiteUnavailable) {
			t.Fatalf("stub Sign: %v", err)
		}
		if err := impl.Verify(PublicKeySet{}, input, [][]byte{{1}, {2}}, ModeVerifyBoth); !errors.Is(err, ErrSuiteUnavailable) {
			t.Fatalf("stub Verify: %v", err)
		}
	}
}
