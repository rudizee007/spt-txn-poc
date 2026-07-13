package statuslist

import (
	"crypto/ed25519"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func TestGetSetAllWidths(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		l, err := New(bits, 100)
		if err != nil {
			t.Fatal(err)
		}
		// Modulus in int: for bits=8 the max value is 255 and (255+1) overflows
		// a uint8 Status to 0, so the range arithmetic must not be done in Status.
		mod := 1 << bits
		// Set a pattern.
		for i := 0; i < 100; i++ {
			if err := l.Set(i, Status(i%mod)); err != nil {
				t.Fatalf("bits=%d set %d: %v", bits, i, err)
			}
		}
		for i := 0; i < 100; i++ {
			got, err := l.Get(i)
			if err != nil {
				t.Fatal(err)
			}
			if want := Status(i % mod); got != want {
				t.Fatalf("bits=%d idx=%d got %d want %d", bits, i, got, want)
			}
		}
	}
}

func TestSetRejectsOverWidth(t *testing.T) {
	l, _ := New(1, 8)
	if err := l.Set(0, StatusSuspended); !errors.Is(err, ErrStatusSize) {
		t.Fatalf("1-bit list accepted status 2: %v", err)
	}
	if err := l.Set(0, StatusInvalid); err != nil {
		t.Fatalf("1-bit list rejected status 1: %v", err)
	}
}

func TestIndexBounds(t *testing.T) {
	l, _ := New(2, 4)
	if _, err := l.Get(4); !errors.Is(err, ErrIndex) {
		t.Fatal("out-of-range Get accepted")
	}
	if err := l.Set(-1, StatusValid); !errors.Is(err, ErrIndex) {
		t.Fatal("negative Set accepted")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, bits := range []int{1, 2, 4, 8} {
		n := 500 + rng.Intn(500)
		l, _ := New(bits, n)
		want := make([]Status, n)
		maxV := 1 << bits
		for i := 0; i < n; i++ {
			s := Status(rng.Intn(maxV))
			want[i] = s
			if err := l.Set(i, s); err != nil {
				t.Fatal(err)
			}
		}
		enc, err := l.Encode()
		if err != nil {
			t.Fatal(err)
		}
		dec, err := Decode(enc, n)
		if err != nil {
			t.Fatalf("decode bits=%d: %v", bits, err)
		}
		if dec.Len() != n || dec.Bits() != bits {
			t.Fatalf("decoded shape bits=%d len=%d", dec.Bits(), dec.Len())
		}
		for i := 0; i < n; i++ {
			got, _ := dec.Get(i)
			if got != want[i] {
				t.Fatalf("bits=%d idx=%d got %d want %d", bits, i, got, want[i])
			}
		}
	}
}

func statusKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerifyToken(t *testing.T) {
	pub, priv := statusKeys(t)
	l, _ := New(1, 1000)
	_ = l.Set(42, StatusInvalid)
	_ = l.Set(43, StatusValid)
	uri := "https://issuer.example/statuslists/9"
	now := time.Now()

	tok, err := SignToken(l, uri, now, time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyToken(tok, uri, pub, now)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if s, _ := got.Get(42); s != StatusInvalid {
		t.Fatalf("idx42 = %d, want revoked", s)
	}
	if s, _ := got.Get(43); s != StatusValid {
		t.Fatalf("idx43 = %d, want valid", s)
	}

	// Expired.
	if _, err := VerifyToken(tok, uri, pub, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token accepted: %v", err)
	}
	// Wrong uri (sub mismatch).
	if _, err := VerifyToken(tok, "https://issuer.example/statuslists/OTHER", pub, now); !errors.Is(err, ErrSubject) {
		t.Fatalf("sub mismatch accepted: %v", err)
	}
	// Wrong key.
	otherPub, _ := statusKeys(t)
	if _, err := VerifyToken(tok, uri, otherPub, now); !errors.Is(err, ErrSig) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	// Tampered signature.
	if _, err := VerifyToken(tok[:len(tok)-2]+"AA", uri, pub, now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestResolverCheck(t *testing.T) {
	pub, priv := statusKeys(t)
	l, _ := New(2, 100)
	_ = l.Set(10, StatusValid)
	_ = l.Set(11, StatusInvalid)
	_ = l.Set(12, StatusSuspended)
	uri := "https://issuer.example/sl/1"
	now := time.Now()
	tok, _ := SignToken(l, uri, now, time.Hour, priv)

	r := NewResolver()
	if err := r.AddVerified(tok, uri, pub, now); err != nil {
		t.Fatal(err)
	}

	if err := r.Check(Reference{Index: 10, URI: uri}); err != nil {
		t.Fatalf("valid entry denied: %v", err)
	}
	if err := r.Check(Reference{Index: 11, URI: uri}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked not detected: %v", err)
	}
	if err := r.Check(Reference{Index: 12, URI: uri}); !errors.Is(err, ErrSuspended) {
		t.Fatalf("suspended not detected: %v", err)
	}
	// Uncached uri ⇒ unavailable (fail closed).
	if err := r.Check(Reference{Index: 0, URI: "https://unknown"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("uncached list not unavailable: %v", err)
	}
	// Out-of-range index ⇒ unknown (fail closed), never valid.
	if err := r.Check(Reference{Index: 9999, URI: uri}); !errors.Is(err, ErrUnknown) {
		t.Fatalf("out-of-range not failed closed: %v", err)
	}
}

func TestReferenceFromClaims(t *testing.T) {
	// Present.
	ref, ok, err := ReferenceFromClaims(map[string]any{
		"status": map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": "u"}},
	})
	if err != nil || !ok || ref.Index != 7 || ref.URI != "u" {
		t.Fatalf("present: %+v ok=%v err=%v", ref, ok, err)
	}
	// Absent (no status claim) ⇒ ok=false, no error.
	if _, ok, err := ReferenceFromClaims(map[string]any{"sub": "x"}); ok || err != nil {
		t.Fatalf("absent should be ok=false,nil-err; got ok=%v err=%v", ok, err)
	}
	// Malformed (status without status_list) ⇒ error (fail closed).
	if _, _, err := ReferenceFromClaims(map[string]any{"status": map[string]any{"x": 1}}); err == nil {
		t.Fatal("malformed status accepted")
	}
	// status_list without uri ⇒ error.
	if _, _, err := ReferenceFromClaims(map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": float64(1)}}}); err == nil {
		t.Fatal("missing uri accepted")
	}
}

func TestAlgNoneRejected(t *testing.T) {
	pub, priv := statusKeys(t)
	l, _ := New(1, 10)
	uri := "u"
	tok, _ := SignToken(l, uri, time.Now(), time.Hour, priv)
	// Swap header to alg:none by re-encoding — simplest is to check VerifyToken
	// rejects a token whose header alg isn't EdDSA. Forge a header.
	forged := b64([]byte(`{"alg":"none","typ":"statuslist+jwt"}`)) + ".x.y"
	if _, err := VerifyToken(forged, uri, pub, time.Now()); !errors.Is(err, ErrAlg) && !errors.Is(err, ErrToken) {
		t.Fatalf("alg:none not rejected: %v", err)
	}
	_ = tok
}

// FuzzDecode: Decode must never panic and must reject malformed input.
func FuzzDecode(f *testing.F) {
	l, _ := New(1, 64)
	_ = l.Set(3, StatusInvalid)
	enc, _ := l.Encode()
	f.Add(enc.Lst, 1, 64)
	f.Add("not-base64!!", 1, 10)
	f.Add("", 2, 0)
	f.Fuzz(func(t *testing.T, lst string, bits, entries int) {
		_, _ = Decode(Encoded{Bits: bits, Lst: lst}, entries) // must not panic
	})
}
