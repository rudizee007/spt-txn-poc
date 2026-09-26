package verifier

// White-box tests of the single-use record keys, the proof record's lifetime,
// and when step 5 records a proof. scripts/mutate-single-use-records.sh reverts
// each control and requires the named test to fail.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"testing/quick"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/dpop"
)

const (
	recordTestHTM   = "POST"
	recordTestHTU   = "https://verifier.example/verify"
	recordTestToken = "presented.token.value"
)

func recordTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func recordTestProof(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	proof, err := dpop.Proof(priv, recordTestHTM, recordTestHTU, dpop.ATH(recordTestToken))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// recordTestProofIssuedAt builds a DPoP proof the way dpop.Proof does, with the
// iat given.
func recordTestProofIssuedAt(t *testing.T, priv ed25519.PrivateKey, iat int64) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	header := map[string]any{"typ": "dpop+jwt", "alg": "EdDSA",
		"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}}
	claims := map[string]any{"jti": fmt.Sprintf("issued-%d", iat), "htm": recordTestHTM, "htu": recordTestHTU,
		"iat": iat, "ath": dpop.ATH(recordTestToken)}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

// heldBy is the part of an SPT-Txn's claims step 5 reads: the key it is bound to.
func heldBy(pub ed25519.PublicKey) map[string]any {
	return map[string]any{"cnf": map[string]any{"jkt": dpop.Thumbprint(pub)}}
}

// TestRecordKeysOfDifferentKindsNeverCompareEqual: whatever identifiers they
// are built from, records of different kinds are different keys.
func TestRecordKeysOfDifferentKindsNeverCompareEqual(t *testing.T) {
	prop := func(a, b string, leg int64) bool {
		return proofRecord(a, b) != txnRecord(b) &&
			proofRecord(a, b) != sliceRecord(a, leg) &&
			txnRecord(b) != sliceRecord(a, leg) &&
			txnRecord(a) != sliceRecord(a, leg)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "0", "id", "id-1"} {
		if proofRecord(v, v) == txnRecord(v) || proofRecord("", v) == txnRecord(v) ||
			proofRecord(v, v) == sliceRecord(v, 0) || txnRecord(v) == sliceRecord(v, 0) ||
			txnRecord(v) == sliceRecord("", 0) {
			t.Fatalf("records of different kinds share a key for identifier %q", v)
		}
	}
}

// TestRecordKeysIdentifyExactlyOneRecord: a key equals one built from the same
// inputs, so a second use is found, and differs from one built from any
// different input, so one use never stands in for another.
func TestRecordKeysIdentifyExactlyOneRecord(t *testing.T) {
	cfg := &quick.Config{MaxCount: 2000}
	for name, prop := range map[string]any{
		"proof, by key": func(k1, k2, jti string) bool {
			return (k1 == k2) == (proofRecord(k1, jti) == proofRecord(k2, jti))
		},
		"proof, by jti": func(jkt, j1, j2 string) bool {
			return (j1 == j2) == (proofRecord(jkt, j1) == proofRecord(jkt, j2))
		},
		"SPT-Txn, by jti": func(j1, j2 string) bool {
			return (j1 == j2) == (txnRecord(j1) == txnRecord(j2))
		},
		"slice, by root": func(r1, r2 string, leg int64) bool {
			return (r1 == r2) == (sliceRecord(r1, leg) == sliceRecord(r2, leg))
		},
		"slice, by leg": func(root string, l1, l2 int64) bool {
			return (l1 == l2) == (sliceRecord(root, l1) == sliceRecord(root, l2))
		},
	} {
		if err := quick.Check(prop, cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if proofRecord("k1", "j") == proofRecord("k2", "j") || proofRecord("", "j") == proofRecord("k", "j") {
		t.Error("proofs under different keys share a record")
	}
	if txnRecord("j1") == txnRecord("j2") || txnRecord("") == txnRecord("j") {
		t.Error("different SPT-Txn tokens share a record")
	}
	if sliceRecord("r", 0) == sliceRecord("r", 1) || sliceRecord("r1", 0) == sliceRecord("r2", 0) {
		t.Error("different slices share a record")
	}
}

// TestProofIsRecordedOnlyAfterPossessionIsEstablished: a proof signed by a key
// other than the one the token is bound to is refused and leaves no record. A
// proof from the bound key is recorded, and presenting it again is refused.
func TestProofIsRecordedOnlyAfterPossessionIsEstablished(t *testing.T) {
	holderPub, holderPriv := recordTestKey(t)
	_, otherPriv := recordTestKey(t)
	e := &Engine{replay: newReplayCache()}

	if err := e.step5DPoP(heldBy(holderPub), recordTestToken, recordTestProof(t, otherPriv), recordTestHTM, recordTestHTU); err == nil {
		t.Fatal("a proof signed by a key other than the token's was accepted")
	}
	if n := len(e.replay.seen); n != 0 {
		t.Fatalf("a presentation that did not establish possession left %d record(s)", n)
	}

	proof := recordTestProof(t, holderPriv)
	if err := e.step5DPoP(heldBy(holderPub), recordTestToken, proof, recordTestHTM, recordTestHTU); err != nil {
		t.Fatalf("the holder's proof was refused: %v", err)
	}
	if n := len(e.replay.seen); n != 1 {
		t.Fatalf("an accepted proof left %d records, want 1", n)
	}
	if err := e.step5DPoP(heldBy(holderPub), recordTestToken, proof, recordTestHTM, recordTestHTU); err == nil {
		t.Fatal("the same proof was accepted twice")
	}
}

// TestStep5AppliesProofMaxAge: step 5 accepts a proof for proofMaxAge after its
// iat and no longer, so the window it applies is the one the proof record's
// lifetime is derived from.
func TestStep5AppliesProofMaxAge(t *testing.T) {
	pub, priv := recordTestKey(t)
	e := &Engine{replay: newReplayCache()}
	maxAge := int64(proofMaxAge / time.Second)
	now := time.Now().Unix()
	if err := e.step5DPoP(heldBy(pub), recordTestToken, recordTestProofIssuedAt(t, priv, now-maxAge-2), recordTestHTM, recordTestHTU); err == nil {
		t.Fatal("step 5 accepted a proof older than proofMaxAge")
	}
	if err := e.step5DPoP(heldBy(pub), recordTestToken, recordTestProofIssuedAt(t, priv, now-maxAge+2), recordTestHTM, recordTestHTU); err != nil {
		t.Fatalf("step 5 refused a proof within proofMaxAge: %v", err)
	}
}

// TestProofRecordTTLCoversTheAcceptanceWindow: dpop.Verify accepts a proof while
// -MaxFutureSkew <= age <= maxAge, both ends inclusive, so a proof first accepted
// at the earliest instant is still acceptable MaxFutureSkew+proofMaxAge later.
// consumeAll treats a record as live only while now is strictly before its
// expiry, so the record's lifetime must be strictly longer than that span.
func TestProofRecordTTLCoversTheAcceptanceWindow(t *testing.T) {
	if span := dpop.MaxFutureSkew + proofMaxAge; proofRecordTTL <= span {
		t.Fatalf("proofRecordTTL %v does not exceed the %v for which a proof can remain acceptable", proofRecordTTL, span)
	}
}

// TestProofRecordOutlivesTheProofsAcceptance: the record step 5 writes lives
// past the last instant the proof it records can be accepted.
func TestProofRecordOutlivesTheProofsAcceptance(t *testing.T) {
	pub, priv := recordTestKey(t)
	e := &Engine{replay: newReplayCache()}
	firstAccepted := time.Now()
	if err := e.step5DPoP(heldBy(pub), recordTestToken, recordTestProof(t, priv), recordTestHTM, recordTestHTU); err != nil {
		t.Fatal(err)
	}
	lastAcceptable := firstAccepted.Add(dpop.MaxFutureSkew + proofMaxAge)
	if n := len(e.replay.seen); n != 1 {
		t.Fatalf("an accepted proof left %d records, want 1", n)
	}
	for k, exp := range e.replay.seen {
		if k.kind != recordProof {
			t.Fatalf("recorded kind %d, want a proof record", k.kind)
		}
		// A proof carries no signed wall expiry, so it is held on the monotonic
		// budget alone; that budget must outlast the acceptance window.
		if !exp.wall.IsZero() {
			t.Fatalf("a proof record has a wall expiry %v; it should be held on the monotonic budget alone", exp.wall)
		}
		if !exp.mono.After(lastAcceptable) {
			t.Fatalf("the proof record's monotonic expiry is %v, but a proof first accepted at %v can be acceptable until %v",
				exp.mono, firstAccepted, lastAcceptable)
		}
	}
}

// TestConsumeAllRefusesARecordWithNoKind: a key built without a kind is refused,
// alone or in a batch, and nothing in the batch is recorded.
func TestConsumeAllRefusesARecordWithNoKind(t *testing.T) {
	c := newReplayCache()
	if c.consumeAll(consumption{key: recordKey{id: "x"}, ttl: time.Minute}) {
		t.Fatal("a record with no kind was accepted")
	}
	if c.consumeAll(
		consumption{key: txnRecord("x"), ttl: time.Minute},
		consumption{key: recordKey{}, ttl: time.Minute},
	) {
		t.Fatal("a batch containing a record with no kind was accepted")
	}
	if n := len(c.seen); n != 0 {
		t.Fatalf("a refused batch left %d record(s)", n)
	}
}
