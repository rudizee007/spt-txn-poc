package intent

import (
	"encoding/json"
	"errors"
	"testing"
)

func params(s string) json.RawMessage { return json.RawMessage(s) }

func TestDigestDeterministicAndKeyOrderIndependent(t *testing.T) {
	a := Intent{Tool: "payments.transfer", Params: params(`{"amount":"100.00","ccy":"USD"}`), Target: "mcp://payments"}
	b := Intent{Tool: "payments.transfer", Params: params(`{"ccy":"USD","amount":"100.00"}`), Target: "mcp://payments"}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("semantically identical intents digest differently: %s vs %s", da, db)
	}
}

func TestDigestSeparatesFields(t *testing.T) {
	// tool/params/target must be injectively bound: moving bytes between
	// fields must change the digest.
	base := Intent{Tool: "a", Params: params(`{"k":"b"}`), Target: "c"}
	variants := []Intent{
		{Tool: "ab", Params: params(`{"k":""}`), Target: "c"},
		{Tool: "a", Params: params(`{"k":"bc"}`), Target: ""},
		{Tool: "a", Params: params(`{"k":"b"}`), Target: "C"},
		{Tool: "A", Params: params(`{"k":"b"}`), Target: "c"},
	}
	d0, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range variants {
		dv, err := v.Digest()
		if err != nil {
			continue // rejected variants can't collide
		}
		if dv == d0 {
			t.Errorf("variant %d collides with base digest", i)
		}
	}
}

func TestMatch(t *testing.T) {
	declared := Intent{Tool: "files.read", Params: params(`{"path":"/data/report.pdf"}`), Target: "mcp://files"}
	bound, err := declared.Digest()
	if err != nil {
		t.Fatal(err)
	}

	if err := Match(bound, declared); err != nil {
		t.Fatalf("identical call rejected: %v", err)
	}

	// Hijacked action: same token, different call — must fail.
	hijacked := Intent{Tool: "files.delete", Params: params(`{"path":"/data/report.pdf"}`), Target: "mcp://files"}
	if err := Match(bound, hijacked); !errors.Is(err, ErrMismatch) {
		t.Fatalf("hijacked tool accepted (err=%v)", err)
	}

	// Same tool, mutated params.
	mutated := Intent{Tool: "files.read", Params: params(`{"path":"/etc/shadow"}`), Target: "mcp://files"}
	if err := Match(bound, mutated); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mutated params accepted (err=%v)", err)
	}

	// Token replayed at a different server.
	elsewhere := Intent{Tool: "files.read", Params: params(`{"path":"/data/report.pdf"}`), Target: "mcp://other"}
	if err := Match(bound, elsewhere); !errors.Is(err, ErrMismatch) {
		t.Fatalf("cross-target replay accepted (err=%v)", err)
	}
}

func TestMatchFailClosed(t *testing.T) {
	ok := Intent{Tool: "t", Params: params(`{}`), Target: "x"}
	cases := []struct {
		name  string
		bound string
		call  Intent
	}{
		{"no digest in token", "", ok},
		{"garbage digest", "!!!not-base64!!!", ok},
		{"wrong length digest", "AAAA", ok},
		{"params not object", mustDigest(t, ok), Intent{Tool: "t", Params: params(`[1,2]`), Target: "x"}},
		{"params malformed", mustDigest(t, ok), Intent{Tool: "t", Params: params(`{"a":`), Target: "x"}},
		{"params duplicate key", mustDigest(t, ok), Intent{Tool: "t", Params: params(`{"a":1,"a":1}`), Target: "x"}},
		{"params float", mustDigest(t, ok), Intent{Tool: "t", Params: params(`{"a":1.5}`), Target: "x"}},
		{"empty tool", mustDigest(t, ok), Intent{Tool: "", Params: params(`{}`), Target: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Match(tc.bound, tc.call); !errors.Is(err, ErrMismatch) {
				t.Fatalf("got err=%v; want ErrMismatch (fail closed)", err)
			}
		})
	}
}

func TestAbsentParamsBindAsEmptyObject(t *testing.T) {
	a := Intent{Tool: "t", Params: nil, Target: "x"}
	b := Intent{Tool: "t", Params: params(`{}`), Target: "x"}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("absent params and empty object diverge: %s vs %s", da, db)
	}
}

func mustDigest(t *testing.T, in Intent) string {
	t.Helper()
	d, err := in.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
