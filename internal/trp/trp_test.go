package trp_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/travelrule"
	"github.com/rudizee007/spt-txn-poc/internal/trp"
)

func TestTravelAddressRoundTrip(t *testing.T) {
	const endpoint = "https://beneficiary.example/trp/transfer?acct=rBob"
	addr := trp.EncodeTravelAddress(endpoint)
	got, err := trp.DecodeTravelAddress(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != endpoint {
		t.Errorf("round trip = %q, want %q", got, endpoint)
	}
	if _, err := trp.DecodeTravelAddress("not-a-travel-address"); err == nil {
		t.Error("decoding a non-travel-address must fail")
	}
}

// stubVerify is a *travelrule.Verifier.Verify stand-in: it approves when the
// expected hash matches and the surname disclosure is requested.
func stubVerify(want string) trp.VerifyFunc {
	return func(_ *travelrule.Attestation, expected string, disclose []string) (map[string]any, error) {
		if expected != want {
			return nil, errors.New("payment binding mismatch")
		}
		out := map[string]any{"txn_context_hash": expected}
		for _, d := range disclose {
			out[d] = "disclosed"
		}
		return out, nil
	}
}

// fixedHash is an independent expected-hash source for the beneficiary Handler
// (TR-3): it returns a constant the beneficiary "observes" out of band, never
// the request's own asserted hash.
func fixedHash(h string) func(*trp.TransferRequest) string {
	return func(*trp.TransferRequest) string { return h }
}

// insecureClient is a Client allowed to dial the httptest loopback server.
func insecureClient(srv *httptest.Server) *trp.Client {
	c := trp.NewClient(srv.Client())
	c.AllowInsecureTarget = true
	return c
}

func TestTransfer_Approved(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), fixedHash("h1")))
	defer srv.Close()

	resp, status, err := insecureClient(srv).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{
			Asset:  trp.Asset{Symbol: "XRP"},
			Amount: "5000",
			Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
				Version:        trp.ExtensionVersion,
				TxnContextHash: "h1",
				Disclose:       []string{"beneficiary.name.primary"},
			}},
		})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 200 || resp.Approved == nil {
		t.Fatalf("status=%d approved=%v rejected=%q", status, resp.Approved, resp.Rejected)
	}
	if resp.Disclosed["beneficiary.name.primary"] != "disclosed" {
		t.Errorf("expected surname disclosed, got %v", resp.Disclosed)
	}
}

func TestTransfer_RejectsBadBinding(t *testing.T) {
	// The beneficiary independently expects "h1"; the attestation asserting a
	// different hash must be rejected via the verify stub.
	srv := httptest.NewServer(trp.Handler(stubVerify("WRONG"), fixedHash("h1")))
	defer srv.Close()

	resp, status, err := insecureClient(srv).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Amount: "1", Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
			Version: trp.ExtensionVersion, TxnContextHash: "WRONG",
		}}})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 422 || resp.Rejected == "" {
		t.Fatalf("expected 422 rejected, got status=%d resp=%+v", status, resp)
	}
}

func TestTransfer_RejectsCleartextOnly(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), fixedHash("h1")))
	defer srv.Close()

	// No spt-txn extension: a plain-IVMS101 TRP transfer must be refused.
	resp, status, err := insecureClient(srv).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Asset: trp.Asset{Symbol: "XRP"}, Amount: "1"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 422 || resp.Rejected == "" {
		t.Fatalf("expected 422 rejected for cleartext-only, got status=%d resp=%+v", status, resp)
	}
}

// TR-3: a Handler built with a nil expectedHash must fail closed — every
// request is rejected 422 rather than trusting the request's own hash.
func TestHandler_NilExpectedHashFailsClosed(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), nil))
	defer srv.Close()

	resp, status, err := insecureClient(srv).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Amount: "1", Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
			Version: trp.ExtensionVersion, TxnContextHash: "h1",
		}}})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 422 || resp.Rejected == "" {
		t.Fatalf("nil expectedHash must fail closed (422), got status=%d resp=%+v", status, resp)
	}
}

// TR-2: the production target guard rejects non-https and loopback/private
// destinations. A default client (AllowInsecureTarget false) must refuse the
// loopback httptest server before any request is sent.
func TestSend_RejectsInsecureTargetByDefault(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), fixedHash("h1")))
	defer srv.Close()

	_, _, err := trp.NewClient(srv.Client()).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Amount: "1", Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
			Version: trp.ExtensionVersion, TxnContextHash: "h1",
		}}})
	if err == nil {
		t.Fatal("default client must reject an http loopback target")
	}
}

func TestSend_RejectsNonHTTPS(t *testing.T) {
	c := trp.NewClient(nil) // default secure client
	_, _, err := c.Send(context.Background(),
		trp.EncodeTravelAddress("http://beneficiary.example/trp/transfer"),
		&trp.TransferRequest{Amount: "1", Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
			Version: trp.ExtensionVersion, TxnContextHash: "h1",
		}}})
	if err == nil {
		t.Fatal("a plaintext http target must be rejected")
	}
}

// TR-5: replaying the same Request-Identifier must be rejected 409.
func TestHandler_RejectsReplayedRequestIdentifier(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), fixedHash("h1")))
	defer srv.Close()

	body := []byte(`{"asset":{"symbol":"XRP"},"amount":"1","extensions":{"spt-txn":{"version":"spt-txn/1","txn_context_hash":"h1"}}}`)
	send := func() int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(trp.HeaderAPIVersion, trp.APIVersion)
		req.Header.Set(trp.HeaderRequestIdentifier, "fixed-id-123")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := send(); s != 200 {
		t.Fatalf("first request status = %d, want 200", s)
	}
	if s := send(); s != 409 {
		t.Fatalf("replayed request status = %d, want 409", s)
	}
}

func TestValidAmount(t *testing.T) {
	for _, ok := range []string{"1", "5000", "0.01", "5000.00"} {
		if err := trp.ValidAmount(ok); err != nil {
			t.Errorf("ValidAmount(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "abc", "0", "-1", "NaN", "Inf"} {
		if err := trp.ValidAmount(bad); err == nil {
			t.Errorf("ValidAmount(%q) = nil, want error", bad)
		}
	}
}
