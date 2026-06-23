package trp_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/travelrule"
	"github.com/violetskysecurity/spt-txn-poc/internal/trp"
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

func TestTransfer_Approved(t *testing.T) {
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), nil))
	defer srv.Close()

	resp, status, err := trp.NewClient(srv.Client()).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{
			Asset:  trp.Asset{Symbol: "XRP"},
			Amount: 5000,
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
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), nil))
	defer srv.Close()

	resp, status, err := trp.NewClient(srv.Client()).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
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
	srv := httptest.NewServer(trp.Handler(stubVerify("h1"), nil))
	defer srv.Close()

	// No spt-txn extension: a plain-IVMS101 TRP transfer must be refused.
	resp, status, err := trp.NewClient(srv.Client()).Send(context.Background(),
		trp.EncodeTravelAddress(srv.URL),
		&trp.TransferRequest{Asset: trp.Asset{Symbol: "XRP"}, Amount: 1})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 422 || resp.Rejected == "" {
		t.Fatalf("expected 422 rejected for cleartext-only, got status=%d resp=%+v", status, resp)
	}
}
