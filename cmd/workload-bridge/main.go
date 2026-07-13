// cmd/workload-bridge — RFC 8693 Token Exchange: attested WORKLOAD identity ->
// SPT-Txn CAT. The workload analog of cmd/idp-bridge (SPT-Txn P4, NHI attested
// issuance; spec docs/spec/NHI-ATTESTED-ISSUANCE.md).
//
// A workload presents an attested identity — SPIFFE JWT-SVID / X.509-SVID, a
// Kubernetes projected ServiceAccount token, or a cloud workload-identity OIDC
// assertion (AWS IRSA / GCP WIF / Azure FC) — and receives a transaction-scoped
// CAT whose spt_attestation claim seals the evidence digest. A downstream
// verifier then checks not only WHO acted but ON WHAT ATTESTED SUBSTRATE.
//
// Trust material is PINNED (the correct posture for SPIFFE bundles):
//
//	SPT_WL_JWKS_FILE     JWKS JSON for the JWT trust domain (RSA + Ed25519 keys)
//	SPT_WL_X509_ROOTS    PEM roots for spiffe-x509-svid (optional)
//	SPT_WL_ISSUER        expected `iss` for k8s/cloud methods (not SPIFFE JWT-SVID)
//	SPT_WL_AUDIENCE      required audience this exchange endpoint expects
//	SPT_WL_CAT_ISSUER    CAT issuer identity (default domain-a.authorg)
//	SPT_WL_CAT_SEED_HEX  pinned Ed25519 CAT signing seed (else ephemeral)
//	SPT_WL_ADDR          listen address (default 127.0.0.1:8091)
//
// POST /token params (form-encoded or JSON):
//
//	grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
//	subject_token       = <attested assertion>  (JWT methods)
//	subject_token_cert  = <base64 DER leaf>      (spiffe-x509-svid; PEM also ok)
//	subject_token_type  = urn:violetsky:token-type:{spiffe-jwt-svid|k8s-sa|gcp-wif|...}
//	holder_key_hex      = <64-hex Ed25519 public key of the workload/agent>
//	audience            = <this endpoint's identifier>   (required)
//	scope               = <JSON object>   (optional ceiling)
//	requested_max_age_s = <int>           (optional freshness predicate)
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
const catTokenType = "urn:violetsky:token-type:spt-cat"

// maxDelegationDepth bounds the delegation fan-out a single exchange may request
// (fail-closed: a caller can never request an unbounded chain). The attestation
// proves identity, not entitlement; requested scope is an advisory ceiling and
// per-principal entitlement is enforced downstream at the PEP/policy layer.
const maxDelegationDepth = 8

func main() {
	addr := envOr("SPT_WL_ADDR", "127.0.0.1:8091")
	catIssuer := envOr("SPT_WL_CAT_ISSUER", "domain-a.authorg")
	expectedIssuer := os.Getenv("SPT_WL_ISSUER")
	audience := os.Getenv("SPT_WL_AUDIENCE")

	log.SetPrefix("workload-bridge: ")
	log.SetFlags(log.Ltime)

	if audience == "" {
		log.Fatal("SPT_WL_AUDIENCE is required (binds assertions to this endpoint)")
	}

	// CAT signing key.
	var priv ed25519.PrivateKey
	if seedHex := os.Getenv("SPT_WL_CAT_SEED_HEX"); seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("SPT_WL_CAT_SEED_HEX must be %d hex bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		priv = p
		log.Printf("generated ephemeral CAT issuer key (pin with SPT_WL_CAT_SEED_HEX=%s)", hex.EncodeToString(priv.Seed()))
	}
	pub := priv.Public().(ed25519.PublicKey)
	log.Printf("CAT issuer %q public key: %s", catIssuer, hex.EncodeToString(pub))

	// Pinned JWT trust bundle.
	var ks attest.KeySource
	if f := os.Getenv("SPT_WL_JWKS_FILE"); f != "" {
		keys, err := loadJWKS(f)
		if err != nil {
			log.Fatalf("JWKS %s: %v", f, err)
		}
		ks = attest.NewStaticKeySource(keys)
		log.Printf("loaded %d JWT trust key(s) from %s", len(keys), f)
	}

	// Optional X.509 SVID roots.
	var x509Bundle attest.X509Bundle
	if f := os.Getenv("SPT_WL_X509_ROOTS"); f != "" {
		pool, err := loadPEMRoots(f)
		if err != nil {
			log.Fatalf("X.509 roots %s: %v", f, err)
		}
		x509Bundle = attest.X509Bundle{Roots: pool}
		log.Printf("loaded X.509 SVID trust roots from %s", f)
	}

	h := &handler{
		ks: ks, x509: x509Bundle, priv: priv, catIssuer: catIssuer,
		expectedIssuer: expectedIssuer, audience: audience,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "workload-bridge"})
	})
	mux.HandleFunc("/issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": catIssuer, "public_key_hex": hex.EncodeToString(pub)})
	})
	mux.HandleFunc("/token", h.exchange)

	log.Printf("listening on %s  (POST /token, GET /issuer, GET /health)", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

type handler struct {
	ks             attest.KeySource
	x509           attest.X509Bundle
	priv           ed25519.PrivateKey
	catIssuer      string
	expectedIssuer string
	audience       string
}

func (h *handler) exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	p := parseParams(r)

	if p["grant_type"] != grantTokenExchange {
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "expected "+grantTokenExchange)
		return
	}
	// Audience must match this endpoint (defeats cross-service replay).
	if p["audience"] != h.audience {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "audience must equal this exchange endpoint")
		return
	}
	holder, err := hex.DecodeString(p["holder_key_hex"])
	if err != nil || len(holder) != ed25519.PublicKeySize {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "holder_key_hex must be 64 hex chars")
		return
	}
	method, err := attest.MethodFromTokenType(p["subject_token_type"])
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "unsupported subject_token_type")
		return
	}

	id, err := h.verify(r.Context(), method, p)
	if err != nil {
		log.Printf("attestation rejected (%s): %v", method, err)
		oauthErr(w, http.StatusUnauthorized, "invalid_grant", "attestation rejected")
		return
	}

	// Optional freshness predicate.
	if s := p["requested_max_age_s"]; s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			if err := (attest.Freshness{MaxAge: time.Duration(secs) * time.Second}).Check(id, time.Now()); err != nil {
				log.Printf("freshness rejected: %v", err)
				oauthErr(w, http.StatusForbidden, "invalid_grant", "attestation not fresh enough")
				return
			}
		}
	}

	scope := parseScope(p["scope"])
	if scope == nil {
		scope = map[string]any{"action": "transfer", "max_amount": 10000, "currency": "USD"}
	}
	depth := 3
	if d, err := strconv.Atoi(p["delegation_depth_max"]); err == nil && d >= 1 {
		depth = d
	}
	if depth > maxDelegationDepth {
		depth = maxDelegationDepth
	}

	// CAT lifetime bounded by the attestation lifetime (spec §4). Default 15
	// min, clamped so the CAT never outlives the proof.
	ttl := 15 * time.Minute
	if !id.ExpiresAt.IsZero() {
		if rem := time.Until(id.ExpiresAt); rem > 0 && rem < ttl {
			ttl = rem
		}
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             h.catIssuer,
		Subject:            "workload:" + id.Subject,
		PrincipalName:      id.Subject,
		Scope:              cattoken.CapabilityScope(scope),
		DelegationDepthMax: depth,
		TTL:                ttl,
		HolderPublicKey:    ed25519.PublicKey(holder),
		Attestation:        id.SealClaim(),
	}, h.priv)
	if err != nil {
		log.Printf("cattoken.Issue: %v", err)
		oauthErr(w, http.StatusBadRequest, "invalid_request", "issuance failed")
		return
	}
	log.Printf("exchanged %s attestation (sub=%s) -> attested CAT", method, id.Subject)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      cat.Token,
		"issued_token_type": catTokenType,
		"token_type":        "N_A",
		"expires_in":        int(time.Until(cat.ExpiresAt).Seconds()),
		"attested_subject":  id.Subject,
		"attestation_method": string(id.Method),
	})
}

func (h *handler) verify(ctx context.Context, method attest.Method, p map[string]string) (attest.Identity, error) {
	switch method {
	case attest.MethodSPIFFEX509SVID:
		der, err := decodeCert(p["subject_token_cert"])
		if err != nil {
			return attest.Identity{}, err
		}
		return attest.VerifyX509SVID([][]byte{der}, h.x509, time.Now())
	case attest.MethodSPIFFEJWTSVID:
		return attest.VerifySPIFFEJWTSVID(ctx, p["subject_token"], []string{h.audience}, h.ks)
	case attest.MethodK8sSA:
		return attest.VerifyK8sSAToken(ctx, p["subject_token"], h.expectedIssuer, []string{h.audience}, h.ks)
	default: // cloud OIDC federation
		return attest.VerifyCloudWorkload(ctx, p["subject_token"], method, h.expectedIssuer, []string{h.audience}, h.ks)
	}
}

// ── trust-material loading ──────────────────────────────────────────────

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
	} `json:"keys"`
}

func loadJWKS(path string) (map[string]crypto.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		switch k.Kty {
		case "RSA":
			nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
			if err != nil {
				return nil, err
			}
			eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
			if err != nil {
				return nil, err
			}
			e := 0
			for _, b := range eb {
				e = e<<8 | int(b)
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
			if err != nil {
				return nil, err
			}
			if len(xb) != ed25519.PublicKeySize {
				return nil, os.ErrInvalid
			}
			out[k.Kid] = ed25519.PublicKey(xb)
		}
	}
	return out, nil
}

func loadPEMRoots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, os.ErrInvalid
	}
	return pool, nil
}

func decodeCert(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, os.ErrInvalid
		}
		return block.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// ── HTTP helpers ────────────────────────────────────────────────────────

func parseParams(r *http.Request) map[string]string {
	out := map[string]string{}
	ct := r.Header.Get("Content-Type")
	if len(ct) >= 16 && ct[:16] == "application/json" {
		var m map[string]any
		if json.NewDecoder(r.Body).Decode(&m) == nil {
			for k, v := range m {
				switch t := v.(type) {
				case string:
					out[k] = t
				default:
					b, _ := json.Marshal(t)
					out[k] = string(b)
				}
			}
		}
		return out
	}
	_ = r.ParseForm()
	for k := range r.Form {
		out[k] = r.Form.Get(k)
	}
	return out
}

func parseScope(s string) map[string]any {
	if s == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, err, desc string) {
	writeJSON(w, code, map[string]string{"error": err, "error_description": desc})
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
