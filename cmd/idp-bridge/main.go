// cmd/idp-bridge — RFC 8693 Token Exchange: identity provider -> SPT-Txn CAT.
//
// Reference integration proving an EXISTING OpenID Connect identity provider
// (Keycloak in the demo; the same flow targets Okta / Auth0 / Ping unchanged)
// can mint SPT-Txn Compliance Attestation Tokens over standard OAuth 2.0 Token
// Exchange — no rip-and-replace. The issued CAT then verifies OFFLINE and can be
// delegated to an AI agent (see cmd/idp-verify).
//
// In production this logic folds into cmd/catsvc (the hardened CAT issuer); it
// ships standalone here so the proof runs anywhere, unentangled from the
// OpenBSD pledge/unveil/signify specifics of catsvc.
//
// Endpoints:
//
//	POST /token    RFC 8693 token exchange (form-encoded or JSON)
//	GET  /issuer   the CAT issuer's Ed25519 public key (hex) — for the verifier/registry
//	GET  /health   liveness
//
// POST /token parameters (application/x-www-form-urlencoded or JSON):
//
//	grant_type         = urn:ietf:params:oauth:grant-type:token-exchange   (required)
//	subject_token      = <Keycloak access token>                            (required)
//	subject_token_type = urn:ietf:params:oauth:token-type:access_token
//	holder_key_hex     = <64-hex Ed25519 public key of the agent/holder>     (required)
//	scope              = <JSON object>   (optional; else spt_scope claim, else default)
//	ttl_hours, delegation_depth_max      (optional)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/oidc"
)

const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
const catTokenType = "urn:violetsky:token-type:spt-cat"

func main() {
	addr := envOr("SPT_IDP_ADDR", "127.0.0.1:8090")
	issuerURL := envOr("SPT_IDP_OIDC_ISSUER", "http://localhost:8080/realms/spt")
	audience := os.Getenv("SPT_IDP_AUDIENCE") // optional; SET IN PRODUCTION
	catIssuer := envOr("SPT_IDP_CAT_ISSUER", "domain-a.authorg")

	log.SetPrefix("idp-bridge: ")
	log.SetFlags(log.Ltime)

	// CAT signing key: load a pinned seed (hex, 32 bytes) or generate one.
	var priv ed25519.PrivateKey
	if seedHex := os.Getenv("SPT_IDP_CAT_SEED_HEX"); seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("SPT_IDP_CAT_SEED_HEX must be %d hex bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		priv = p
		log.Printf("generated ephemeral CAT issuer key (pin with SPT_IDP_CAT_SEED_HEX=%s)",
			hex.EncodeToString(priv.Seed()))
	}
	pub := priv.Public().(ed25519.PublicKey)
	log.Printf("CAT issuer %q public key: %s", catIssuer, hex.EncodeToString(pub))

	// OIDC verifier — discovery + JWKS against the identity provider.
	var opts []oidc.Option
	if audience != "" {
		opts = append(opts, oidc.WithAudience(audience))
	}
	// TEST-ONLY: some self-hosted IdPs (e.g. a local Janssen/Gluu with a
	// self-signed cert) can't be reached over verified TLS during a demo.
	// SPT_IDP_INSECURE_SKIP_VERIFY=true disables cert verification for the
	// discovery/JWKS fetches. NEVER set this in production.
	if os.Getenv("SPT_IDP_INSECURE_SKIP_VERIFY") == "true" {
		log.Printf("WARNING: TLS certificate verification DISABLED (SPT_IDP_INSECURE_SKIP_VERIFY) — demo/testing only, never production")
		opts = append(opts, oidc.WithHTTPClient(&http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}))
	}
	ver, err := oidc.NewVerifier(context.Background(), issuerURL, opts...)
	if err != nil {
		log.Fatalf("OIDC discovery against %s: %v (is the identity provider up?)", issuerURL, err)
	}
	log.Printf("OIDC verifier ready for issuer %s", issuerURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "idp-bridge"})
	})
	mux.HandleFunc("/issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": catIssuer, "public_key_hex": hex.EncodeToString(pub)})
	})
	mux.HandleFunc("/token", handleExchange(ver, priv, catIssuer))

	log.Printf("listening on %s  (POST /token, GET /issuer, GET /health)", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func handleExchange(ver *oidc.Verifier, priv ed25519.PrivateKey, catIssuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			oauthErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		p := parseParams(r)

		if p["grant_type"] != grantTokenExchange {
			oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "expected "+grantTokenExchange)
			return
		}
		subjectToken := p["subject_token"]
		if subjectToken == "" {
			oauthErr(w, http.StatusBadRequest, "invalid_request", "subject_token required")
			return
		}
		holderHex := p["holder_key_hex"]
		holder, err := hex.DecodeString(holderHex)
		if err != nil || len(holder) != ed25519.PublicKeySize {
			oauthErr(w, http.StatusBadRequest, "invalid_request", "holder_key_hex must be 64 hex chars (32-byte Ed25519 key)")
			return
		}

		// Verify the identity provider's token (signature, iss, exp, aud).
		claims, err := ver.Verify(r.Context(), subjectToken)
		if err != nil {
			log.Printf("subject token rejected: %v", err)
			oauthErr(w, http.StatusUnauthorized, "invalid_grant", "subject token rejected")
			return
		}
		subject := claims.Str("sub")
		if subject == "" {
			oauthErr(w, http.StatusUnauthorized, "invalid_grant", "subject token missing sub")
			return
		}
		principal := claims.Str("preferred_username")
		if principal == "" {
			principal = subject
		}

		// Map claims -> CAT scope. Precedence: request `scope` (JSON) > `spt_scope`
		// claim > a conservative default. Deployment-specific in production.
		scope := parseScope(p["scope"])
		if scope == nil {
			if s, ok := claims["spt_scope"].(map[string]any); ok {
				scope = s
			}
		}
		if scope == nil {
			scope = map[string]any{"action": "transfer", "max_amount": 10000, "currency": "USD"}
		}

		depth := 3
		if d, err := strconv.Atoi(p["delegation_depth_max"]); err == nil && d >= 0 {
			depth = d
		}
		ttl := 24 * time.Hour
		if h, err := strconv.Atoi(p["ttl_hours"]); err == nil && h > 0 {
			ttl = time.Duration(h) * time.Hour
		}

		cat, err := cattoken.Issue(cattoken.IssueRequest{
			Issuer:             catIssuer,
			Subject:            subject,
			PrincipalName:      principal,
			Scope:              cattoken.CapabilityScope(scope),
			DelegationDepthMax: depth,
			TTL:                ttl,
			HolderPublicKey:    ed25519.PublicKey(holder),
		}, priv)
		if err != nil {
			log.Printf("cattoken.Issue: %v", err)
			oauthErr(w, http.StatusBadRequest, "invalid_request", "issuance failed")
			return
		}
		log.Printf("exchanged IdP token (sub=%s) -> CAT for holder %s…", subject, holderHex[:8])

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":      cat.Token,
			"issued_token_type": catTokenType,
			"token_type":        "N_A",
			"expires_in":        int(time.Until(cat.ExpiresAt).Seconds()),
			"human_anchor":      cat.HumanAnchor.String(),
		})
	}
}

// parseParams accepts either form-encoded (RFC 8693 canonical) or a JSON body.
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
