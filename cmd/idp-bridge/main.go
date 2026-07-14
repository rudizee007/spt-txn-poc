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
//	scope              = <JSON object>   (optional; intersected with the policy ceiling)
//	ttl_hours, delegation_depth_max      (optional)
//	dry_run            = "true"          (optional; run the full evaluation and
//	                                      return the decision it WOULD make,
//	                                      WITHOUT issuing a token)
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
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
const catTokenType = "urn:violetsky:token-type:spt-cat"

// Fail-closed bounds (mirror cmd/workload-bridge). A caller cannot request an
// unbounded delegation chain, and a CAT can never outlive the IdP proof it was
// minted on. Scope entitlement is decided by the issuer as
// intersect(requested, permitted) and re-checked on the chain by the PEP.
const (
	maxDelegationDepth = 8
	defaultCATTTL      = 24 * time.Hour
	maxCATTTL          = 24 * time.Hour
)

func main() {
	addr := envOr("SPT_IDP_ADDR", "127.0.0.1:8090")
	issuerURL := envOr("SPT_IDP_OIDC_ISSUER", "http://localhost:8080/realms/spt")
	audience := os.Getenv("SPT_IDP_AUDIENCE")
	catIssuer := envOr("SPT_IDP_CAT_ISSUER", "domain-a.authorg")

	log.SetPrefix("idp-bridge: ")
	log.SetFlags(log.Ltime)

	// Fail closed on audience — no bypass. Without an audience bound, a subject
	// token minted for ANY other relying party in the same issuer could be
	// replayed at this endpoint and exchanged for a delegable root CAT
	// (authority inflation). The fix for a demo is one env var, so there is no
	// opt-out: the endpoint will not start without it.
	if audience == "" {
		log.Fatal("SPT_IDP_AUDIENCE is required so subject tokens are bound to this endpoint (defeats cross-service replay). Set it to this exchange endpoint's audience identifier.")
	}

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

	// OIDC verifier — discovery + JWKS against the identity provider. Audience
	// is guaranteed non-empty by the fail-closed check above.
	opts := []oidc.Option{oidc.WithAudience(audience)}
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
	mux.HandleFunc("/token", handleExchange(ver, priv, catIssuer, loadPermittedScope("SPT_IDP_PERMITTED_SCOPE")))

	log.Printf("listening on %s  (POST /token, GET /issuer, GET /health)", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// idpDecision is the outcome of evaluating an IdP exchange, computed identically
// for the live and dry-run paths. It never carries a token — minting happens
// only in the live branch of the handler, after this decision.
type idpDecision struct {
	wouldIssue bool

	// allow
	subject   string
	principal string
	scope     tbac.Scope
	depth     int
	ttl       time.Duration
	holder    []byte
	holderHex string

	// deny (mirrors the live oauthErr call)
	httpStatus    int
	oauthError    string
	description   string
	decisionClass string // "ok" | "violation" | "invalid_request"
}

func handleExchange(ver *oidc.Verifier, priv ed25519.PrivateKey, catIssuer string, permitted tbac.Scope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			oauthErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		p := parseParams(r)
		dryRun := p["dry_run"] == "true"

		dec := decideIDP(r.Context(), ver, permitted, p)

		if !dec.wouldIssue {
			if dryRun {
				writeJSON(w, http.StatusOK, map[string]any{
					"dry_run":           true,
					"would_issue":       false,
					"decision_class":    dec.decisionClass,
					"error":             dec.oauthError,
					"error_description": dec.description,
				})
				return
			}
			oauthErr(w, dec.httpStatus, dec.oauthError, dec.description)
			return
		}

		if dryRun {
			writeJSON(w, http.StatusOK, map[string]any{
				"dry_run":              true,
				"would_issue":          true,
				"decision_class":       "ok",
				"granted_scope":        map[string]any(dec.scope),
				"delegation_depth_max": dec.depth,
				"expires_in":           int(dec.ttl.Seconds()),
				"subject":              dec.subject,
			})
			return
		}

		cat, err := cattoken.Issue(cattoken.IssueRequest{
			Issuer:             catIssuer,
			Subject:            dec.subject,
			PrincipalName:      dec.principal,
			Scope:              cattoken.CapabilityScope(dec.scope),
			DelegationDepthMax: dec.depth,
			TTL:                dec.ttl,
			HolderPublicKey:    ed25519.PublicKey(dec.holder),
		}, priv)
		if err != nil {
			log.Printf("cattoken.Issue: %v", err)
			oauthErr(w, http.StatusBadRequest, "invalid_request", "issuance failed")
			return
		}
		log.Printf("exchanged IdP token (sub=%s) -> CAT for holder %s…", dec.subject, dec.holderHex[:8])

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":      cat.Token,
			"issued_token_type": catTokenType,
			"token_type":        "N_A",
			"expires_in":        int(time.Until(cat.ExpiresAt).Seconds()),
			"human_anchor":      cat.HumanAnchor.String(),
		})
	}
}

// decideIDP runs the full evaluation pipeline (verify the IdP token, derive
// subject/principal, intersect scope, bound depth, clamp TTL) and returns a
// decision. It mints nothing. Live and dry-run call it identically.
func decideIDP(ctx context.Context, ver *oidc.Verifier, permitted tbac.Scope, p map[string]string) idpDecision {
	deny := func(status int, oauthError, desc, class string) idpDecision {
		return idpDecision{httpStatus: status, oauthError: oauthError, description: desc, decisionClass: class}
	}

	if p["grant_type"] != grantTokenExchange {
		return deny(http.StatusBadRequest, "unsupported_grant_type", "expected "+grantTokenExchange, "invalid_request")
	}
	subjectToken := p["subject_token"]
	if subjectToken == "" {
		return deny(http.StatusBadRequest, "invalid_request", "subject_token required", "invalid_request")
	}
	holderHex := p["holder_key_hex"]
	holder, err := hex.DecodeString(holderHex)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return deny(http.StatusBadRequest, "invalid_request", "holder_key_hex must be 64 hex chars (32-byte Ed25519 key)", "invalid_request")
	}

	// Verify the identity provider's token (signature, iss, exp, aud).
	claims, err := ver.Verify(ctx, subjectToken)
	if err != nil {
		log.Printf("subject token rejected: %v", err)
		return deny(http.StatusUnauthorized, "invalid_grant", "subject token rejected", "violation")
	}
	// Subject: prefer `sub` (a human / OIDC login). A machine-to-machine or agent
	// token minted via client_credentials has no `sub` — the authenticated
	// principal IS the OAuth client — so fall back to `client_id`, then `azp`.
	// This is the workload / AI-agent identity case (e.g. a PingOne Worker app or
	// an Agent IAM Core M2M identity). The token is fully verified either way;
	// only the choice of subject claim differs.
	subject := claims.Str("sub")
	if subject == "" {
		subject = claims.Str("client_id")
	}
	if subject == "" {
		subject = claims.Str("azp")
	}
	if subject == "" {
		return deny(http.StatusUnauthorized, "invalid_grant", "subject token has no sub, client_id, or azp", "violation")
	}
	principal := claims.Str("preferred_username")
	if principal == "" {
		principal = subject
	}

	// Issuer-side scope decision: grant intersect(requested, permitted).
	// Requested precedence: request `scope` (JSON) > IdP `spt_scope` claim.
	// An omitted request yields the full permitted ceiling; neither source can
	// widen beyond it. The PEP re-checks the chain at execution.
	requested := parseScope(p["scope"])
	if requested == nil {
		if s, ok := claims["spt_scope"].(map[string]any); ok {
			requested = s
		}
	}
	var scope tbac.Scope
	if requested == nil {
		scope = permitted
	} else {
		g, err := tbac.Intersect(permitted, tbac.Scope(requested))
		if err != nil {
			log.Printf("scope rejected: %v", err)
			return deny(http.StatusForbidden, "invalid_scope", "requested scope exceeds the policy-permitted ceiling", "violation")
		}
		scope = g
	}

	depth := 3
	if d, err := strconv.Atoi(p["delegation_depth_max"]); err == nil && d >= 1 {
		depth = d
	}
	if depth > maxDelegationDepth {
		depth = maxDelegationDepth
	}

	// TTL is capped and then clamped down to the IdP proof's remaining life,
	// so the CAT can never outlive the token it was minted on.
	ttl := defaultCATTTL
	if h, err := strconv.Atoi(p["ttl_hours"]); err == nil && h > 0 {
		ttl = time.Duration(h) * time.Hour
	}
	if ttl > maxCATTTL {
		ttl = maxCATTTL
	}
	if exp, ok := claimExp(claims); ok {
		if rem := time.Until(exp); rem > 0 && rem < ttl {
			ttl = rem
		}
	}

	return idpDecision{
		wouldIssue: true, subject: subject, principal: principal,
		scope: scope, depth: depth, ttl: ttl, holder: holder, holderHex: holderHex,
	}
}

// claimExp reads the subject token's exp claim (epoch seconds) across the
// numeric encodings JSON decoding may yield.
func claimExp(c oidc.Claims) (time.Time, bool) {
	switch n := c["exp"].(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
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

// loadPermittedScope reads the policy-permitted scope ceiling this issuer will
// grant, from env as a JSON object. It is REQUIRED and fails closed at startup:
// the issuer will not run without an explicit ceiling, so no authority is ever
// granted by omission (a default ceiling would silently hand out real authority
// on an unconfigured deployment). A malformed value likewise refuses to start.
// Per-principal entitlement policy is a jurisdictional-TBAC concern layered
// above this.
func loadPermittedScope(env string) tbac.Scope {
	raw := os.Getenv(env)
	if raw == "" {
		log.Fatalf("%s is required: the issuer must be told the policy-permitted scope ceiling it may grant (a JSON object). It will not start without one, so no authority is granted by omission.", env)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || len(m) == 0 {
		log.Fatalf("%s must be a non-empty JSON object: %v", env, err)
	}
	log.Printf("permitted scope ceiling loaded from %s", env)
	return tbac.Scope(m)
}
