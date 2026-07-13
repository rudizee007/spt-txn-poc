package attest

// jwt.go — JWT-based attestation verification shared by SPIFFE JWT-SVID, K8s
// ServiceAccount tokens, and cloud workload-identity OIDC assertions. The key
// source is pluggable (KeySource) so verification is fully offline-testable
// and can be backed by a live JWKS, a static bundle, or the existing
// internal/oidc verifier in production.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// KeySource resolves a signing key by key id and algorithm. Implementations
// MUST return keys only from a trusted bundle/JWKS for the expected issuer;
// returning a key for an unknown kid is a verification failure, not a guess.
type KeySource interface {
	Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error)
}

// JWTConfig parameterises a JWT-based attestation check.
type JWTConfig struct {
	// Method labels the resulting Identity.
	Method Method
	// ExpectedIssuer is the required `iss` (trailing slash ignored). For SPIFFE
	// JWT-SVID this is typically empty and the trust domain is derived from the
	// spiffe:// subject; set RequireSPIFFESubject in that case.
	ExpectedIssuer string
	// Audiences: if non-empty, the token's aud MUST intersect this set.
	// REQUIRED (non-empty) for SVID and cloud methods per spec §2.
	Audiences []string
	// RequireSPIFFESubject requires sub to be a spiffe:// URI and derives
	// TrustDomain from it.
	RequireSPIFFESubject bool
	// RequireExpiry rejects a token that carries no (numeric) exp claim. An
	// attestation without an expiry would never age out; SVID/cloud methods
	// set this so a missing exp is a rejection, not an eternal token.
	RequireExpiry bool
	// Leeway tolerates clock skew on exp/nbf. Zero uses clockSkew.
	Leeway time.Duration
	// Now, if non-zero, fixes the verification time. Production leaves it zero
	// (real wall clock); tests set it to verify against a captured token whose
	// exp/nbf are fixed. It never relaxes a check — it only substitutes the
	// instant the temporal checks compare against.
	Now time.Time
}

// allowedJWTAlgs is the algorithm allowlist. Everything else — including
// "none" and any HMAC/ES variant not listed — is rejected.
var allowedJWTAlgs = map[string]bool{"RS256": true, "EdDSA": true}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// VerifyJWT verifies a compact JWS attestation and returns an Identity.
func VerifyJWT(ctx context.Context, token string, cfg JWTConfig, ks KeySource) (Identity, error) {
	if ks == nil {
		return Identity{}, fmt.Errorf("%w: nil key source", ErrKey)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("%w: want 3 JWS parts, got %d", ErrMalformed, len(parts))
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: header b64: %v", ErrMalformed, err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return Identity{}, fmt.Errorf("%w: header json: %v", ErrMalformed, err)
	}
	// Allowlist the algorithm BEFORE touching keys — defeats alg:none and
	// algorithm-confusion.
	if !allowedJWTAlgs[hdr.Alg] {
		return Identity{}, fmt.Errorf("%w: %q", ErrAlg, hdr.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: signature b64: %v", ErrMalformed, err)
	}

	key, err := ks.Key(ctx, hdr.Kid, hdr.Alg)
	if err != nil || key == nil {
		return Identity{}, fmt.Errorf("%w: kid %q: %v", ErrKey, hdr.Kid, err)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifyJWS(hdr.Alg, key, []byte(signingInput), sig); err != nil {
		return Identity{}, err
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: payload b64: %v", ErrMalformed, err)
	}
	// Reject duplicate JSON members in the payload — a token that parses one
	// way here and another way in a downstream JSON reader is an attack
	// surface.
	if err := rejectDuplicateJSONKeys(pb); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return Identity{}, fmt.Errorf("%w: payload json: %v", ErrMalformed, err)
	}

	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = clockSkew
	}
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Issuer.
	if cfg.ExpectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if strings.TrimRight(iss, "/") != strings.TrimRight(cfg.ExpectedIssuer, "/") {
			return Identity{}, fmt.Errorf("%w: %q != %q", ErrIssuer, iss, cfg.ExpectedIssuer)
		}
	}

	// Temporal.
	iat, _ := numTime(claims["iat"])
	nbf, hasNbf := numTime(claims["nbf"])
	exp, hasExp := numTime(claims["exp"])
	if cfg.RequireExpiry && !hasExp {
		return Identity{}, fmt.Errorf("%w: missing required exp", ErrExpired)
	}
	if hasExp && now.After(exp.Add(leeway)) {
		return Identity{}, ErrExpired
	}
	if hasNbf && now.Add(leeway).Before(nbf) {
		return Identity{}, ErrNotYetValid
	}

	// Audience.
	if len(cfg.Audiences) > 0 {
		if !audienceIntersects(claims["aud"], cfg.Audiences) {
			return Identity{}, ErrAudience
		}
	}

	// Subject / trust domain.
	sub, _ := claims["sub"].(string)
	trustDomain := strings.TrimRight(cfg.ExpectedIssuer, "/")
	if cfg.RequireSPIFFESubject {
		td, err := spiffeTrustDomain(sub)
		if err != nil {
			return Identity{}, err
		}
		trustDomain = td
	}
	if sub == "" {
		return Identity{}, fmt.Errorf("%w: empty subject", ErrMalformed)
	}

	aud := audienceList(claims["aud"])
	return Identity{
		Method:         cfg.Method,
		Subject:        sub,
		TrustDomain:    trustDomain,
		Audience:       aud,
		IssuedAt:       iat,
		NotBefore:      nbf,
		ExpiresAt:      exp,
		EvidenceDigest: evidenceDigest([]byte(token)),
		Claims:         claims,
	}, nil
}

// verifyJWS checks the signature for an allowlisted algorithm using a
// type-matched key. A key of the wrong type for the header alg is a failure
// (this is where algorithm-confusion attacks are stopped).
func verifyJWS(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 requires an RSA key", ErrAlg)
		}
		sum := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, sum[:], sig); err != nil {
			return ErrSignature
		}
		return nil
	case "EdDSA":
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: EdDSA requires an Ed25519 key", ErrAlg)
		}
		if len(edKey) != ed25519.PublicKeySize || !ed25519.Verify(edKey, signingInput, sig) {
			return ErrSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrAlg, alg)
	}
}

// spiffeTrustDomain validates a spiffe:// ID per the SPIFFE-ID format and
// returns its trust domain. It parses with net/url and rejects anything the
// SPIFFE spec forbids in the authority — userinfo, a port, an empty host, or a
// query/fragment — so a crafted authority (e.g. "spiffe://evil@good/x" or
// "spiffe://good:9/x") can never yield a misattributed trust domain.
func spiffeTrustDomain(sub string) (string, error) {
	u, err := url.Parse(sub)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSubject, err)
	}
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("%w: scheme %q", ErrSubject, u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo not allowed in a SPIFFE ID", ErrSubject)
	}
	if u.Port() != "" {
		return "", fmt.Errorf("%w: port not allowed in a SPIFFE ID", ErrSubject)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: query/fragment not allowed in a SPIFFE ID", ErrSubject)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: empty trust domain", ErrSubject)
	}
	return host, nil
}

func numTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Unix(i, 0), true
		}
	}
	return time.Time{}, false
}

// audienceList normalises the aud claim (string or []any) to a string slice.
func audienceList(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func audienceIntersects(claim any, want []string) bool {
	have := audienceList(claim)
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

// rejectDuplicateJSONKeys walks the JSON object and errors on any duplicated
// member name at any depth. json.Unmarshal silently takes last-wins, which
// would let a token mean different things to different parsers.
func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	return scanNoDup(dec)
}

func scanNoDup(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = true
			if err := scanNoDup(dec); err != nil { // value
				return err
			}
		}
		_, err := dec.Token() // '}'
		return err
	case '[':
		for dec.More() {
			if err := scanNoDup(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return err
	}
	return nil
}
