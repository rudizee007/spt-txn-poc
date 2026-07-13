package statuslist

// token.go — the signed Status List Token (draft §Status List Token) and the
// verifier-side resolver that checks a referenced token's status offline.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenType is the JWT `typ` for a Status List Token.
const TokenType = "statuslist+jwt"

var (
	ErrToken       = errors.New("statuslist: malformed status list token")
	ErrAlg         = errors.New("statuslist: unexpected alg (EdDSA only; alg:none rejected)")
	ErrSig         = errors.New("statuslist: signature verification failed")
	ErrExpired     = errors.New("statuslist: status list token expired")
	ErrSubject     = errors.New("statuslist: status list token sub does not match requested uri")
	ErrUnavailable = errors.New("statuslist: status unavailable")
	ErrRevoked     = errors.New("statuslist: token revoked")
	ErrSuspended   = errors.New("statuslist: token suspended")
	ErrUnknown     = errors.New("statuslist: unknown status value")
)

// SignToken builds and signs a Status List Token for list `l` published at
// `uri`, valid for `ttl`. The signing key is the issuer's status key (distinct
// from its token issuance key).
func SignToken(l *List, uri string, iat time.Time, ttl time.Duration, statusKey ed25519.PrivateKey) (string, error) {
	if len(statusKey) != ed25519.PrivateKeySize {
		return "", errors.New("statuslist: bad status key size")
	}
	enc, err := l.Encode()
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": "EdDSA", "typ": TokenType}
	claims := map[string]any{
		"sub":         uri,
		"iat":         iat.UTC().Unix(),
		"exp":         iat.Add(ttl).UTC().Unix(),
		"ttl":         int64(ttl.Seconds()),
		"status_list": map[string]any{"bits": enc.Bits, "lst": enc.Lst},
		// entries is not a draft field; carry the declared length in a private
		// claim so a verifier can reconstruct exact bounds without ambiguity.
		"spt_entries": l.entries,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	sig := ed25519.Sign(statusKey, []byte(signingInput))
	return signingInput + "." + b64(sig), nil
}

// VerifyToken checks a Status List Token's signature, type, expiry, and that
// its sub matches the requested uri, then returns the decoded list. now is the
// verification time.
func VerifyToken(token, uri string, statusPub ed25519.PublicKey, now time.Time) (*List, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 parts", ErrToken)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header b64", ErrToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrToken)
	}
	if hdr.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: %q", ErrAlg, hdr.Alg)
	}
	if hdr.Typ != TokenType {
		return nil, fmt.Errorf("%w: typ %q", ErrToken, hdr.Typ)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature b64", ErrToken)
	}
	if len(statusPub) != ed25519.PublicKeySize || !ed25519.Verify(statusPub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrSig
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload b64", ErrToken)
	}
	var claims struct {
		Sub        string `json:"sub"`
		Exp        int64  `json:"exp"`
		Entries    int    `json:"spt_entries"`
		StatusList struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrToken)
	}
	if claims.Sub != uri {
		return nil, fmt.Errorf("%w: %q != %q", ErrSubject, claims.Sub, uri)
	}
	// A status snapshot MUST carry an expiry. Without one a stale revocation
	// list would be trusted forever, so an absent or zero exp fails closed
	// (revocation freshness is a security property, not a nicety).
	if claims.Exp == 0 {
		return nil, fmt.Errorf("%w: status list token has no exp", ErrExpired)
	}
	if now.Unix() >= claims.Exp {
		return nil, ErrExpired
	}
	return Decode(Encoded{Bits: claims.StatusList.Bits, Lst: claims.StatusList.Lst}, claims.Entries)
}

// Reference is a referenced token's `status.status_list` binding.
type Reference struct {
	Index int
	URI   string
}

// ReferenceFromClaims extracts the status-list reference from a token's claims,
// or (zero, false) if the token carries no status claim. A malformed status
// claim returns ok=false with a non-nil error so the caller can fail closed
// rather than silently skip the check.
func ReferenceFromClaims(claims map[string]any) (Reference, bool, error) {
	statusRaw, ok := claims["status"].(map[string]any)
	if !ok {
		return Reference{}, false, nil // no status claim: not in scope
	}
	slRaw, ok := statusRaw["status_list"].(map[string]any)
	if !ok {
		return Reference{}, false, fmt.Errorf("%w: status without status_list", ErrToken)
	}
	uri, _ := slRaw["uri"].(string)
	if uri == "" {
		return Reference{}, false, fmt.Errorf("%w: status_list without uri", ErrToken)
	}
	idxF, ok := slRaw["idx"].(float64)
	if !ok {
		// Also accept an int (in-process construction).
		if i, iok := slRaw["idx"].(int); iok {
			return Reference{Index: i, URI: uri}, true, nil
		}
		return Reference{}, false, fmt.Errorf("%w: status_list without numeric idx", ErrToken)
	}
	return Reference{Index: int(idxF), URI: uri}, true, nil
}

// Resolver holds verified, cached Status Lists and answers status queries
// offline. It is the verifier-side integration point. Safe for concurrent
// reads after population; populate before serving.
type Resolver struct {
	lists map[string]*List
}

// NewResolver builds an empty resolver.
func NewResolver() *Resolver { return &Resolver{lists: map[string]*List{}} }

// AddVerified verifies a Status List Token and caches the resulting list under
// its uri. Call this from the snapshot-distribution path, never the hot path.
func (r *Resolver) AddVerified(token, uri string, statusPub ed25519.PublicKey, now time.Time) error {
	l, err := VerifyToken(token, uri, statusPub, now)
	if err != nil {
		return err
	}
	r.lists[uri] = l
	return nil
}

// Check resolves the reference and returns nil only when the status is VALID.
// Every other outcome — list not cached, index out of range, revoked,
// suspended, or an unknown status value — is a fail-closed error. The caller
// maps ErrUnavailable to decision class `unavailable` and the rest to
// `violation`.
func (r *Resolver) Check(ref Reference) error {
	l, ok := r.lists[ref.URI]
	if !ok {
		return fmt.Errorf("%w: no cached list for %q", ErrUnavailable, ref.URI)
	}
	s, err := l.Get(ref.Index)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err) // out-of-range ⇒ fail closed
	}
	switch s {
	case StatusValid:
		return nil
	case StatusInvalid:
		return ErrRevoked
	case StatusSuspended:
		return ErrSuspended
	default:
		return fmt.Errorf("%w: %d", ErrUnknown, s)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
