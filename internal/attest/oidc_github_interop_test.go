package attest

// oidc_github_interop_test.go — hermetic interop test against a REAL cloud IdP.
//
// The token in testdata/ is a genuine GitHub Actions OIDC token
// (issuer https://token.actions.githubusercontent.com), and the JWKS in
// testdata/ is GitHub's real published RSA signing key for that token's kid.
// GitHub OIDC is one of the workload-identity IdPs used for AWS/GCP/Azure
// federation, so this exercises the exact production path a cloud-workload
// assertion takes: real RS256 signature, issuer, audience, and subject.
//
// It is hermetic (no network): the captured token's exp/nbf are fixed, so the
// clock is pinned inside the validity window via JWTConfig.Now. This is a
// permanent regression test that the verifier accepts a real cloud-signed
// workload token — and fails closed on expiry, wrong audience, wrong issuer,
// and a tampered signature.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// Captured token validity window (unix seconds): nbf 1783960900, exp 1783961500.
var githubTokenWithin = time.Unix(1783961300, 0)

// The fixture is deliberately NOT committed: a real OIDC token carries the
// minting repo's identity in its claims, which must not be published from this
// public repo (disclosure barrier). It is gitignored; drop a token +
// matching JWKS in testdata/ locally to enable this interop check. When absent,
// the test skips (the mock-based discovery/JWKS tests still run in CI).
func requireGitHubFixture(t *testing.T) {
	t.Helper()
	for _, name := range []string{"github_oidc_token.txt", "github_oidc_jwks.json"} {
		if _, err := os.Stat("testdata/" + name); err != nil {
			t.Skipf("GitHub OIDC interop fixture testdata/%s not present; skipping", name)
		}
	}
}

func loadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

func githubKeySource(t *testing.T) KeySource {
	t.Helper()
	keys, err := ParseJWKS(loadTestdata(t, "github_oidc_jwks.json"))
	if err != nil {
		t.Fatalf("parse GitHub JWKS: %v", err)
	}
	return NewStaticKeySource(keys)
}

func githubToken(t *testing.T) string {
	t.Helper()
	return string(loadTestdata(t, "github_oidc_token.txt"))
}

func githubBaseConfig() JWTConfig {
	return JWTConfig{
		Method:         MethodOIDC,
		ExpectedIssuer: githubActionsIssuer,
		Audiences:      []string{"spt-txn-test"},
		RequireExpiry:  true,
		Now:            githubTokenWithin,
	}
}

func TestGitHubOIDC_RealToken_Verifies(t *testing.T) {
	requireGitHubFixture(t)
	id, err := VerifyJWT(context.Background(), githubToken(t), githubBaseConfig(), githubKeySource(t))
	if err != nil {
		t.Fatalf("real GitHub OIDC token failed to verify: %v", err)
	}
	if id.Method != MethodOIDC {
		t.Fatalf("method = %q", id.Method)
	}
	// Assert the GitHub Actions subject SHAPE, not the specific minting repo
	// (that would embed a repo name in this public repo — disclosure barrier).
	if !strings.HasPrefix(id.Subject, "repo:") || !strings.Contains(id.Subject, ":ref:") {
		t.Fatalf("subject not a GitHub Actions repo subject: %q", id.Subject)
	}
	// The rich workload claims must survive to the decision layer.
	if v, ok := id.Claims["repository_visibility"].(string); !ok || (v != "private" && v != "public") {
		t.Fatalf("repository_visibility claim missing/unexpected: %q", v)
	}
	if v, _ := id.Claims["actor"].(string); v == "" {
		t.Fatalf("actor claim missing")
	}
}

func TestGitHubOIDC_RealToken_FailClosed(t *testing.T) {
	requireGitHubFixture(t)
	ctx := context.Background()
	ks := githubKeySource(t)
	token := githubToken(t)

	t.Run("expired", func(t *testing.T) {
		cfg := githubBaseConfig()
		cfg.Now = time.Unix(1783961500+3600, 0) // an hour past exp
		if _, err := VerifyJWT(ctx, token, cfg, ks); !errors.Is(err, ErrExpired) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		cfg := githubBaseConfig()
		cfg.Now = time.Unix(1783960900-3600, 0) // an hour before nbf
		if _, err := VerifyJWT(ctx, token, cfg, ks); !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("want ErrNotYetValid, got %v", err)
		}
	})

	t.Run("wrong_audience", func(t *testing.T) {
		cfg := githubBaseConfig()
		cfg.Audiences = []string{"someone-elses-relying-party"}
		if _, err := VerifyJWT(ctx, token, cfg, ks); !errors.Is(err, ErrAudience) {
			t.Fatalf("want ErrAudience, got %v", err)
		}
	})

	t.Run("wrong_issuer", func(t *testing.T) {
		cfg := githubBaseConfig()
		cfg.ExpectedIssuer = "https://evil.example"
		if _, err := VerifyJWT(ctx, token, cfg, ks); !errors.Is(err, ErrIssuer) {
			t.Fatalf("want ErrIssuer, got %v", err)
		}
	})

	t.Run("tampered_signature", func(t *testing.T) {
		// Flip the last base64url char of the signature; header/payload are
		// untouched so it reaches the signature check and must fail there.
		b := []byte(token)
		if b[len(b)-1] == 'A' {
			b[len(b)-1] = 'B'
		} else {
			b[len(b)-1] = 'A'
		}
		if _, err := VerifyJWT(ctx, string(b), githubBaseConfig(), ks); !errors.Is(err, ErrSignature) {
			t.Fatalf("want ErrSignature, got %v", err)
		}
	})
}
