package main

// Regression tests for the guards added on 2026-09-09. Each one fails when the
// guard it covers is reverted; that is the whole point of the file, and a test
// here that still passes with its fix removed is a bug in the test.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// ── control bytes ──────────────────────────────────────────────────────────

// A control byte survives argv and the prompt reader but not the shell: bash
// and sh drop NUL from a quoted word, so run.sh would start the PEP under a
// value that policy.json does not record while the receipt still cites
// policy.json's hash. CR does the same to the generated README's headings.
func TestNonEmpty_RefusesControlBytes(t *testing.T) {
	for _, bad := range []string{"pay\x00ments", "pay\rments", "pay\nments", "pay\tments", "pay\x7fments", "\x1b[31mpayments"} {
		if err := nonEmpty(bad); !errors.Is(err, errControlChar) {
			t.Errorf("nonEmpty(%q) = %v, want errControlChar", bad, err)
		}
	}
	for _, ok := range []string{"payments.example", "a2a://payments.example", "pay/ments", "pay ments", "did:web:x"} {
		if err := nonEmpty(ok); err != nil {
			t.Errorf("nonEmpty(%q) = %v, want nil", ok, err)
		}
	}
}

// End to end: the value never reaches run.sh or policy.json, and nothing is
// written — not even the temporary directory.
func TestGenerate_RefusesAControlByteInAnOperatorValue(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	cfg := mcpConfig(out)
	cfg.Audience = "pay\x00ments.example"

	g := &generator{cfg: cfg, now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errControlChar) {
		t.Fatalf("run() = %v, want errControlChar", err)
	}
	assertNothingLeft(t, parent, out)
}

// ── the TTL ceiling is the engine's, not a number we chose ─────────────────

// maxAcceptableTokenTTL exists because decision.New refuses to build when its
// replay window is shorter than MaxTokenTTL. If either side moves, this fails
// rather than letting the generator emit a deployment that cannot start.
func TestMaxTokenTTLCeilingMatchesTheEngine(t *testing.T) {
	base := func(ttl time.Duration) decision.Config {
		return decision.Config{
			PEP:         "pep.spt-txn",
			PolicyHash:  "hash",
			Audience:    "payments.example",
			MaxTokenTTL: ttl,
			Verify: func(context.Context, string) (map[string]any, error) {
				return map[string]any{}, nil
			},
			Emit: func(*receipt.Receipt) (string, error) { return "", nil },
		}
	}
	if _, err := decision.New(base(maxAcceptableTokenTTL)); err != nil {
		t.Fatalf("the engine rejects our ceiling %s: %v", maxAcceptableTokenTTL, err)
	}
	_, err := decision.New(base(maxAcceptableTokenTTL + time.Second))
	if err == nil {
		t.Fatalf("the engine accepts %s, so our ceiling is lower than it needs to be",
			maxAcceptableTokenTTL+time.Second)
	}
	if !strings.Contains(err.Error(), "ReplayWindow") {
		t.Fatalf("rejected for the wrong reason, so this test proves nothing: %v", err)
	}
}

// And the generator refuses it BEFORE generating any key, rather than
// reporting success on a deployment that fails at startup.
func TestValidate_RefusesATTLTheEngineWouldReject(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	cfg := mcpConfig(out)
	cfg.MaxTokenTTL = maxAcceptableTokenTTL + time.Second

	g := &generator{cfg: cfg, now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errTTLTooLong) {
		t.Fatalf("run() = %v, want errTTLTooLong", err)
	}
	assertNothingLeft(t, parent, out)
}

// ── -listen is an address, not an identifier ───────────────────────────────

func TestValidateListenAddr(t *testing.T) {
	for _, ok := range []string{":8402", "127.0.0.1:8402", "localhost:8402", "[::1]:8402", "0.0.0.0:1"} {
		if err := validateListenAddr(ok); err != nil {
			t.Errorf("validateListenAddr(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"8402", "", "127.0.0.1", ":http", ":80a", "host:80:80", "h ost:80", ":80\x00"} {
		if err := validateListenAddr(bad); err == nil {
			t.Errorf("validateListenAddr(%q) = nil, want an error", bad)
		}
	}
}

// ── the output path is re-checked under the lock ───────────────────────────

// checkOutDir runs before key generation; MkdirTemp then publishes a visible
// entry in the parent, which tells anyone watching that the check has passed.
// The re-check immediately before os.Remove is what stops a path swapped in
// that window from being silently unlinked.
func TestGenerate_RefusesAnOutputPathSwappedAfterTheCheck(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	planted := false
	g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader,
		beforeWrite: func(rel string) error {
			// After the check has passed and generation is under way.
			if !planted {
				planted = true
				if err := os.Symlink(victim, out); err != nil {
					t.Fatalf("plant: %v", err)
				}
			}
			return nil
		}}

	_, err := g.run()
	if !errors.Is(err, errOutDirChanged) {
		t.Fatalf("run() = %v, want errOutDirChanged", err)
	}
	// The planted symlink survives — it was refused, not unlinked.
	st, lerr := os.Lstat(out)
	if lerr != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was consumed rather than refused (lstat err=%v)", lerr)
	}
	if body, rerr := os.ReadFile(victim); rerr != nil || string(body) != "do not touch\n" {
		t.Fatalf("victim damaged (err=%v)", rerr)
	}
	// And no temporary directory is left holding keys.
	entries, derr := os.ReadDir(parent)
	if derr != nil {
		t.Fatal(derr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".spt-txn-init-") {
			t.Errorf("temporary directory left behind: %s", e.Name())
		}
	}
}

// ── a panic must not leave the keys behind ─────────────────────────────────

// The cleanup defer is conditioned on an explicit success flag rather than on
// run()'s named error return: a panic unwinds with err still nil, so an
// err-conditioned defer would skip RemoveAll and strand issuer.key.
func TestGenerate_PanicLeavesNoTemporaryDirectory(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")

	g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader,
		beforeWrite: func(rel string) error {
			if rel == fileREADME { // late: the keys are already on disk
				panic("injected: panic mid-generation")
			}
			return nil
		}}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the injected panic did not propagate; this test proves nothing")
			}
		}()
		_, _ = g.run()
	}()

	assertNothingLeft(t, parent, out)
}

// ── the enforcement point is not chosen by the environment ────────────────

// run.sh inherits its environment from whoever starts it; for MCP that is the
// client, whose config the operator may not have written. A "${MCP_PEP:=...}"
// indirection let that party swap a pass-through in for the enforcement point
// while run.sh, policy.json and the policy hash stayed byte-identical.
func TestRunScript_DoesNotResolveThePEPFromTheEnvironment(t *testing.T) {
	for _, cfg := range []config{mcpConfig(filepath.Join(t.TempDir(), "d")), a2aConfig(filepath.Join(t.TempDir(), "d"))} {
		res := generate(t, cfg)
		run := string(readFile(t, res.OutDir, fileRunScript))
		for _, forbidden := range []string{"MCP_PEP", "A2A_PEP", "${", "$("} {
			// $( is allowed only in the basename call inside the error message.
			if forbidden == "$(" {
				continue
			}
			if strings.Contains(run, forbidden) {
				t.Errorf("%s run.sh still reads %s from the environment:\n%s", cfg.Profile, forbidden, run)
			}
		}
	}
}

func TestRunScript_PinsTheBinaryWhenGiven(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	cfg := mcpConfig(out)
	cfg.PEPBinary = "/opt/spt/mcp-pep"
	res := generate(t, cfg)

	run := string(readFile(t, out, fileRunScript))
	if !strings.Contains(run, "exec '/opt/spt/mcp-pep'") {
		t.Errorf("run.sh does not exec the pinned path:\n%s", run)
	}
	if strings.Contains(run, "command -v") {
		t.Error("run.sh still does a PATH lookup despite a pinned binary")
	}
	readme := string(readFile(t, out, fileREADME))
	if !strings.Contains(readme, "PINNED") || !strings.Contains(readme, "/opt/spt/mcp-pep") {
		t.Error("README does not tell the operator the binary is pinned")
	}
	_ = res
}

// A relative path resolves against run.sh's own directory, which is the
// deployment — so it would "pin" whatever a same-uid process drops in there.
func TestValidate_RefusesARelativePEPBinary(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	cfg := mcpConfig(out)
	cfg.PEPBinary = "./mcp-pep"

	g := &generator{cfg: cfg, now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errPEPBinaryRelative) {
		t.Fatalf("run() = %v, want errPEPBinaryRelative", err)
	}
	assertNothingLeft(t, parent, out)
}

// ── run.sh says what the policy hash does and does not cover ──────────────

// policy_hash is specified (draft -03, docs/spec/RECEIPT-FORMAT.md) as the
// hash of the policy bundle VERSION EVALUATED. It is not a commitment to the
// deployment's wiring, and run.sh used to tell the operator it was — which
// made an edited -upstream look self-announcing when it is not.
func TestRunScript_StatesWhatThePolicyHashCovers(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	generate(t, a2aConfig(out))
	run := string(readFile(t, out, fileRunScript))

	for _, want := range []string{
		"which\n# policy version was in force",
		"does NOT cover the wiring below",
		"-upstream",
		"-audit-log",
		"WITHOUT changing any receipt",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("run.sh lacks %q:\n%s", want, run)
		}
	}
	// And it must not carry the claim that was false.
	if strings.Contains(run, "Every value below is also recorded in policy.json") {
		t.Error("run.sh still claims policy.json records every value below it")
	}
}

// ── the issuer key can stay out of this tool entirely ─────────────────────

// -tts-pub is the only mode in which no key that can MINT a token is ever
// written to disk by this tool: the operator's existing TTS, or a PKCS#11
// token, holds the private half and spt-txn-init never sees it.
func TestGenerate_ExternalIssuerWritesNoIssuerPrivateKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	out := filepath.Join(t.TempDir(), "deploy")
	cfg := mcpConfig(out)
	cfg.TTSPubHex = pubHex
	res := generate(t, cfg)

	if _, err := os.Stat(filepath.Join(out, fileIssuerKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists in an external-issuer deployment (err=%v)", fileIssuerKey, err)
	}
	for _, f := range res.Files {
		if f.Name == fileIssuerKey {
			t.Error("the summary still lists issuer.key")
		}
	}
	// The key the PEP verifies against is the one supplied, everywhere.
	if got := strings.TrimSpace(string(readFile(t, out, fileIssuerPub))); got != pubHex {
		t.Errorf("issuer.pub = %s, want the supplied key", got)
	}
	if res.TTSPubHex != pubHex {
		t.Errorf("result.TTSPubHex = %s, want the supplied key", res.TTSPubHex)
	}
	if !strings.Contains(string(readFile(t, out, fileRunScript)), "PINNED='"+pubHex+"'") {
		t.Error("run.sh does not pin the supplied key")
	}
	if !strings.Contains(string(readFile(t, out, filePolicy)), pubHex) {
		t.Error("policy.json does not record the supplied key")
	}
	readme := string(readFile(t, out, fileREADME))
	if !strings.Contains(readme, "no issuer private key was generated, written or") {
		t.Error("README does not state that no issuer private key exists")
	}
	if strings.Contains(readme, "You are your own issuer") {
		t.Error("README still claims the self-issued posture")
	}
}

func TestValidate_RefusesABadTTSPub(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := hex.EncodeToString(pub)
	for _, bad := range []string{
		good[:62],               // too short
		good + "ab",             // too long
		strings.ToUpper(good),   // uppercase, so two spellings of one key
		strings.Repeat("z", 64), // not hex
		"0x" + good[2:],         // 0x prefix
	} {
		cfg := mcpConfig(filepath.Join(t.TempDir(), "deploy"))
		cfg.TTSPubHex = bad
		if err := validate(&cfg); !errors.Is(err, errTTSPubHex) {
			t.Errorf("validate(-tts-pub %q) = %v, want errTTSPubHex", bad, err)
		}
	}
	cfg := mcpConfig(filepath.Join(t.TempDir(), "deploy"))
	cfg.TTSPubHex = good
	if err := validate(&cfg); err != nil {
		t.Errorf("validate rejected a good key: %v", err)
	}
}

// ── the issuer key is placed beside the deployment, never inside it ────────

// Nothing in a deployment reads issuer.key: both PEPs take -tts-pub, the
// public half, and mint.sh mints under cmd/mcp-mint's throwaway issuer. The
// deployment directory is what gets copied into an image, mounted, archived
// or committed, so a key that can mint must not be inside it.
//
// This bounds ACCIDENT, not an attacker: a process running as the operator
// reads it wherever it sits. -tts-pub is the mode with no such key at all.
func TestGenerate_IssuerKeyIsPlacedBesideTheDeployment(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	res := generate(t, mcpConfig(out))

	if _, err := os.Stat(filepath.Join(out, fileIssuerKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s is inside the deployment (err=%v)", fileIssuerKey, err)
	}
	want := out + "-issuer.key"
	if res.IssuerKeyPath != want {
		t.Fatalf("IssuerKeyPath = %s, want %s", res.IssuerKeyPath, want)
	}
	st, err := os.Lstat(want)
	if err != nil {
		t.Fatalf("the issuer key was not placed: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Errorf("issuer key mode %o, want 0600", got)
	}
	// It is the private half of the key the deployment pins.
	priv := ed25519.PrivateKey(readHexKey(t, parent, filepath.Base(want), ed25519.PrivateKeySize))
	pub := strings.TrimSpace(string(readFile(t, out, fileIssuerPub)))
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != pub {
		t.Error("the placed key is not the private half of issuer.pub")
	}
	// And the operator is told, in both places they will look.
	readme := string(readFile(t, out, fileREADME))
	if !strings.Contains(readme, "NOT in this directory") || !strings.Contains(readme, "deploy-issuer.key") {
		t.Error("README does not say where the issuer key went")
	}
	var buf bytes.Buffer
	res.printSummary(&buf)
	if !strings.Contains(buf.String(), "deploy-issuer.key") {
		t.Errorf("summary does not name the issuer key path:\n%s", buf.String())
	}
}

// The placement must never overwrite. os.Link answers "is that path free?"
// atomically — link(2) fails with EEXIST — rather than by a check a racing
// process can invalidate.
func TestGenerate_RefusesAnOccupiedIssuerKeyPath(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	occupied := out + "-issuer.key"
	if err := os.WriteFile(occupied, []byte("someone else's key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errIssuerKeyExists) {
		t.Fatalf("run() = %v, want errIssuerKeyExists", err)
	}
	if body, err := os.ReadFile(occupied); err != nil || string(body) != "someone else's key\n" {
		t.Fatalf("the existing file was overwritten (err=%v)", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Error("a deployment was written despite the refusal")
	}
}

// ── run.sh must not make the deployment anyone's working directory ────────

// The PEP's working directory becomes the working directory of everything it
// starts: for MCP that is the wrapped third-party server, which is the one
// component of the deployment the operator did not write. The deployment
// directory holds log.key, the receipt log and run.sh itself, so a
// cd "$(dirname "$0")" handed all three to that server.
//
// Resolving an absolute base instead leaves the process where its caller was,
// so the wrapped server sees exactly the environment it would have seen had
// the client spawned it directly — mcp-pep stays transparent and needs no
// change — and the deployment is nobody's cwd.
func TestRunScript_DoesNotChangeTheWorkingDirectory(t *testing.T) {
	for _, cfg := range []config{
		mcpConfig(filepath.Join(t.TempDir(), "deploy")),
		a2aConfig(filepath.Join(t.TempDir(), "deploy")),
	} {
		res := generate(t, cfg)
		run := string(readFile(t, res.OutDir, fileRunScript))

		for _, line := range strings.Split(run, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "cd ") {
				t.Errorf("%s run.sh changes directory (%q); the deployment becomes the cwd of whatever the PEP starts",
					cfg.Profile, strings.TrimSpace(line))
			}
		}
		if !strings.Contains(run, `HERE=$(cd "$(dirname "$0")" && pwd)`) {
			t.Errorf("%s run.sh does not resolve an absolute base:\n%s", cfg.Profile, run)
		}
		// Every path it hands the PEP is absolute, so nothing depends on cwd.
		for _, want := range []string{
			`-log-key-file "$HERE/` + fileLogKey + `"`,
			`-audit-log "$HERE/`,
		} {
			if !strings.Contains(run, want) {
				t.Errorf("%s run.sh lacks %q:\n%s", cfg.Profile, want, run)
			}
		}
	}
}

// ── issuer.pub and the pin must not drift apart silently ──────────────────

// run.sh pins the issuer key as a LITERAL and does not read issuer.pub: that
// file is 0644 and run.sh is 0700, so reading it would move the trust anchor
// into the weaker of the two. But the copy is what an operator hands their TTS
// and what the file table invites them to replace, and a deployment that keeps
// verifying against a key its own directory no longer names is failing open in
// the half that matters. So run.sh checks the two agree at every start.
//
// Executed for real: the script is run with a deliberately missing pinned
// binary, so an intact deployment fails at the binary guard — which proves it
// got PAST the pin check — and a tampered one fails at the pin check itself.
func TestRunScript_RefusesWhenIssuerPubDoesNotMatchThePin(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	cfg := mcpConfig(out)
	cfg.PEPBinary = "/nonexistent/mcp-pep"
	generate(t, cfg)
	script := filepath.Join(out, fileRunScript)

	const pinMsg = "does not match the key this script pins"
	const binMsg = "is missing or not executable"

	got, err := exec.Command(script).CombinedOutput()
	if err == nil {
		t.Fatalf("run.sh succeeded with a nonexistent binary:\n%s", got)
	}
	if strings.Contains(string(got), pinMsg) {
		t.Fatalf("the pin check fired on an intact deployment:\n%s", got)
	}
	if !strings.Contains(string(got), binMsg) {
		t.Fatalf("did not reach the binary guard, so the pin check is untested:\n%s", got)
	}

	// Now replace issuer.pub in place, exactly as an operator might.
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, fileIssuerPub),
		[]byte(hex.EncodeToString(other)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err = exec.Command(script).CombinedOutput()
	if err == nil {
		t.Fatalf("run.sh started with a mismatched issuer.pub:\n%s", got)
	}
	if !strings.Contains(string(got), pinMsg) {
		t.Fatalf("run.sh did not refuse the mismatch:\n%s", got)
	}
	if !strings.Contains(string(got), "rotates nothing") {
		t.Errorf("the refusal does not tell the operator why replacing files does not work:\n%s", got)
	}
}
