package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

// Every test that asserts a rejection also asserts an acceptance, and asserts
// WHICH rule fired. A validator that refuses everything, or one whose check
// under test was deleted so that a later check fired instead, fails these.

// fixedNow is a stable clock so ids and validity windows are reproducible
// across a test.
var fixedNow = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func mcpConfig(out string) config {
	return config{
		Profile:        profileMCP,
		OutDir:         out,
		Audience:       "payments.example",
		Issuer:         "did:web:payments.example",
		MaxTokenTTL:    60 * time.Second,
		ServerIdentity: "payments.example",
		ServerCmd:      []string{"./the-server", "--flag", "a b", "it's"},
	}
}

func a2aConfig(out string) config {
	return config{
		Profile:       profileA2A,
		OutDir:        out,
		Audience:      "payments.example",
		Issuer:        "did:web:payments.example",
		MaxTokenTTL:   60 * time.Second,
		Upstream:      "http://127.0.0.1:9000/",
		PublicURL:     "https://guarded.example/",
		AgentIdentity: "a2a://payments.example",
		Listen:        ":8402",
	}
}

func generate(t *testing.T, cfg config) *result {
	t.Helper()
	g := &generator{cfg: cfg, now: fixedNow, rand: rand.Reader}
	res, err := g.run()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return res
}

// expectedPrivateFiles is the list of files that hold private key material,
// stated HERE and cross-checked against the production list in both
// directions. Three assertions hang off it (0600, no-leak, PRIVATE marker);
// ranging over privateFiles itself would let an entry deleted from it vanish
// from all three (mutation P-1 survived exactly that way once).
// keyFile locates one file holding private key material. It exists because
// the issuer key is NOT in the deployment directory, and on 2026-09-09 moving
// it out silently removed it from both the no-leak search and the 0600 check:
// four mutations that had been killed for weeks began surviving. Any test
// asserting something about "the private keys" ranges over this, not over
// privateFiles, which is deployment-scoped by design.
type keyFile struct{ Dir, Name string }

func allPrivateKeyFiles(t *testing.T, res *result) []keyFile {
	t.Helper()
	var out []keyFile
	for _, n := range expectedPrivateFiles(t) {
		out = append(out, keyFile{res.OutDir, n})
	}
	if res.IssuerKeyPath != "" {
		out = append(out, keyFile{filepath.Dir(res.IssuerKeyPath), filepath.Base(res.IssuerKeyPath)})
	}
	return out
}

func expectedPrivateFiles(t *testing.T) []string {
	t.Helper()
	// issuer.key is NOT here: it is placed beside the deployment, not in it.
	// TestGenerate_IssuerKeyIsPlacedBesideTheDeployment covers that one.
	want := []string{"log.key", "snapshot-publication.key"}
	if len(privateFiles) != len(want) {
		t.Fatalf("privateFiles = %v, want exactly %v", privateFiles, want)
	}
	for _, w := range want {
		if !isPrivate(w) {
			t.Fatalf("privateFiles lacks %s: %v", w, privateFiles)
		}
	}
	for _, p := range privateFiles {
		found := false
		for _, w := range want {
			found = found || w == p
		}
		if !found {
			t.Fatalf("privateFiles names %s, which this test does not expect", p)
		}
	}
	return want
}

func readFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func readHexKey(t *testing.T, dir, name string, size int) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(string(readFile(t, dir, name))))
	if err != nil {
		t.Fatalf("%s is not hex: %v", name, err)
	}
	if len(b) != size {
		t.Fatalf("%s: %d bytes, want %d", name, len(b), size)
	}
	return b
}

// ── the snapshot ───────────────────────────────────────────────────────────

// TestGenerate_SnapshotVerifiesWithTheRealVerifier is the contract the brief
// names: the artifact must pass pkg/trustsnapshot.Verify under the written
// publication key, and a body altered after signing must not.
func TestGenerate_SnapshotVerifiesWithTheRealVerifier(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(out))

	manifest := readFile(t, out, fileManifest)
	body := readFile(t, out, fileRegistry)
	pubPub := ed25519.PublicKey(readHexKey(t, out, filePublicationPub, ed25519.PublicKeySize))
	if hex.EncodeToString(pubPub) != res.PublicationPubHex {
		t.Fatalf("summary reports publication key %s, file holds %s", res.PublicationPubHex, hex.EncodeToString(pubPub))
	}
	opts := trustsnapshot.Options{PinnedKeys: []ed25519.PublicKey{pubPub}, MaxAge: 24 * time.Hour, Now: fixedNow}

	m, err := trustsnapshot.Verify(manifest, body, opts)
	if err != nil {
		t.Fatalf("the generated snapshot does not verify: %v", err)
	}
	if m.ID != res.SnapshotID {
		t.Fatalf("manifest id %q, summary says %q", m.ID, res.SnapshotID)
	}
	if len(m.IssuerIDs) != 1 || m.IssuerIDs[0] != "did:web:payments.example" {
		t.Fatalf("issuer_ids = %v, want exactly the configured issuer", m.IssuerIDs)
	}

	// The body names the issuer key the PEP pins, and nothing else. Swap the
	// key bytes for another key: the digest no longer matches and the verifier
	// says so by its own rule, not by a parse failure.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tampered := tamperBodyKey(t, body, otherPub)
	if _, err := trustsnapshot.Verify(manifest, tampered, opts); !errors.Is(err, trustsnapshot.ErrDigestMismatch) {
		t.Fatalf("tampered body: err = %v, want ErrDigestMismatch", err)
	}

	// And the signature is over the publication key written beside it — not
	// the issuer key, not any other. A verifier pinning the wrong key refuses.
	ttsPub := ed25519.PublicKey(readHexKey(t, out, fileIssuerPub, ed25519.PublicKeySize))
	wrongPin := trustsnapshot.Options{PinnedKeys: []ed25519.PublicKey{ttsPub}, MaxAge: 24 * time.Hour, Now: fixedNow}
	if _, err := trustsnapshot.Verify(manifest, body, wrongPin); !errors.Is(err, trustsnapshot.ErrBadSignature) {
		t.Fatalf("pinned issuer key instead of publication key: err = %v, want ErrBadSignature", err)
	}
}

// tamperBodyKey rewrites the single record's public key, keeping the body a
// valid snapshot body so the failure is the digest and not the parser.
func tamperBodyKey(t *testing.T, body []byte, newKey ed25519.PublicKey) []byte {
	t.Helper()
	var ff struct {
		Version int                     `json:"version"`
		Records []*trustregistry.Record `json:"records"`
	}
	if err := json.Unmarshal(body, &ff); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if len(ff.Records) != 1 {
		t.Fatalf("body has %d records, want 1", len(ff.Records))
	}
	ff.Records[0].PublicKey = newKey
	b, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGenerate_SnapshotBindsTheIssuerKeyThePEPPins: the record is a tts_issuer
// record for the configured issuer and its key IS issuer.pub. A snapshot that
// verified but named another role or another key would be a valid artifact
// about nothing.
func TestGenerate_SnapshotBindsTheIssuerKeyThePEPPins(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	// The real clock here: OpenVerified evaluates freshness and the record's
	// validity window at Lookup time against time.Now(), exactly as a service
	// loading this snapshot would.
	g := &generator{cfg: mcpConfig(out), now: time.Now(), rand: rand.Reader}
	res, err := g.run()
	if err != nil {
		t.Fatal(err)
	}

	reg, err := trustregistry.OpenVerified(filepath.Join(out, fileManifest), filepath.Join(out, fileRegistry), trustsnapshot.Options{
		PinnedKeys: []ed25519.PublicKey{readHexKey(t, out, filePublicationPub, ed25519.PublicKeySize)},
		MaxAge:     24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenVerified (the path cmd/agentsvc loads by): %v", err)
	}
	defer func() { _ = reg.Close() }()

	// A PEP-side verifier looks this key up by (iss, tts_issuer). The same
	// issuer under ct_issuer must be absent: one key, one role.
	rec, err := reg.Lookup(t.Context(), "did:web:payments.example", trustregistry.RoleTTSIssuer)
	if err != nil {
		t.Fatalf("lookup tts_issuer: %v", err)
	}
	if got := hex.EncodeToString(rec.PublicKey); got != res.TTSPubHex {
		t.Fatalf("snapshot names key %s, run.sh pins %s", got, res.TTSPubHex)
	}
	if !bytes.Equal(rec.PublicKey, readHexKey(t, out, fileIssuerPub, ed25519.PublicKeySize)) {
		t.Fatal("snapshot key differs from issuer.pub")
	}
	if _, err := reg.Lookup(t.Context(), "did:web:payments.example", trustregistry.RoleCTIssuer); err == nil {
		t.Fatal("the issuer key is also registered as ct_issuer; a key must hold one role")
	}
	// The issuer key is the private half of issuer.pub — the operator's TTS
	// signs with one and the PEP pins the other. It lives beside the
	// deployment, so read it from where run() actually put it.
	priv := ed25519.PrivateKey(readHexKey(t,
		filepath.Dir(res.IssuerKeyPath), filepath.Base(res.IssuerKeyPath), ed25519.PrivateKeySize))
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), rec.PublicKey) {
		t.Fatal("issuer.key is not the private half of the key the snapshot names")
	}
}

// TestGenerate_SelfCheckFailureWritesNothing: the self-check before the
// rename is what stops a mis-signed snapshot leaving the tool, and a failure
// at that point must leave nothing behind.
func TestGenerate_SelfCheckFailureWritesNothing(t *testing.T) {
	// The self-check cannot be made to fail through the public inputs — Sign
	// and Verify agree by construction — so this asserts the surrounding
	// property: a run that fails at the manifest step leaves nothing. That
	// the self-check itself has teeth is mutation M-10 in
	// scripts/mutate-spt-txn-init.sh (sign with the wrong key; generation
	// refuses), and M-11 (wrong key with the self-check disabled; the real
	// verifier in TestGenerate_SnapshotVerifiesWithTheRealVerifier refuses).
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader,
		beforeWrite: func(rel string) error {
			if rel == fileManifest {
				return errors.New("injected: manifest write fails")
			}
			return nil
		}}
	if _, err := g.run(); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("err = %v, want the injected failure", err)
	}
	assertNothingLeft(t, parent, out)
}

// ── refuse to overwrite ────────────────────────────────────────────────────

func TestGenerate_RefusesANonEmptyOutputDirectory(t *testing.T) {
	parent := t.TempDir()

	// Accepted: absent.
	generate(t, mcpConfig(filepath.Join(parent, "absent")))

	// Accepted: present but empty — and the generated files land IN it.
	empty := filepath.Join(parent, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	generate(t, mcpConfig(empty))
	if _, err := os.Stat(filepath.Join(empty, fileRunScript)); err != nil {
		t.Fatalf("empty existing directory was accepted but not populated: %v", err)
	}

	// Refused, by the non-empty rule: one unrelated file is enough.
	full := filepath.Join(parent, "full")
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &generator{cfg: mcpConfig(full), now: fixedNow, rand: rand.Reader}
	_, err := g.run()
	if !errors.Is(err, errOutDirNotEmpty) {
		t.Fatalf("non-empty dir: err = %v, want errOutDirNotEmpty", err)
	}
	if b, _ := os.ReadFile(filepath.Join(full, "notes.txt")); string(b) != "mine" {
		t.Fatal("the operator's file was touched")
	}
	entries, _ := os.ReadDir(full)
	if len(entries) != 1 {
		t.Fatalf("refused directory now has %d entries, want the operator's 1", len(entries))
	}

	// Refused, by a different rule: the path is a file.
	file := filepath.Join(parent, "a-file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	g = &generator{cfg: mcpConfig(file), now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errOutDirNotADir) {
		t.Fatalf("path is a file: err = %v, want errOutDirNotADir", err)
	}
}

// TestGenerate_RefusedRunLeavesNoTemporaryDirectory: a refusal is not a
// half-run either.
func TestGenerate_RefusedRunLeavesNoTemporaryDirectory(t *testing.T) {
	parent := t.TempDir()
	full := filepath.Join(parent, "full")
	if err := os.MkdirAll(filepath.Join(full, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &generator{cfg: mcpConfig(full), now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errOutDirNotEmpty) {
		t.Fatalf("err = %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(parent, ".spt-txn-init-*")); len(left) != 0 {
		t.Fatalf("temporary directories left behind: %v", left)
	}
}

// ── permissions ────────────────────────────────────────────────────────────

func TestGenerate_Permissions(t *testing.T) {
	// The modes are restated with Chmod after each write, so the caller's
	// umask can neither loosen a key file nor strip the execute bit from a
	// script; these are exact matches, not upper bounds.
	for _, cfg := range []config{mcpConfig(""), a2aConfig("")} {
		out := filepath.Join(t.TempDir(), "deploy")
		cfg.OutDir = out
		res := generate(t, cfg)

		st, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Errorf("%s: directory mode %o, want 0700", cfg.Profile, got)
		}
		keys := allPrivateKeyFiles(t, res)
		if len(keys) != 3 {
			t.Fatalf("%s: expected 3 private key files, got %d: %v", cfg.Profile, len(keys), keys)
		}
		for _, kf := range keys {
			st, err := os.Stat(filepath.Join(kf.Dir, kf.Name))
			if err != nil {
				t.Fatalf("%s: %v", cfg.Profile, err)
			}
			if got := st.Mode().Perm(); got != 0o600 {
				t.Errorf("%s: %s mode %o, want 0600", cfg.Profile, kf.Name, got)
			}
		}
		// Anti-vacuity: the non-secret files are NOT 0600 (the assertion above
		// is not satisfied by a blanket mode), and the scripts are executable.
		for _, name := range []string{fileIssuerPub, filePublicationPub, fileRegistry, fileManifest, filePolicy, fileREADME} {
			st, err := os.Stat(filepath.Join(out, name))
			if err != nil {
				t.Fatalf("%s: %v", cfg.Profile, err)
			}
			if got := st.Mode().Perm(); got != 0o644 {
				t.Errorf("%s: %s mode %o, want 0644", cfg.Profile, name, got)
			}
		}
		st, err = os.Stat(filepath.Join(out, fileRunScript))
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Errorf("%s: run.sh mode %o, want 0700", cfg.Profile, got)
		}
	}
}

// ── nothing private on stdout, nothing private outside the key files ───────

func TestGenerate_NoPrivateKeyMaterialOnStdout(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(out))

	var stdout bytes.Buffer
	res.printSummary(&stdout)
	printed := stdout.String()

	// The secrets, in every encoding a careless print could use. Hex ALONE is
	// not enough, and the narrower list was a real gap: registry.json and its
	// manifest carry key bytes only as base64 (trustregistry.Record.PublicKey
	// is []byte, which encoding/json renders base64), so a hex-only search can
	// never fire on those two files at all. Verified 2026-09-09: a private key
	// emitted in base64 — to stdout, and into run.sh — passed the whole suite.
	// owner[j] is the index in `private` of the key secrets[j] belongs to.
	keys := allPrivateKeyFiles(t, res)
	if len(keys) != 3 {
		t.Fatalf("expected 3 private key files for a self-issued deployment, got %d: %v", len(keys), keys)
	}
	var secrets []string
	var owner []int
	for i, kf := range keys {
		priv := readHexKey(t, kf.Dir, kf.Name, ed25519.PrivateKeySize)
		for _, b := range [][]byte{priv, priv[:32]} { // whole key, and the seed alone
			for _, enc := range []string{
				hex.EncodeToString(b),
				strings.ToUpper(hex.EncodeToString(b)),
				base64.StdEncoding.EncodeToString(b),
				base64.RawStdEncoding.EncodeToString(b),
				base64.URLEncoding.EncodeToString(b),
				base64.RawURLEncoding.EncodeToString(b),
				string(b), // the raw bytes, for a file that is not text
			} {
				secrets = append(secrets, enc)
				owner = append(owner, i)
			}
		}
	}

	// Anti-vacuity: the summary does contain the public values, so a search
	// of it finds things; and a summary that contained a secret WOULD be
	// caught (the check below is run against a doctored copy first).
	if !strings.Contains(printed, res.TTSPubHex) || !strings.Contains(printed, res.PolicyHash) {
		t.Fatalf("summary lacks the public values it is supposed to carry:\n%s", printed)
	}
	if !containsAny(printed+secrets[0], secrets) {
		t.Fatal("the secret search cannot find a secret it was handed; the check is broken")
	}
	if containsAny(printed, secrets) {
		t.Fatalf("private key material on stdout:\n%s", printed)
	}

	// EVERY file in the deployment except the private keys themselves. A
	// hard-coded list cannot cover a file a later change adds, and the point
	// of this test is to catch the change nobody thought about.
	inDeployment := map[string]bool{}
	for _, kf := range keys {
		if kf.Dir == out {
			inDeployment[kf.Name] = true
		}
	}
	scanned := 0
	if err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(out, path)
		if relErr != nil {
			return relErr
		}
		if inDeployment[rel] {
			return nil
		}
		scanned++
		if containsAny(string(readFile(t, out, rel)), secrets) {
			t.Errorf("%s carries private key material", rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", out, err)
	}
	if scanned == 0 {
		t.Fatal("walked the deployment and scanned nothing; the walk is broken")
	}

	// And the key files hold only their own key: a private key never
	// appears in another private key's file.
	for i, kf := range keys {
		content := string(readFile(t, kf.Dir, kf.Name))
		for j, sec := range secrets {
			if owner[j] != i && strings.Contains(content, sec) {
				t.Errorf("%s carries another file's private key", kf.Name)
			}
		}
	}
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// ── fail closed ────────────────────────────────────────────────────────────

func TestGenerate_FailureLeavesNoHalfWrittenDeployment(t *testing.T) {
	for _, failAt := range []string{fileLogKey, fileRegistry, fileRunScript, fileREADME} {
		parent := t.TempDir()
		out := filepath.Join(parent, "deploy")
		g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader,
			beforeWrite: func(rel string) error {
				if rel == failAt {
					return errors.New("injected failure at " + rel)
				}
				return nil
			}}
		_, err := g.run()
		if err == nil || !strings.Contains(err.Error(), "injected failure at "+failAt) {
			t.Fatalf("fail at %s: err = %v, want the injected failure", failAt, err)
		}
		assertNothingLeft(t, parent, out)
	}

	// Anti-vacuity: with no failure injected the same generator writes the
	// deployment (so the absence above is cleanup, not a generator that never
	// writes).
	parent := t.TempDir()
	out := filepath.Join(parent, "deploy")
	g := &generator{cfg: mcpConfig(out), now: fixedNow, rand: rand.Reader, beforeWrite: func(string) error { return nil }}
	if _, err := g.run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, fileREADME)); err != nil {
		t.Fatal(err)
	}
}

// assertNothingLeft: neither the output directory nor a temporary sibling
// exists after a failed run. The issuer key written before the failure must
// not be findable anywhere.
func assertNothingLeft(t *testing.T, parent, out string) {
	t.Helper()
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output directory exists after a failed run (err=%v)", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("left behind after a failed run: %s", e.Name())
	}
}

// ── validators ─────────────────────────────────────────────────────────────

func TestValidateProfile(t *testing.T) {
	for _, ok := range []string{"mcp", "a2a"} {
		if err := validateProfile(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	// The forward-auth skin is not in this tree and is not offered; neither
	// is any alias or case variant.
	for _, bad := range []string{"", "MCP", "forward-auth", "http", "envoy", "mcp "} {
		if err := validateProfile(bad); !errors.Is(err, errBadProfile) {
			t.Errorf("%q: err = %v, want errBadProfile", bad, err)
		}
	}
}

func TestValidateAbsoluteURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:9000/", "https://guarded.example/", "http://h", "https://h:8443/a/b?c=d"} {
		if err := validateAbsoluteURL(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	cases := []struct {
		in   string
		want error
	}{
		{"", errEmpty},
		{"   ", errEmpty},
		{"ftp://h/", errURLScheme},
		{"h:9000/", errURLScheme}, // parses as scheme "h", opaque "9000/"
		{"/relative/path", errURLScheme},
		{"127.0.0.1:9000", errURLUnparsable}, // a colon in the first path segment
		{"http://", errURLNoHost},
		{"https:///path", errURLNoHost},
		{"http://h/%zz", errURLUnparsable},
		{"://h", errURLUnparsable},
	}
	for _, c := range cases {
		if err := validateAbsoluteURL(c.in); !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.in, err, c.want)
		}
	}
}

func TestNonEmpty(t *testing.T) {
	for _, ok := range []string{"x", " x ", "payments.example"} {
		if err := nonEmpty(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ", "\t\n"} {
		if err := nonEmpty(bad); !errors.Is(err, errEmpty) {
			t.Errorf("%q: err = %v, want errEmpty", bad, err)
		}
	}
}

func TestValidateIdentifier(t *testing.T) {
	for _, ok := range []string{"did:web:payments.example", "domain-a", "a_b.c:d", "X1"} {
		if err := validateIdentifier(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	cases := []struct {
		in   string
		want error
	}{
		{"", errEmpty},
		{"did:web:pay ments", errIdentCharset},
		{"a/b", errIdentCharset},
		{"a@b", errIdentCharset},
		{"ünïcode", errIdentCharset},
		{"a..b", errIdentTraversal},
		{"..", errIdentTraversal},
	}
	for _, c := range cases {
		if err := validateIdentifier(c.in); !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.in, err, c.want)
		}
	}
	// What Sign enforces, this enforces: an identifier accepted here is one
	// Sign accepts, and one refused here Sign refuses too.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"version":1,"records":[]}`)
	if _, err := trustsnapshot.Sign(body, "id", fixedNow, []string{"did:web:payments.example"}, nil, priv); err != nil {
		t.Fatalf("Sign refused an identifier validateIdentifier accepts: %v", err)
	}
	if _, err := trustsnapshot.Sign(body, "id", fixedNow, []string{"a/b"}, nil, priv); err == nil {
		t.Fatal("Sign accepted an identifier validateIdentifier refuses; the two have drifted")
	}
}

// TestValidate_NamesTheFieldAndTheRule: the whole-config validator reports
// which field, by the flag that sets it, and which rule. Every case is a
// config valid in every respect except the one under test.
func TestValidate_NamesTheFieldAndTheRule(t *testing.T) {
	if err := validate(ptr(mcpConfig("./out"))); err != nil {
		t.Fatalf("valid mcp config rejected: %v", err)
	}
	if err := validate(ptr(a2aConfig("./out"))); err != nil {
		t.Fatalf("valid a2a config rejected: %v", err)
	}
	a2aNoPublic := a2aConfig("./out")
	a2aNoPublic.PublicURL = ""
	if err := validate(&a2aNoPublic); err != nil {
		t.Fatalf("a2a without a public URL is a supported posture (card relay off), got %v", err)
	}

	cases := []struct {
		name  string
		mut   func(*config)
		field string
		rule  error
	}{
		{"profile", func(c *config) { c.Profile = "envoy" }, "-profile", errBadProfile},
		{"audience empty", func(c *config) { c.Audience = "" }, "-audience", errEmpty},
		{"issuer charset", func(c *config) { c.Issuer = "did:web:a b" }, "-issuer", errIdentCharset},
		{"out empty", func(c *config) { c.OutDir = "" }, "-out", errEmpty},
		{"mcp server identity", func(c *config) { c.Profile = profileMCP; c.ServerIdentity = "" }, "-server-identity", errEmpty},
		{"mcp no command", func(c *config) { c.Profile = profileMCP; c.ServerCmd = nil }, "-- <wrapped-server-command>", errEmpty},
		{"mcp empty command word", func(c *config) { c.Profile = profileMCP; c.ServerCmd = []string{""} }, "-- <wrapped-server-command>", errEmpty},
	}
	for _, c := range cases {
		cfg := mcpConfig("./out")
		c.mut(&cfg)
		assertFieldError(t, c.name, validate(&cfg), c.field, c.rule)
	}

	a2aCases := []struct {
		name  string
		mut   func(*config)
		field string
		rule  error
	}{
		{"upstream empty", func(c *config) { c.Upstream = "" }, "-upstream", errEmpty},
		{"upstream scheme", func(c *config) { c.Upstream = "ftp://h/" }, "-upstream", errURLScheme},
		{"upstream host", func(c *config) { c.Upstream = "http://" }, "-upstream", errURLNoHost},
		{"public-url scheme", func(c *config) { c.PublicURL = "guarded.example" }, "-public-url", errURLScheme},
		{"agent identity", func(c *config) { c.AgentIdentity = "" }, "-agent-identity", errEmpty},
		{"listen", func(c *config) { c.Listen = "" }, "-listen", errEmpty},
	}
	for _, c := range a2aCases {
		cfg := a2aConfig("./out")
		c.mut(&cfg)
		assertFieldError(t, c.name, validate(&cfg), c.field, c.rule)
	}
}

func ptr(c config) *config { return &c }

func assertFieldError(t *testing.T, name string, err error, field string, rule error) {
	t.Helper()
	var fe *fieldError
	if !errors.As(err, &fe) {
		t.Errorf("%s: err = %v, want a fieldError for %s", name, err, field)
		return
	}
	if fe.Field != field {
		t.Errorf("%s: rejected field %q, want %q (err: %v)", name, fe.Field, field, err)
	}
	if !errors.Is(err, rule) {
		t.Errorf("%s: rule = %v, want %v", name, fe.Err, rule)
	}
}

// ── non-interactive resolution ─────────────────────────────────────────────

func TestResolveNonInteractive_NamesEveryMissingValue(t *testing.T) {
	// Complete configs resolve, and defaults are filled in.
	mcp := config{Profile: profileMCP, ServerIdentity: "s", ServerCmd: []string{"srv"}, Audience: "payments.example"}
	if err := resolveNonInteractive(&mcp); err != nil {
		t.Fatalf("complete mcp: %v", err)
	}
	if mcp.OutDir != "./spt-txn-mcp" || mcp.Issuer != "did:web:payments.example" || mcp.MaxTokenTTL != 60*time.Second {
		t.Fatalf("defaults not applied: %+v", mcp)
	}
	a2a := config{Profile: profileA2A, Upstream: "http://h/", AgentIdentity: "a", Audience: "payments.example"}
	if err := resolveNonInteractive(&a2a); err != nil {
		t.Fatalf("complete a2a (public-url is optional): %v", err)
	}
	if a2a.Listen != ":8402" || a2a.OutDir != "./spt-txn-a2a" {
		t.Fatalf("defaults not applied: %+v", a2a)
	}

	// No profile: named, and nothing else guessed.
	err := resolveNonInteractive(&config{})
	if !errors.Is(err, errNonInteractive) || !strings.Contains(err.Error(), "-profile") {
		t.Fatalf("no profile: err = %v", err)
	}
	// A bad profile is a validation error, not a "missing" one.
	if err := resolveNonInteractive(&config{Profile: "envoy"}); !errors.Is(err, errBadProfile) {
		t.Fatalf("bad profile: err = %v, want errBadProfile", err)
	}

	// Each required value, removed on its own from an otherwise complete
	// config, is named — and ONLY it is named. The list of what is required
	// lives HERE, not in a call to requiredFields: iterating the code's own
	// list would let an entry deleted from it vanish from this test too
	// (mutation I-9 survived exactly that way once).
	required := map[string]map[string]func(*config){
		profileMCP: {
			"-audience":                   func(c *config) { c.Audience = "" },
			"-server-identity":            func(c *config) { c.ServerIdentity = "" },
			"-- <wrapped-server-command>": func(c *config) { c.ServerCmd = nil },
		},
		profileA2A: {
			"-audience":       func(c *config) { c.Audience = "" },
			"-upstream":       func(c *config) { c.Upstream = "" },
			"-agent-identity": func(c *config) { c.AgentIdentity = "" },
		},
	}
	for profile, blankers := range required {
		got := requiredFields(profile)
		if len(got) != len(blankers) {
			t.Errorf("%s: requiredFields = %v, want exactly %d entries", profile, got, len(blankers))
		}
		for _, f := range got {
			if _, ok := blankers[f]; !ok {
				t.Errorf("%s: requiredFields names %q, which this test does not expect", profile, f)
			}
		}
		for missing, blank := range blankers {
			var cfg config
			if profile == profileMCP {
				cfg = config{Profile: profileMCP, ServerIdentity: "s", ServerCmd: []string{"srv"}, Audience: "a"}
			} else {
				cfg = config{Profile: profileA2A, Upstream: "http://h/", AgentIdentity: "a", Audience: "a"}
			}
			blank(&cfg)
			err := resolveNonInteractive(&cfg)
			if !errors.Is(err, errNonInteractive) {
				t.Errorf("%s without %s: err = %v, want errNonInteractive naming it", profile, missing, err)
				continue
			}
			named := strings.TrimPrefix(err.Error(), errNonInteractive.Error()+": ")
			if named != missing {
				t.Errorf("%s without %s: named %q", profile, missing, named)
			}
		}
	}

	// A value that is present but invalid is refused by its validator, not
	// reported as missing: non-interactive mode does not repair input.
	bad := config{Profile: profileA2A, Upstream: "ftp://h/", AgentIdentity: "a", Audience: "a"}
	assertFieldError(t, "bad upstream", resolveNonInteractive(&bad), "-upstream", errURLScheme)
	badIssuer := config{Profile: profileMCP, ServerIdentity: "s", ServerCmd: []string{"srv"}, Audience: "pay ments"}
	assertFieldError(t, "derived issuer outside charset", resolveNonInteractive(&badIssuer), "-issuer", errIdentCharset)
}

// ── interactive prompting ──────────────────────────────────────────────────

func TestPrompt_ReAsksOnInvalidInputAndAcceptsValid(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("ftp://x/\n\nhttp://ok/\n"))
	var out bytes.Buffer
	p := &prompter{in: in, out: &out}
	v, err := p.ask("Upstream", "", false, validateAbsoluteURL)
	if err != nil {
		t.Fatal(err)
	}
	if v != "http://ok/" {
		t.Fatalf("got %q", v)
	}
	// Both bad answers were reported by the rule that refused them, and the
	// question was asked three times.
	if !strings.Contains(out.String(), errURLScheme.Error()) {
		t.Errorf("scheme rejection not reported:\n%s", out.String())
	}
	if !strings.Contains(out.String(), errEmpty.Error()) {
		t.Errorf("empty rejection not reported:\n%s", out.String())
	}
	if n := strings.Count(out.String(), "Upstream"); n != 3 {
		t.Errorf("asked %d times, want 3:\n%s", n, out.String())
	}
}

func TestPrompt_DefaultAndOptional(t *testing.T) {
	// Empty line takes the default.
	p := &prompter{in: bufio.NewReader(strings.NewReader("\n")), out: &bytes.Buffer{}}
	v, err := p.ask("Issuer", "did:web:x", false, validateIdentifier)
	if err != nil || v != "did:web:x" {
		t.Fatalf("default: v=%q err=%v", v, err)
	}
	// A typed value overrides the default.
	p = &prompter{in: bufio.NewReader(strings.NewReader("did:web:y\n")), out: &bytes.Buffer{}}
	v, err = p.ask("Issuer", "did:web:x", false, validateIdentifier)
	if err != nil || v != "did:web:y" {
		t.Fatalf("override: v=%q err=%v", v, err)
	}
	// Empty line on an optional question is the empty answer, and it is NOT
	// run through the validator (which would refuse it).
	p = &prompter{in: bufio.NewReader(strings.NewReader("\n")), out: &bytes.Buffer{}}
	v, err = p.ask("Public URL", "", true, validateAbsoluteURL)
	if err != nil || v != "" {
		t.Fatalf("optional skip: v=%q err=%v", v, err)
	}
	// A typed value on an optional question IS validated.
	p = &prompter{in: bufio.NewReader(strings.NewReader("nope\nhttps://ok/\n")), out: &bytes.Buffer{}}
	v, err = p.ask("Public URL", "", true, validateAbsoluteURL)
	if err != nil || v != "https://ok/" {
		t.Fatalf("optional typed: v=%q err=%v", v, err)
	}
}

func TestPrompt_ClosedInputIsAnErrorNotAnAnswer(t *testing.T) {
	// EOF with nothing typed.
	p := &prompter{in: bufio.NewReader(strings.NewReader("")), out: &bytes.Buffer{}}
	_, err := p.ask("Audience", "", false, nonEmpty)
	if !errors.Is(err, errInputClosed) || !strings.Contains(err.Error(), "Audience") {
		t.Fatalf("EOF: err = %v, want errInputClosed naming Audience", err)
	}
	// EOF after an invalid last line: refused, then closed — not looped, not
	// accepted.
	p = &prompter{in: bufio.NewReader(strings.NewReader("ftp://x/")), out: &bytes.Buffer{}}
	_, err = p.ask("Upstream", "", false, validateAbsoluteURL)
	if !errors.Is(err, errInputClosed) {
		t.Fatalf("EOF after bad: err = %v, want errInputClosed", err)
	}
	// A final line without a trailing newline is still an answer.
	p = &prompter{in: bufio.NewReader(strings.NewReader("http://ok/")), out: &bytes.Buffer{}}
	v, err := p.ask("Upstream", "", false, validateAbsoluteURL)
	if err != nil || v != "http://ok/" {
		t.Fatalf("no trailing newline: v=%q err=%v", v, err)
	}
}

// TestResolveInteractive_FlagsAreNotReAsked: a value given as a flag is not
// prompted for; only the gaps are. The transcript proves which questions were
// asked.
func TestResolveInteractive_FlagsAreNotReAsked(t *testing.T) {
	cfg := config{Profile: profileMCP, Audience: "payments.example", OutDir: "./x", MaxTokenTTL: time.Second}
	in := bufio.NewReader(strings.NewReader("payments.example\n./srv --port 1\n\n"))
	var out bytes.Buffer
	if err := resolveInteractive(&cfg, in, &out); err != nil {
		t.Fatalf("resolve: %v\n%s", err, out.String())
	}
	if cfg.ServerIdentity != "payments.example" || len(cfg.ServerCmd) != 3 || cfg.Issuer != "did:web:payments.example" {
		t.Fatalf("resolved %+v", cfg)
	}
	for _, notAsked := range []string{"Profile", "Audience", "Output directory"} {
		if strings.Contains(out.String(), notAsked) {
			t.Errorf("%q was asked although a flag set it:\n%s", notAsked, out.String())
		}
	}
	for _, asked := range []string{"server identity", "server command", "Issuer identity"} {
		if !strings.Contains(out.String(), asked) {
			t.Errorf("%q was not asked:\n%s", asked, out.String())
		}
	}
	// A bad flag value is refused, not re-prompted: interactive mode never
	// silently repairs an explicit answer.
	bad := config{Profile: "envoy"}
	err := resolveInteractive(&bad, bufio.NewReader(strings.NewReader("mcp\n")), &bytes.Buffer{})
	assertFieldError(t, "bad -profile flag", err, "-profile", errBadProfile)
}

// ── shell rendering ────────────────────────────────────────────────────────

func TestShellQuote_RoundTripsThroughSh(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this machine")
	}
	// Words an unquoted rendering would mangle: expansion ($HOME, `id`),
	// word splitting (a b), a separator (a;b), the quote character itself,
	// and the empty word, which disappears entirely when unquoted.
	words := []string{"plain", "a b", "it's", `"dq"`, "$HOME", "`id`", "a;b", "", "-flag", "back\\slash", "*"}
	script := `for w in ` + shellQuoteAll(words) + `; do printf '%s\n' "$w"; done`
	out, err := exec.Command(sh, "-c", script).Output()
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(got) != len(words) {
		t.Fatalf("got %d words %q, want %d", len(got), got, len(words))
	}
	for i := range words {
		if got[i] != words[i] {
			t.Errorf("word %d: got %q, want %q", i, got[i], words[i])
		}
	}
}

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"srv", []string{"srv"}},
		{"  srv  --x   y ", []string{"srv", "--x", "y"}},
		{`srv "a b" 'c d'`, []string{"srv", "a b", "c d"}},
		{`srv it\'s`, []string{"srv", "it's"}},
		{`srv "say \"hi\""`, []string{"srv", `say "hi"`}},
		{`srv 'lit\eral'`, []string{"srv", `lit\eral`}},
		{`srv ""`, []string{"srv", ""}},
		{"", nil},
		{"   ", nil},
	}
	for _, c := range cases {
		got := splitCommand(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: word %d = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestRunScript_CarriesEveryRequiredFlag: run.sh is the exact command, so it
// must carry every flag the PEP refuses to start without, with the values
// this deployment generated, and nothing that would make the PEP answer for
// a different deployment.
func TestRunScript_CarriesEveryRequiredFlag(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(out))
	run := string(readFile(t, out, fileRunScript))

	for _, want := range []string{
		"exec 'mcp-pep'", // the fixed name, not an environment variable
		"-server-identity 'payments.example'",
		"-audience 'payments.example'",
		"PINNED='" + res.TTSPubHex + "'", // the pin is a literal in a 0700 script
		"-tts-pub \"$PINNED\"",
		"-log-key-file \"$HERE/" + fileLogKey + "\"", // absolute: run.sh must not cd
		"-policy-hash '" + res.PolicyHash + "'",
		"-max-token-ttl 1m0s",
		"-- './the-server' '--flag' 'a b' 'it'\\''s'",
		"cd \"$(dirname \"$0\")\"",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("run.sh lacks %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, "-jurisdiction") {
		t.Error("run.sh passes -jurisdiction although none was configured")
	}

	a2aOut := filepath.Join(t.TempDir(), "deploy")
	cfg := a2aConfig(a2aOut)
	cfg.Jurisdiction = "eu"
	res = generate(t, cfg)
	run = string(readFile(t, a2aOut, fileRunScript))
	for _, want := range []string{
		"exec 'a2a-pep'",
		"-listen ':8402'",
		"-upstream 'http://127.0.0.1:9000/'",
		"-public-url 'https://guarded.example/'",
		"-agent-identity 'a2a://payments.example'",
		"-audience 'payments.example'",
		"PINNED='" + res.TTSPubHex + "'", // the pin is a literal in a 0700 script
		"-tts-pub \"$PINNED\"",
		"-log-key-file \"$HERE/" + fileLogKey + "\"", // absolute: run.sh must not cd
		"-policy-hash '" + res.PolicyHash + "'",
		"-jurisdiction 'eu'",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("a2a run.sh lacks %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, " -- ") {
		t.Error("a2a run.sh carries a wrapped command; a2a-pep takes none")
	}
	// The pinned key in run.sh is the one in issuer.pub.
	if !strings.Contains(run, strings.TrimSpace(string(readFile(t, a2aOut, fileIssuerPub)))) {
		t.Error("run.sh's -tts-pub is not issuer.pub")
	}
}

// TestPolicyHash_IsTheBase64URLSHA256OfPolicyJSON: an auditor holding
// policy.json recomputes the hash in a receipt. That only works if the flag is
// exactly that function of exactly those bytes.
func TestPolicyHash_IsTheBase64URLSHA256OfPolicyJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(out))
	pol := readFile(t, out, filePolicy)

	if got := policyHashOf(pol); got != res.PolicyHash {
		t.Fatalf("recomputed %s from policy.json, run.sh carries %s", got, res.PolicyHash)
	}
	// It is base64url without padding, of 32 bytes: 43 characters from the
	// url alphabet, as RECEIPT-FORMAT.md specifies.
	if len(res.PolicyHash) != 43 || strings.ContainsAny(res.PolicyHash, "+/=") {
		t.Fatalf("policy hash %q is not unpadded base64url of a SHA-256", res.PolicyHash)
	}
	// Anti-vacuity: a different bundle has a different hash, and the bundle
	// carries the values that make this deployment this deployment.
	if policyHashOf(append(pol, '\n')) == res.PolicyHash {
		t.Fatal("hash does not depend on the bytes")
	}
	var p policy
	if err := json.Unmarshal(pol, &p); err != nil {
		t.Fatal(err)
	}
	if p.Audience != "payments.example" || p.Target != "payments.example" || p.TTSPublicKey != res.TTSPubHex || p.Issuer != "did:web:payments.example" || p.Profile != profileMCP {
		t.Fatalf("policy.json does not describe the deployment: %+v", p)
	}
}

// TestMintScript_OnlyForMCP: mcp-mint mints an MCP intent; the A2A profile
// gets no mint.sh and its README says why.
func TestMintScript_OnlyForMCP(t *testing.T) {
	mcpOut := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(mcpOut))
	mint := string(readFile(t, mcpOut, fileMintScript))
	for _, want := range []string{
		"\"$MCP_MINT\" -tool",
		"-target \"$TARGET\"",
		"TARGET='payments.example'",
		"AUDIENCE='payments.example'",
		"-tts-pub \"$TTS_PUB\"",
		"-policy-hash '" + res.PolicyHash + "'",
		"-audit-log \"$AUDIT\"",
		"-- './the-server' '--flag' 'a b' 'it'\\''s'",
		"has no way to sign with issuer.key",
	} {
		if !strings.Contains(mint, want) {
			t.Errorf("mint.sh lacks %q", want)
		}
	}
	// It must NOT pin the generated issuer key: with mcp-mint's throwaway
	// key every call would be refused and the smoke test would "prove" a
	// PEP that denies everything.
	if strings.Contains(mint, res.TTSPubHex) {
		t.Error("mint.sh pins issuer.pub, which mcp-mint cannot sign for")
	}
	found := false
	for _, f := range res.Files {
		if f.Name == fileMintScript {
			found = true
		}
	}
	if !found {
		t.Error("summary does not list mint.sh for mcp")
	}

	a2aOut := filepath.Join(t.TempDir(), "deploy")
	res = generate(t, a2aConfig(a2aOut))
	if _, err := os.Stat(filepath.Join(a2aOut, fileMintScript)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a2a deployment has a mint.sh (err=%v); mcp-mint does not mint A2A intents", err)
	}
	for _, f := range res.Files {
		if f.Name == fileMintScript {
			t.Error("summary lists mint.sh for a2a")
		}
	}
	readme := string(readFile(t, a2aOut, fileREADME))
	if !strings.Contains(readme, "There is no `mint.sh` for this profile") {
		t.Error("a2a README does not explain the missing mint.sh")
	}
}

// TestREADME_LabelsThePostureHonestly: the README says being your own issuer
// is legitimate, and names what it does not include. Both halves, by
// substring, so neither can be dropped without this noticing.
func TestREADME_LabelsThePostureHonestly(t *testing.T) {
	for _, cfg := range []config{mcpConfig(""), a2aConfig("")} {
		out := filepath.Join(t.TempDir(), "deploy")
		cfg.OutDir = out
		generate(t, cfg)
		readme := string(readFile(t, out, fileREADME))
		for _, want := range []string{
			"You are your own issuer",
			"complete and legitimate\nposture for a single operator",
			"**The PEP does not read it.**",
			"2. **The PEP does not read the snapshot.**",
			"## What this deployment does not have",
			"No revocation distribution",
			"No multi-issuer trust",
			"No key-rotation service",
			"## Changing the configuration",
			"## Never do this",
			"snapshot verify -body " + fileRegistry + " -pub \"$(cat " + filePublicationPub + ")\"",
			"snapshot sign -registry " + fileRegistry + " -key " + filePublicationKey,
		} {
			if !strings.Contains(readme, want) {
				t.Errorf("%s README lacks %q", cfg.Profile, want)
			}
		}
		// The two snapshot commands must not need the module root as the
		// working directory: nothing else in the README does.
		if strings.Contains(readme, "go run ./cmd/snapshot") {
			t.Errorf("%s README runs cmd/snapshot with go run, which only works from the module root", cfg.Profile)
		}
		for _, never := range []string{"dev only", "development only", "not for production", "toy"} {
			if strings.Contains(strings.ToLower(readme), never) {
				t.Errorf("%s README undersells the posture with %q", cfg.Profile, never)
			}
		}
	}
}

// TestResolveInteractive_NoInvalidIssuerDefault: an audience outside the
// identifier charset must not be proposed as did:web:<audience>; the operator
// is asked without a default and the value they type is validated.
func TestResolveInteractive_NoInvalidIssuerDefault(t *testing.T) {
	cfg := config{Profile: profileMCP, ServerIdentity: "s", ServerCmd: []string{"srv"}, Audience: "pay/ments", OutDir: "./x"}
	var out bytes.Buffer
	err := resolveInteractive(&cfg, bufio.NewReader(strings.NewReader("did:web:payments.example\n")), &out)
	if err != nil {
		t.Fatalf("resolve: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "[did:web:pay/ments]") {
		t.Errorf("an invalid issuer was offered as the default:\n%s", out.String())
	}
	if cfg.Issuer != "did:web:payments.example" {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
	// And a valid audience IS offered as the default, and Enter takes it.
	cfg = config{Profile: profileMCP, ServerIdentity: "s", ServerCmd: []string{"srv"}, Audience: "payments.example", OutDir: "./x"}
	out.Reset()
	if err := resolveInteractive(&cfg, bufio.NewReader(strings.NewReader("\n")), &out); err != nil {
		t.Fatalf("resolve: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[did:web:payments.example]") || cfg.Issuer != "did:web:payments.example" {
		t.Fatalf("valid default not offered/taken: issuer=%q\n%s", cfg.Issuer, out.String())
	}
}

// TestSummary_MarksExactlyThePrivateFiles: the PRIVATE marker in the summary
// is on every key file and on nothing else, so an operator reading the
// summary knows which three files never leave the machine.
func TestSummary_MarksExactlyThePrivateFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	res := generate(t, mcpConfig(out))
	marked := map[string]bool{}
	for _, f := range res.Files {
		if f.Private {
			marked[f.Name] = true
		}
	}
	private := expectedPrivateFiles(t)
	for _, name := range private {
		if !marked[name] {
			t.Errorf("%s is not marked PRIVATE in the summary", name)
		}
		delete(marked, name)
	}
	for name := range marked {
		t.Errorf("%s is marked PRIVATE but holds no private key", name)
	}
	var buf bytes.Buffer
	res.printSummary(&buf)
	// One PRIVATE line per private file IN the deployment, plus one for the
	// issuer key beside it — which is private, is not in Files, and the
	// operator has to be told about because they must move it.
	wantMarks := len(private)
	if res.IssuerKeyPath != "" {
		wantMarks++
		if !strings.Contains(buf.String(), "PRIVATE "+filepath.Base(res.IssuerKeyPath)) {
			t.Errorf("summary does not mark the issuer key PRIVATE:\n%s", buf.String())
		}
	}
	if n := strings.Count(buf.String(), "PRIVATE "); n != wantMarks {
		t.Errorf("summary prints PRIVATE %d times, want %d", n, wantMarks)
	}
	for _, name := range private {
		if !strings.Contains(buf.String(), "PRIVATE "+name) {
			t.Errorf("summary does not mark %s PRIVATE:\n%s", name, buf.String())
		}
	}
}

// ── the directory holds exactly what the README documents ─────────────────

// TestGenerate_DirectoryContainsExactlyTheDocumentedFiles: every file in the
// output directory is in the README's table and the summary, and vice versa.
// A scratch artifact that shipped, or a documented file that did not, fails.
func TestGenerate_DirectoryContainsExactlyTheDocumentedFiles(t *testing.T) {
	want := map[string][]string{
		profileMCP: {"README.md", "issuer.pub", "log.key", "mint.sh", "policy.json",
			"registry.json", "registry.json.manifest.json", "run.sh", "snapshot-publication.key", "snapshot-publication.pub"},
		profileA2A: {"README.md", "issuer.pub", "log.key", "policy.json",
			"registry.json", "registry.json.manifest.json", "run.sh", "snapshot-publication.key", "snapshot-publication.pub"},
	}
	for _, cfg := range []config{mcpConfig(""), a2aConfig("")} {
		out := filepath.Join(t.TempDir(), "deploy")
		cfg.OutDir = out
		res := generate(t, cfg)
		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if strings.Join(got, ",") != strings.Join(want[cfg.Profile], ",") {
			t.Errorf("%s: directory holds %v, want %v", cfg.Profile, got, want[cfg.Profile])
		}
		readme := string(readFile(t, out, fileREADME))
		var listed []string
		for _, f := range res.Files {
			listed = append(listed, f.Name)
		}
		for _, name := range want[cfg.Profile] {
			if !strings.Contains(readme, "| `"+name+"` |") {
				t.Errorf("%s: README table lacks a row for %s", cfg.Profile, name)
			}
			if !containsAny(strings.Join(listed, "\n"), []string{name}) {
				t.Errorf("%s: summary does not list %s", cfg.Profile, name)
			}
		}
		if len(listed) != len(want[cfg.Profile]) {
			t.Errorf("%s: summary lists %d files, directory holds %d", cfg.Profile, len(listed), len(want[cfg.Profile]))
		}
	}
}

// TestWrite_RefusesToOverwrite: the writer creates, it never truncates. The
// first write succeeds with its content; a second write of the same name is
// refused by the file-exists rule and the first content survives.
func TestWrite_RefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	g := &generator{}
	if err := g.write(dir, "f", []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "first" {
		t.Fatalf("first write: %q", b)
	}
	err := g.write(dir, "f", []byte("second"), 0o644)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write: err = %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "first" {
		t.Fatalf("second write changed the file: %q", b)
	}
}

// TestGenerate_RefusesASymlinkOutputPath: a symlink to an empty directory is
// not silently replaced by a real directory. It is refused by its own rule,
// the link and its target are untouched, and the same path as a real empty
// directory is accepted.
func TestGenerate_RefusesASymlinkOutputPath(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	g := &generator{cfg: mcpConfig(link), now: fixedNow, rand: rand.Reader}
	if _, err := g.run(); !errors.Is(err, errOutDirSymlink) {
		t.Fatalf("symlink out dir: err = %v, want errOutDirSymlink", err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced (err=%v)", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("the link's target was written into: %d entries", len(entries))
	}
	if left, _ := filepath.Glob(filepath.Join(parent, ".spt-txn-init-*")); len(left) != 0 {
		t.Fatalf("temporary directory left behind: %v", left)
	}
	// The same target, named directly, is an empty directory and is accepted.
	generate(t, mcpConfig(target))
}

// ── Markdown rendering of operator values ─────────────────────────────────

func TestMarkdownHelpers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "`plain`"},
		{"", "` `"},
		{"a`b", "``a`b``"},
		{"`lead", "`` `lead ``"},
		{"trail`", "`` trail` ``"},
		{"x```y", "````x```y````"},
		{"two\nlines", "`two lines`"},
	}
	for _, c := range cases {
		if got := mdCode(c.in); got != c.want {
			t.Errorf("mdCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := mdCell("a|b"); got != "`a\\|b`" {
		t.Errorf("mdCell = %q", got)
	}
	if got := mdFence("no backticks"); got != "```" {
		t.Errorf("mdFence plain = %q", got)
	}
	if got := mdFence("has ``` inside"); got != "````" {
		t.Errorf("mdFence with ``` = %q", got)
	}
	if got := mdFence("has ````` five"); got != "``````" {
		t.Errorf("mdFence with five = %q", got)
	}
}

// TestREADME_EscapesOperatorValues: an identity carrying a backtick, a pipe
// and a fence must not break the README's code spans, table or shell block.
func TestREADME_EscapesOperatorValues(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	cfg := mcpConfig(out)
	cfg.ServerIdentity = "pay`ments|example```"
	cfg.ServerCmd = []string{"./srv", "--name", "a|b`c"}
	generate(t, cfg)
	readme := string(readFile(t, out, fileREADME))

	// Table: every row in the Files table has exactly four unescaped pipes
	// (three cells), including the registry row that carries the issuer and
	// the run.sh row.
	inTable := false
	rows := 0
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "| File |") {
			inTable = true
		}
		if inTable {
			if !strings.HasPrefix(line, "|") {
				break
			}
			rows++
			unescaped := strings.Count(line, "|") - strings.Count(line, `\|`)
			if unescaped != 4 {
				t.Errorf("table row has %d unescaped pipes, want 4: %s", unescaped, line)
			}
		}
	}
	if rows < 10 {
		t.Fatalf("Files table has %d rows; did the scan find it?", rows)
	}
	// Code spans: the identity is rendered with a delimiter longer than its
	// own longest run, so the span closes where intended.
	// (The identity reaches prose and the shell block only; the one operator
	// value in a table cell is the issuer, whose charset admits neither a
	// backtick nor a pipe. mdCell's escaping is unit-tested above.)
	if want := "```` pay`ments|example``` ````"; !strings.Contains(readme, want) {
		t.Errorf("identity not rendered in prose as %q", want)
	}
	// Fenced block: the shell block opens and closes with a fence longer than
	// any backtick run inside it, and the quoted identity is inside it.
	idx := strings.Index(readme, "which runs, exactly:")
	if idx < 0 {
		t.Fatal("no shell block")
	}
	rest := readme[idx:]
	fenceStart := strings.Index(rest, "\n`")
	fence := rest[fenceStart+1:]
	fence = fence[:strings.IndexByte(fence, 's')] // up to the "sh" info string
	if len(fence) < 4 {
		t.Fatalf("shell block fence %q is not longer than the ``` inside the identity", fence)
	}
	body := rest[fenceStart+1+len(fence)+3:] // past fence + "sh\n"
	closing := strings.Index(body, "\n"+fence+"\n")
	if closing < 0 {
		t.Fatalf("shell block does not close with %q", fence)
	}
	if !strings.Contains(body[:closing], shellQuote(cfg.ServerIdentity)) {
		t.Errorf("shell block does not carry the quoted identity")
	}
	if longestRun(body[:closing], '`') >= len(fence) {
		t.Errorf("shell block contains a backtick run as long as its fence")
	}
	// Anti-vacuity: a plain identity renders with single backticks and a
	// three-backtick fence.
	plainOut := filepath.Join(t.TempDir(), "deploy")
	generate(t, mcpConfig(plainOut))
	plain := string(readFile(t, plainOut, fileREADME))
	if !strings.Contains(plain, "`payments.example`") || !strings.Contains(plain, "```sh\nmcp-pep \\\n") {
		t.Error("plain identity is not rendered with the minimal delimiters")
	}
}

// ── build commands, and advice that has a working form ────────────────────

// TestREADME_BuildCommandsProduceStaticBinaries: every build line the README
// and the scripts print carries CGO_ENABLED=0. Without it a2a-pep links
// glibc for the cgo resolver and is not the static binary the README calls it.
func TestREADME_BuildCommandsProduceStaticBinaries(t *testing.T) {
	for _, cfg := range []config{mcpConfig(""), a2aConfig("")} {
		out := filepath.Join(t.TempDir(), "deploy")
		cfg.OutDir = out
		generate(t, cfg)
		files := []string{fileREADME, fileRunScript}
		if cfg.Profile == profileMCP {
			files = append(files, fileMintScript)
		}
		builds := 0
		for _, name := range files {
			for _, line := range strings.Split(string(readFile(t, out, name)), "\n") {
				if !strings.Contains(line, "go build") {
					continue
				}
				builds++
				if !strings.Contains(line, "CGO_ENABLED=0 go build -o /usr/local/bin/") {
					t.Errorf("%s %s: build line without CGO_ENABLED=0: %s", cfg.Profile, name, line)
				}
			}
		}
		// mcp: README (pep, mint, snapshot) + run.sh (pep) + mint.sh (pep, mint) = 6
		// a2a: README (pep, snapshot) + run.sh (pep) = 3
		want := map[string]int{profileMCP: 6, profileA2A: 3}[cfg.Profile]
		if builds != want {
			t.Errorf("%s: found %d build lines, want %d", cfg.Profile, builds, want)
		}
	}
}

// TestRunScript_AdvisesAWorkingPath: the advice against editing run.sh names
// something the installer will actually do (a new directory), and states the
// consequence (new key, new hash, old tokens do not verify).
func TestRunScript_AdvisesAWorkingPath(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	generate(t, mcpConfig(out))
	run := string(readFile(t, out, fileRunScript))
	for _, want := range []string{"into a NEW directory", "refuses to overwrite this one", "new issuer keypair and a new policy hash", "do not verify at the new one"} {
		if !strings.Contains(run, want) {
			t.Errorf("run.sh lacks %q", want)
		}
	}
	if strings.Contains(run, "re-run spt-txn-init rather than editing") {
		t.Error("run.sh still gives the advice the installer refuses to honour")
	}
	readme := string(readFile(t, out, fileREADME))
	for _, want := range []string{"## Changing the configuration", "into a **new** directory", "tokens minted for this deployment do not verify at the new\none", "`.spt-txn-init-*`"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	// The interrupt claim in the README matches what the code does: Ctrl-C
	// and errors clean up, a hard kill cannot.
	if !strings.Contains(readme, "Ctrl-C and errors clean\nup after themselves; a hard kill cannot.") {
		t.Error("README does not state the interrupt guarantee precisely")
	}
}

// TestMintScript_StatesWhatItCannotShow: the smoke test's own header says it
// checks self-consistency, not the values, and that -policy-hash is copied,
// not validated.
func TestMintScript_StatesWhatItCannotShow(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	generate(t, mcpConfig(out))
	mint := string(readFile(t, out, fileMintScript))
	for _, want := range []string{
		"the PEP copies it in; it\n#   does not check it against policy.json",
		"sets both sides from the same values",
		"self-consistency check",
	} {
		if !strings.Contains(mint, want) {
			t.Errorf("mint.sh lacks %q", want)
		}
	}
	if strings.Contains(mint, "policy.json's hash, the server") {
		t.Error("mint.sh still claims to prove policy.json's hash")
	}
}
