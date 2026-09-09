// Command spt-txn-init takes an operator from a checkout to an enforcing
// SPT-Txn deployment without reverse-engineering flag semantics or hand-building
// a signed trust snapshot.
//
// docs/spec/GATEWAY-PROFILES.md §5 sets the bar: deployable in an afternoon,
// one binary per skin, one config. cmd/mcp-pep and cmd/a2a-pep meet the binary
// half; the config half was fifteen and nine flags, six of them required on
// each (a2a-pep's six flags; mcp-pep's five plus the wrapped command), and
// nothing in the tree that produced the key material they expect.
// This closes that gap. It asks the few facts only the operator has — which
// profile, what is being guarded, what identity and audience it answers for —
// and generates everything else into one directory:
//
//   - an Ed25519 issuer (tts) keypair; the PEP pins the public half
//   - an Ed25519 receipt-log signing key
//   - a signed single-issuer trust snapshot, produced by pkg/trustsnapshot.Sign
//     and checked with pkg/trustsnapshot.Verify before the directory is handed
//     over
//   - the policy bundle and its hash, which every receipt binds to
//   - run.sh: the exact, complete command that starts the PEP
//   - mint.sh (MCP only): a smoke test built on cmd/mcp-mint
//   - README.md: what each file is, what to run next, and what this
//     deployment does NOT have
//
// # This is a security surface
//
// The installer handles private key material, so it is held to the rules the
// PEPs are:
//
//   - No private key is ever written to stdout or any log. Public keys and
//     paths only.
//   - It refuses to overwrite. A non-empty output directory is an error, and
//     there is no flag that changes that.
//   - The directory is 0700 and every private key file is 0600.
//   - It makes no network call of any kind.
//   - It fails closed: everything is written to a temporary directory and
//     renamed into place only after the snapshot has been re-verified. An
//     error part-way removes that directory, and so does SIGINT, SIGTERM or
//     SIGHUP (the handler removes it, then re-raises the signal). What this
//     cannot cover is SIGKILL or a power loss mid-run, which can leave a
//     dot-named `.spt-txn-init-*` directory beside the output path; the
//     README says to look for and delete one.
//
// Interactive by default; every prompt can be pre-answered with a flag, and
// -non-interactive turns any unanswered required prompt into a named error so
// the same binary runs in CI:
//
//	spt-txn-init
//	spt-txn-init -profile mcp -server-identity payments.example \
//	             -audience payments.example -out ./spt-txn-mcp \
//	             -non-interactive -- the-real-mcp-server --its --flags
//	spt-txn-init -profile a2a -upstream http://127.0.0.1:9000/ \
//	             -public-url https://guarded.example/ \
//	             -agent-identity a2a://payments.example \
//	             -audience payments.example -non-interactive
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

// Profiles this installer knows how to deploy. Exactly the two published
// enforcement points in this tree, and nothing else.
const (
	profileMCP = "mcp"
	profileA2A = "a2a"
)

// File names inside the generated directory. They are constants because
// run.sh, mint.sh, the README and the tests all have to agree on them.
const (
	fileIssuerKey      = "issuer.key"
	fileIssuerPub      = "issuer.pub"
	fileLogKey         = "log.key"
	filePublicationKey = "snapshot-publication.key"
	filePublicationPub = "snapshot-publication.pub"
	fileRegistry       = "registry.json"
	filePolicy         = "policy.json"
	fileRunScript      = "run.sh"
	fileMintScript     = "mint.sh"
	fileREADME         = "README.md"
)

// fileManifest is the snapshot manifest, at the path every reader in this tree
// looks for it (trustregistry.ManifestPathFor).
var fileManifest = trustregistry.ManifestPathFor(fileRegistry)

// privateFiles are the files inside the DEPLOYMENT that hold private key
// material. They are written 0600, they are the only files in that directory
// which may contain it, and the tests assert both.
//
// issuer.key is deliberately not here. Nothing in a deployment reads it — both
// PEPs take -tts-pub, the public half — and the deployment directory is what
// gets copied into an image, mounted, archived or committed. It is placed
// beside the directory instead, at issuerKeyPath(). Neither key that remains
// can mint: one signs receipts, the other signs the trust snapshot.
var privateFiles = []string{fileLogKey, filePublicationKey}

// issuerKeyPath is where the self-issued issuer private key is placed: beside
// the deployment, never inside it. It is a sibling rather than a child so that
// copying the deployment cannot pick it up by accident.
//
// This bounds ACCIDENT, not an attacker. A process running as the operator can
// read any file the operator can read, wherever it sits. -tts-pub is the mode
// in which no such key is written at all.
func issuerKeyPath(outDir string) string { return outDir + "-issuer.key" }

// isPrivate reports whether name is one of privateFiles. The summary's
// PRIVATE marker and the 0600 mode both derive from this list, so a key file
// added later is either in it, or is visibly unmarked.
func isPrivate(name string) bool {
	for _, p := range privateFiles {
		if p == name {
			return true
		}
	}
	return false
}

// snapshotMaxAge is the staleness bound the generated snapshot is self-checked
// against. It matches the default every verifier in this tree applies
// (cmd/snapshot verify, cmd/agentsvc), so "it verified at generation time"
// means "it would load today".
const snapshotMaxAge = 24 * time.Hour

// issuerKeyValidity is how long the trust snapshot says the generated issuer
// key is valid for. One year is a default, not a recommendation: the README
// tells the operator it is there and how to re-sign.
const issuerKeyValidity = 365 * 24 * time.Hour

// The ways an input can be refused. Distinct sentinels because the tests
// assert WHICH rule rejected a value, not merely that something did.
var (
	errBadProfile        = errors.New("profile must be mcp or a2a")
	errEmpty             = errors.New("must not be empty")
	errURLUnparsable     = errors.New("is not a parsable URL")
	errURLScheme         = errors.New("must be an absolute http or https URL")
	errURLNoHost         = errors.New("has no host")
	errIdentCharset      = errors.New("may contain only alphanumerics, hyphen, underscore, dot and colon")
	errIdentTraversal    = errors.New("contains a traversal sequence")
	errOutDirNotEmpty    = errors.New("output directory exists and is not empty; refusing to overwrite")
	errOutDirNotADir     = errors.New("output path exists and is not a directory")
	errOutDirSymlink     = errors.New("output path is a symlink; give the path it points to")
	errNonInteractive    = errors.New("non-interactive mode and a required value is not set")
	errInputClosed       = errors.New("input closed before a valid answer was given")
	errSnapshotSelfCheck = errors.New("generated snapshot does not verify; nothing was written")
	errControlChar       = errors.New("must not contain a control character")
	errListenAddr        = errors.New("must be a host:port listen address, e.g. :8402 or 127.0.0.1:8402")
	errTTLTooLong        = errors.New("is longer than the decision engine will accept")
	errOutDirChanged     = errors.New("output path changed while the deployment was being generated; nothing was written")
	errPEPBinaryRelative = errors.New("must be an absolute path")
	errTTSPubHex         = errors.New("must be 64 lowercase hex characters: a 32-byte Ed25519 public key")
	errIssuerKeyExists   = errors.New("issuer key path already exists; refusing to overwrite it")
)

// fieldError names the input a validation error is about.
type fieldError struct {
	Field string
	Err   error
}

func (e *fieldError) Error() string { return e.Field + " " + e.Err.Error() }
func (e *fieldError) Unwrap() error { return e.Err }

// config is the resolved answer set: everything generation needs, whether it
// came from a flag or a prompt.
type config struct {
	Profile      string
	OutDir       string
	Audience     string
	Issuer       string
	Jurisdiction string
	MaxTokenTTL  time.Duration
	// TTSPubHex, when set, is the issuer's Ed25519 PUBLIC key in hex and no
	// issuer private key is generated at all: the operator already has a TTS,
	// or holds the key in a PKCS#11 token (see internal/hsm). This is the only
	// mode in which no signing key for this deployment is ever written to
	// disk. Empty means self-issue, and issuer.key is generated.
	TTSPubHex string
	// PEPBinary, when set, is the absolute path run.sh execs. Empty means the
	// name is resolved from PATH at start time and the deployment is not
	// pinned to a particular binary; the README states which is in force.
	PEPBinary string

	// MCP
	ServerIdentity string
	ServerCmd      []string

	// A2A
	Upstream      string
	PublicURL     string
	AgentIdentity string
	Listen        string
}

func main() {
	var cfg config
	var nonInteractive bool
	var serverCmdLine string

	flag.StringVar(&cfg.Profile, "profile", "", "which enforcement point to deploy: mcp or a2a")
	flag.StringVar(&cfg.OutDir, "out", "", "output directory (default ./spt-txn-<profile>); must not exist or must be empty")
	flag.BoolVar(&nonInteractive, "non-interactive", false,
		"never prompt; a required value that is not set by a flag is an error naming it")
	flag.StringVar(&cfg.Audience, "audience", "",
		"executing-domain identity the PEP answers for, matched against the token's aud")
	flag.StringVar(&cfg.Issuer, "issuer", "",
		"issuer identity recorded in the trust snapshot, the `iss` your tokens will carry "+
			"(default did:web:<audience>)")
	flag.StringVar(&cfg.Jurisdiction, "jurisdiction", "", "jurisdiction profile identifier (optional)")
	flag.StringVar(&cfg.TTSPubHex, "tts-pub", "",
		"issuer Ed25519 public key, 64 hex characters. Given this, NO issuer private key is "+
			"generated or written: your existing TTS or PKCS#11 token holds it. Omit to self-issue")
	flag.StringVar(&cfg.PEPBinary, "pep-binary", "",
		"absolute path to the enforcement point binary; run.sh execs exactly this and does "+
			"no PATH lookup (optional, but a deployment that pins its keys should pin its binary)")
	flag.DurationVar(&cfg.MaxTokenTTL, "max-token-ttl", 60*time.Second,
		"longest remaining token lifetime the PEP accepts (this is its revocation latency)")
	flag.StringVar(&cfg.ServerIdentity, "server-identity", "",
		"mcp: identity of the wrapped MCP server, the intent target")
	flag.StringVar(&serverCmdLine, "server-cmd", "",
		"mcp: the wrapped server command as one shell-like string; the arguments after -- take precedence")
	flag.StringVar(&cfg.Upstream, "upstream", "", "a2a: JSON-RPC endpoint of the wrapped agent, e.g. http://127.0.0.1:9000/")
	flag.StringVar(&cfg.PublicURL, "public-url", "",
		"a2a: the URL clients reach the PEP on; optional, but without it the agent card is not relayed")
	flag.StringVar(&cfg.AgentIdentity, "agent-identity", "", "a2a: identity of the wrapped agent, the intent target")
	flag.StringVar(&cfg.Listen, "listen", ":8402", "a2a: address the PEP listens on")
	flag.Parse()

	if args := flag.Args(); len(args) > 0 {
		cfg.ServerCmd = args
	} else if serverCmdLine != "" {
		cfg.ServerCmd = splitCommand(serverCmdLine)
	}

	var err error
	if nonInteractive {
		err = resolveNonInteractive(&cfg)
	} else {
		fmt.Fprintln(os.Stdout, "spt-txn-init — set up an SPT-Txn enforcement point")
		fmt.Fprintln(os.Stdout, "Answers given as flags are not asked again. Nothing here leaves this machine.")
		fmt.Fprintln(os.Stdout)
		err = resolveInteractive(&cfg, bufio.NewReader(os.Stdin), os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "spt-txn-init: %v\n", err)
		os.Exit(2)
	}

	g := &generator{cfg: cfg, now: time.Now(), rand: rand.Reader}
	res, err := g.run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "spt-txn-init: %v\n", err)
		os.Exit(1)
	}
	res.printSummary(os.Stdout)
}

// ── input resolution ───────────────────────────────────────────────────────

// requiredFields lists, per profile, the values that have no safe default and
// the flag that sets each. Order is the order an operator would fix them.
func requiredFields(profile string) []string {
	common := []string{"-audience"}
	switch profile {
	case profileMCP:
		return append([]string{"-server-identity", "-- <wrapped-server-command>"}, common...)
	case profileA2A:
		return append([]string{"-upstream", "-agent-identity"}, common...)
	}
	return nil
}

// missingRequired names the required values cfg does not carry. Like the PEPs
// it returns the list rather than a bool so the operator is told which.
func missingRequired(cfg *config) []string {
	var missing []string
	for _, f := range requiredFields(cfg.Profile) {
		if fieldValue(cfg, f) == "" {
			missing = append(missing, f)
		}
	}
	return missing
}

// fieldValue maps a flag name to the config field it fills. The wrapped
// command is reported as non-empty when it has at least one word.
func fieldValue(cfg *config, flagName string) string {
	switch flagName {
	case "-audience":
		return cfg.Audience
	case "-server-identity":
		return cfg.ServerIdentity
	case "-- <wrapped-server-command>":
		if len(cfg.ServerCmd) == 0 {
			return ""
		}
		return cfg.ServerCmd[0]
	case "-upstream":
		return cfg.Upstream
	case "-agent-identity":
		return cfg.AgentIdentity
	}
	return ""
}

// resolveNonInteractive fills defaults and validates a flag-only config. A
// missing required value is an error that names the flag; nothing is guessed.
func resolveNonInteractive(cfg *config) error {
	if cfg.Profile == "" {
		return fmt.Errorf("%w: -profile", errNonInteractive)
	}
	if err := validateProfile(cfg.Profile); err != nil {
		return &fieldError{"-profile", err}
	}
	if missing := missingRequired(cfg); len(missing) > 0 {
		return fmt.Errorf("%w: %s", errNonInteractive, strings.Join(missing, ", "))
	}
	applyDefaults(cfg)
	return validate(cfg)
}

// resolveInteractive asks for whatever the flags did not answer, re-asking on
// invalid input, then validates the whole. A flag-supplied value is never
// re-prompted, but it is still validated: a bad flag is refused, not repaired.
func resolveInteractive(cfg *config, in *bufio.Reader, out io.Writer) error {
	p := &prompter{in: in, out: out}

	if cfg.Profile == "" {
		v, err := p.ask("Profile — which enforcement point are you deploying? [mcp/a2a]", "", false, validateProfile)
		if err != nil {
			return err
		}
		cfg.Profile = v
	} else if err := validateProfile(cfg.Profile); err != nil {
		return &fieldError{"-profile", err}
	}

	var err error
	switch cfg.Profile {
	case profileMCP:
		if cfg.ServerIdentity == "" {
			cfg.ServerIdentity, err = p.ask("Wrapped MCP server identity (the intent target, e.g. payments.example)", "", false, nonEmpty)
			if err != nil {
				return err
			}
		}
		if len(cfg.ServerCmd) == 0 {
			line, err := p.ask("Wrapped MCP server command, as you would type it in a shell", "", false, func(s string) error {
				if len(splitCommand(s)) == 0 {
					return errEmpty
				}
				return nil
			})
			if err != nil {
				return err
			}
			cfg.ServerCmd = splitCommand(line)
		}
	case profileA2A:
		if cfg.Upstream == "" {
			cfg.Upstream, err = p.ask("Upstream — JSON-RPC endpoint of the wrapped A2A agent (e.g. http://127.0.0.1:9000/)", "", false, validateAbsoluteURL)
			if err != nil {
				return err
			}
		}
		if cfg.PublicURL == "" {
			cfg.PublicURL, err = p.ask("Public URL clients reach the PEP on (optional; without it the agent card is not relayed)", "", true, validateAbsoluteURL)
			if err != nil {
				return err
			}
		}
		if cfg.AgentIdentity == "" {
			cfg.AgentIdentity, err = p.ask("Wrapped agent identity (the intent target, e.g. a2a://payments.example)", "", false, nonEmpty)
			if err != nil {
				return err
			}
		}
	}

	if cfg.Audience == "" {
		cfg.Audience, err = p.ask("Audience — the executing domain tokens are minted FOR (e.g. payments.example)", "", false, nonEmpty)
		if err != nil {
			return err
		}
	}
	if cfg.Issuer == "" {
		// Propose did:web:<audience> only when it is itself a valid
		// identifier; a default the validator would refuse is not a default.
		def := defaultIssuer(cfg.Audience)
		if validateIdentifier(def) != nil {
			def = ""
		}
		cfg.Issuer, err = p.ask("Issuer identity — the `iss` your tokens will carry", def, false, validateIdentifier)
		if err != nil {
			return err
		}
	}
	if cfg.OutDir == "" {
		cfg.OutDir, err = p.ask("Output directory", defaultOutDir(cfg.Profile), false, nonEmpty)
		if err != nil {
			return err
		}
	}
	applyDefaults(cfg)
	return validate(cfg)
}

// applyDefaults fills the values that have a sensible default derived from
// the answers given. It never touches a value that is set.
func applyDefaults(cfg *config) {
	if cfg.OutDir == "" {
		cfg.OutDir = defaultOutDir(cfg.Profile)
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultIssuer(cfg.Audience)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8402"
	}
	if cfg.MaxTokenTTL <= 0 {
		cfg.MaxTokenTTL = 60 * time.Second
	}
}

func defaultOutDir(profile string) string { return "./spt-txn-" + profile }

// defaultIssuer proposes did:web:<audience>. A single operator being their own
// issuer is the ordinary posture for this installer, and the audience is the
// domain they answer for. It is a proposal: validate() still checks it, so an
// audience outside the identifier charset produces a named error rather than
// a broken snapshot.
func defaultIssuer(audience string) string { return "did:web:" + audience }

// validate checks a complete config. Every rejection names the field and the
// rule, so a flag-driven run reports exactly what to fix.
// maxAcceptableTokenTTL is the ceiling the decision engine imposes on us: it
// refuses to build when its replay window — 10 minutes by default, and neither
// PEP sets it — is shorter than MaxTokenTTL. Bounding here means a deployment
// that cannot start is refused BEFORE any key is generated, instead of being
// reported as a success and failing at startup.
// TestMaxTokenTTLCeilingMatchesTheEngine holds this constant and the engine in
// step, so a change to one fails the build rather than drifting silently.
const maxAcceptableTokenTTL = 10 * time.Minute

func validate(cfg *config) error {
	if err := validateProfile(cfg.Profile); err != nil {
		return &fieldError{"-profile", err}
	}
	// Deliberately NOT the snapshot identifier charset: an audience is a
	// protocol identity whose shape MCP and A2A set, not this tool. The
	// derived did:web: issuer default IS charset-checked, and withheld when
	// it would not validate — see defaultIssuer and resolve.
	if err := nonEmpty(cfg.Audience); err != nil {
		return &fieldError{"-audience", err}
	}
	if err := validateIdentifier(cfg.Issuer); err != nil {
		return &fieldError{"-issuer", err}
	}
	if err := nonEmpty(cfg.OutDir); err != nil {
		return &fieldError{"-out", err}
	}
	// Optional, but it reaches policy.json and run.sh, so it is validated on
	// the same terms as every other identity when it is set at all.
	if cfg.Jurisdiction != "" {
		if err := nonEmpty(cfg.Jurisdiction); err != nil {
			return &fieldError{"-jurisdiction", err}
		}
	}
	if cfg.TTSPubHex != "" {
		raw, err := hex.DecodeString(cfg.TTSPubHex)
		if err != nil || len(raw) != ed25519.PublicKeySize || strings.ToLower(cfg.TTSPubHex) != cfg.TTSPubHex {
			return &fieldError{"-tts-pub", errTTSPubHex}
		}
	}
	// A relative path would resolve against run.sh's own directory, which is
	// the deployment — so "pinning" it there would pin whatever a same-uid
	// process drops in beside the config. Absolute or not at all.
	if cfg.PEPBinary != "" {
		if err := nonEmpty(cfg.PEPBinary); err != nil {
			return &fieldError{"-pep-binary", err}
		}
		if !filepath.IsAbs(cfg.PEPBinary) {
			return &fieldError{"-pep-binary", errPEPBinaryRelative}
		}
	}
	if cfg.MaxTokenTTL > maxAcceptableTokenTTL {
		return &fieldError{"-max-token-ttl", fmt.Errorf("%w: %s exceeds %s", errTTLTooLong, cfg.MaxTokenTTL, maxAcceptableTokenTTL)}
	}
	switch cfg.Profile {
	case profileMCP:
		if err := nonEmpty(cfg.ServerIdentity); err != nil {
			return &fieldError{"-server-identity", err}
		}
		if len(cfg.ServerCmd) == 0 || cfg.ServerCmd[0] == "" {
			return &fieldError{"-- <wrapped-server-command>", errEmpty}
		}
	case profileA2A:
		if err := validateAbsoluteURL(cfg.Upstream); err != nil {
			return &fieldError{"-upstream", err}
		}
		if cfg.PublicURL != "" {
			if err := validateAbsoluteURL(cfg.PublicURL); err != nil {
				return &fieldError{"-public-url", err}
			}
		}
		// a2a://host is the documented shape, so the identifier charset does
		// not apply here either.
		if err := nonEmpty(cfg.AgentIdentity); err != nil {
			return &fieldError{"-agent-identity", err}
		}
		if err := validateListenAddr(cfg.Listen); err != nil {
			return &fieldError{"-listen", err}
		}
	}
	return nil
}

// ── validators ─────────────────────────────────────────────────────────────

// validateProfile admits exactly the two published enforcement points. There
// is no third value and no alias.
func validateProfile(s string) error {
	switch s {
	case profileMCP, profileA2A:
		return nil
	}
	return errBadProfile
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return errEmpty
	}
	// A control byte survives the flag parser and the prompt reader but not
	// the shell: bash and sh silently drop NUL from a quoted word, so run.sh
	// would start the PEP under a value policy.json does not record while the
	// receipts still carry policy.json's hash. Refuse it here rather than let
	// the two drift. CR is the same problem for the generated README.
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return fmt.Errorf("%w: %q", errControlChar, string(s[i]))
		}
	}
	return nil
}

// validateAbsoluteURL mirrors what cmd/a2a-pep enforces at startup, so a URL
// accepted here is one the PEP will accept.
func validateAbsoluteURL(raw string) error {
	if err := nonEmpty(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", errURLUnparsable, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errURLScheme
	}
	if u.Host == "" {
		return errURLNoHost
	}
	return nil
}

// validateListenAddr accepts what net.Listen accepts for tcp: an optional
// host and a numeric port. ":8402", "127.0.0.1:8402", "localhost:8402" and
// "[::1]:8402" all pass. It exists because -listen is the one operator string
// that is an address rather than an identifier, so the identifier charset
// would reject a legitimate IPv6 literal's brackets.
func validateListenAddr(s string) error {
	if err := nonEmpty(s); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%w: %v", errListenAddr, err)
	}
	if port == "" {
		return errListenAddr
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return errListenAddr
		}
	}
	// SplitHostPort has already stripped an IPv6 literal's brackets, so what
	// is left is a bare address or a DNS name; both fit the identifier charset.
	if host != "" {
		return validateIdentifier(host)
	}
	return nil
}

// validateIdentifier enforces the snapshot identifier charset of
// TRUST-REGISTRY-SNAPSHOT.md §3.2 (alphanumerics plus -_.:, no ".."), which is
// what trustsnapshot.Sign will enforce again. Checking it here means an
// operator is re-prompted rather than failed after key generation.
func validateIdentifier(s string) error {
	if s == "" {
		return errEmpty
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return fmt.Errorf("%w: %q", errIdentCharset, string(c))
		}
	}
	if strings.Contains(s, "..") {
		return errIdentTraversal
	}
	return nil
}

// ── prompting ──────────────────────────────────────────────────────────────

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

// ask prints label (and the default, if any), reads one line, and returns it
// once validate accepts it. Invalid input is reported and asked again; an
// empty line returns the default when there is one, or the empty string when
// the value is optional. EOF is an error naming the label — an installer must
// not spin on a closed stdin, and must not treat closed stdin as an answer.
func (p *prompter) ask(label, def string, optional bool, validate func(string) error) (string, error) {
	for {
		switch {
		case def != "":
			fmt.Fprintf(p.out, "%s [%s]: ", label, def)
		case optional:
			fmt.Fprintf(p.out, "%s [Enter to skip]: ", label)
		default:
			fmt.Fprintf(p.out, "%s: ", label)
		}
		line, err := p.in.ReadString('\n')
		if err != nil && (err != io.EOF || line == "") {
			fmt.Fprintln(p.out)
			return "", fmt.Errorf("%w: %s", errInputClosed, label)
		}
		v := strings.TrimSpace(line)
		if v == "" {
			if def != "" {
				v = def
			} else if optional {
				return "", nil
			}
		}
		if verr := validate(v); verr != nil {
			fmt.Fprintf(p.out, "  rejected: %v\n", verr)
			if err == io.EOF {
				return "", fmt.Errorf("%w: %s", errInputClosed, label)
			}
			continue
		}
		return v, nil
	}
}

// splitCommand splits a shell-like command line into words, honouring single
// and double quotes and backslash escapes outside single quotes. It is what
// the interactive prompt uses; a run that needs anything more exotic passes
// the words after -- and skips this entirely.
func splitCommand(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				cur.WriteRune(r)
			}
		case r == '\\':
			escaped = true
			inWord = true
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// shellQuote renders s as one POSIX shell word. Single quotes, with the only
// character that cannot live inside them spliced back in. Every operator value
// that reaches run.sh or mint.sh goes through this, so an identity or an
// argument cannot break out of the command it is placed in.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellQuoteAll(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = shellQuote(w)
	}
	return strings.Join(q, " ")
}

// ── generation ─────────────────────────────────────────────────────────────

// generator produces one deployment directory. rand and now are injectable
// for the tests; beforeWrite is a failpoint the cleanup test uses and is nil
// in production.
type generator struct {
	cfg         config
	now         time.Time
	rand        io.Reader
	beforeWrite func(rel string) error

	// mu serialises every write into the temporary directory against the
	// signal handler's removal of it: the handler takes the lock, removes,
	// and exits while still holding it, so no write can land in between.
	mu sync.Mutex
}

// fileInfo is one line of the printed summary.
type fileInfo struct {
	Name    string
	Private bool
	What    string
}

// result is what generation reports. Nothing in it is secret: every field is
// printed.
type result struct {
	OutDir            string
	Profile           string
	TTSPubHex         string
	PublicationPubHex string
	SnapshotID        string
	PolicyHash        string
	Files             []fileInfo
	RunCommand        string
	// IssuerKeyPath is where the self-issued issuer private key was placed,
	// beside the deployment rather than in it. Empty with -tts-pub, where no
	// issuer private key is generated at all.
	IssuerKeyPath string
}

// checkOutDir refuses to write over anything. An absent path is fine and so
// is an empty directory; a non-empty one is an error and there is no override.
func checkOutDir(path string) error {
	// Lstat, not Stat: run() later removes an empty existing directory with
	// os.Remove, which does NOT follow symlinks. Checking through the link
	// and then removing the link itself would silently replace an operator's
	// symlink with a real directory. Refuse the link and say what to do.
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errOutDirSymlink
	}
	if !st.IsDir() {
		return errOutDirNotADir
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return errOutDirNotEmpty
	}
	return nil
}

// run generates the deployment. Everything is written under a temporary
// sibling of the output directory and renamed into place as the last step, so
// there is no state in which the operator can find a directory that has some
// of its files: either all of it is there and it verified, or none of it is.
func (g *generator) run() (res *result, err error) {
	if err := validate(&g.cfg); err != nil {
		return nil, err
	}
	outDir, err := filepath.Abs(g.cfg.OutDir)
	if err != nil {
		return nil, err
	}
	if err := checkOutDir(outDir); err != nil {
		return nil, fmt.Errorf("%s: %w", outDir, err)
	}
	// The issuer key is placed beside the deployment, so that path must be
	// free too — checked here so an occupied one costs nothing, and again
	// atomically at placement time by os.Link, which refuses to overwrite.
	issuerKey := ""
	if g.cfg.TTSPubHex == "" {
		issuerKey = issuerKeyPath(outDir)
		if _, err := os.Lstat(issuerKey); err == nil {
			return nil, fmt.Errorf("%s: %w", issuerKey, errIssuerKeyExists)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	parent := filepath.Dir(outDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", parent, err)
	}

	tmp, err := os.MkdirTemp(parent, ".spt-txn-init-*")
	if err != nil {
		return nil, fmt.Errorf("temporary directory: %w", err)
	}
	// An error below removes the temporary directory; so does an interrupt
	// (cleanupOnSignal). On success it has been renamed away and RemoveAll
	// finds nothing. Neither path covers SIGKILL or a power loss.
	// Conditioned on an explicit success flag, NOT on the named return: a
	// panic unwinds with err still nil, so an err-conditioned defer would
	// leave the private keys behind. A failed removal is reported rather than
	// discarded — the operator is told the run failed and must also be told
	// that keys survived it.
	success := false
	defer func() {
		if success {
			return
		}
		if rmErr := os.RemoveAll(tmp); rmErr != nil {
			fmt.Fprintf(os.Stderr, "spt-txn-init: could not remove %s, it may hold private keys: %v\n", tmp, rmErr)
		}
	}()
	stop := g.cleanupOnSignal(tmp)
	defer stop()
	// MkdirTemp already creates 0700; stated explicitly because it is a
	// requirement, not an accident of the library.
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("chmod: %w", err)
	}

	res, err = g.populate(tmp)
	if err != nil {
		return nil, err
	}

	// An existing EMPTY output directory was accepted by checkOutDir; remove
	// it so the rename lands the temporary directory on that exact path. Under
	// the lock: an interrupt either lands before this (and removes tmp, so the
	// rename fails and nothing is left) or after (and finds tmp already gone).
	g.mu.Lock()
	defer g.mu.Unlock()
	// checkOutDir ran before key generation, tens of milliseconds ago, and
	// MkdirTemp published a visible entry in the parent the instant it passed
	// — which tells anyone watching that the check is done. Re-check here,
	// under the lock and immediately before the removal, so a symlink or file
	// swapped into the window is refused instead of being silently unlinked
	// by the os.Remove below. The window is not closed, but it shrinks from
	// the whole of populate() to the gap between these two syscalls.
	if err := checkOutDir(outDir); err != nil {
		return nil, fmt.Errorf("%w: %v", errOutDirChanged, err)
	}
	// Place the issuer key beside the deployment FIRST, with os.Link: link(2)
	// fails with EEXIST rather than overwriting, so the "is that path free?"
	// question is answered atomically rather than by a check that a racing
	// process can invalidate. Removing it from tmp afterwards is what keeps
	// the rename below from carrying it into the deployment.
	if issuerKey != "" {
		staged := filepath.Join(tmp, fileIssuerKey)
		if err := os.Link(staged, issuerKey); err != nil {
			return nil, fmt.Errorf("place %s: %w", issuerKey, err)
		}
		if err := os.Remove(staged); err != nil {
			_ = os.Remove(issuerKey)
			return nil, fmt.Errorf("unstage %s: %w", fileIssuerKey, err)
		}
	}
	if err := os.Remove(outDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		if issuerKey != "" {
			_ = os.Remove(issuerKey)
		}
		return nil, fmt.Errorf("replace empty %s: %w", outDir, err)
	}
	if err := os.Rename(tmp, outDir); err != nil {
		if issuerKey != "" {
			_ = os.Remove(issuerKey)
		}
		return nil, fmt.Errorf("move into place: %w", err)
	}
	res.OutDir = outDir
	res.RunCommand = filepath.Join(outDir, fileRunScript)
	res.IssuerKeyPath = issuerKey
	success = true
	return res, nil
}

// cleanupOnSignal removes tmp if the process is interrupted while it is being
// filled, then re-raises the signal so the exit status is the one a shell
// expects. Go's default handler exits without running deferred functions, so
// without this a Ctrl-C after a mistyped answer leaves a dot-named directory of
// private keys beside the output path — exactly the half-written deployment
// this tool promises not to leave. The returned stop function uninstalls the
// handler; call it once the directory has been renamed into place.
func (g *generator) cleanupOnSignal(tmp string) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-ch:
			// Wait for any write in flight, and hold the lock through exit so
			// no further write can land after the removal.
			g.mu.Lock()
			_ = os.RemoveAll(tmp)
			signal.Reset(sig)
			raise(sig)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// populate writes every artifact into dir. It is the whole generation step
// minus the rename, kept separate so run's cleanup has one place to watch.
func (g *generator) populate(dir string) (*result, error) {
	cfg := &g.cfg

	// With -tts-pub the issuer key lives elsewhere — an existing TTS, or a
	// PKCS#11 token — and this tool never holds, writes or sees the private
	// half. That is the only configuration in which the deployment directory
	// contains no key that can mint a token.
	var ttsPub ed25519.PublicKey
	var ttsPriv ed25519.PrivateKey
	selfIssued := cfg.TTSPubHex == ""
	if selfIssued {
		var err error
		ttsPub, ttsPriv, err = ed25519.GenerateKey(g.rand)
		if err != nil {
			return nil, fmt.Errorf("issuer key: %w", err)
		}
	} else {
		raw, err := hex.DecodeString(cfg.TTSPubHex) // validated in validate()
		if err != nil {
			return nil, fmt.Errorf("issuer public key: %w", err)
		}
		ttsPub = ed25519.PublicKey(raw)
	}
	_, logPriv, err := ed25519.GenerateKey(g.rand)
	if err != nil {
		return nil, fmt.Errorf("log key: %w", err)
	}
	pubPub, pubPriv, err := ed25519.GenerateKey(g.rand)
	if err != nil {
		return nil, fmt.Errorf("publication key: %w", err)
	}

	if selfIssued {
		if err := g.write(dir, fileIssuerKey, hexLine(ttsPriv), 0o600); err != nil {
			return nil, err
		}
	}
	if err := g.write(dir, fileIssuerPub, hexLine(ttsPub), 0o644); err != nil {
		return nil, err
	}
	if err := g.write(dir, fileLogKey, hexLine(logPriv), 0o600); err != nil {
		return nil, err
	}
	if err := g.write(dir, filePublicationKey, hexLine(pubPriv), 0o600); err != nil {
		return nil, err
	}
	if err := g.write(dir, filePublicationPub, hexLine(pubPub), 0o644); err != nil {
		return nil, err
	}

	// The snapshot body comes out of the real registry so it carries exactly
	// the record shape every verifier in this tree loads, in the deterministic
	// order ExportBody defines. Register validates the record; nothing here
	// composes the body by hand.
	body, issuerIDs, err := g.buildRegistryBody(dir, cfg.Issuer, ttsPub)
	if err != nil {
		return nil, err
	}
	if err := g.write(dir, fileRegistry, body, 0o644); err != nil {
		return nil, err
	}
	snapshotID := "spt-txn-init-" + g.now.UTC().Format("20060102T150405Z")
	manifest, err := trustsnapshot.Sign(body, snapshotID, g.now, issuerIDs, nil, pubPriv)
	if err != nil {
		return nil, fmt.Errorf("sign snapshot: %w", err)
	}
	manifestJSON, err := trustsnapshot.MarshalManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')
	// Generate, then verify with the real verifier, before anything is
	// handed over. A snapshot this tool cannot verify is not one it may ship.
	if _, err := trustsnapshot.Verify(manifestJSON, body, trustsnapshot.Options{
		PinnedKeys: []ed25519.PublicKey{pubPub},
		MaxAge:     snapshotMaxAge,
		Now:        g.now,
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", errSnapshotSelfCheck, err)
	}
	if err := g.write(dir, fileManifest, manifestJSON, 0o644); err != nil {
		return nil, err
	}

	policyJSON, policyHash, err := policyBundle(cfg, hex.EncodeToString(ttsPub))
	if err != nil {
		return nil, err
	}
	if err := g.write(dir, filePolicy, policyJSON, 0o644); err != nil {
		return nil, err
	}

	ttsPubHex := hex.EncodeToString(ttsPub)
	if err := g.write(dir, fileRunScript, []byte(renderRunScript(cfg, ttsPubHex, policyHash, g.now)), 0o700); err != nil {
		return nil, err
	}
	files := []fileInfo{
		{fileIssuerPub, isPrivate(fileIssuerPub), "issuer public key, hex — a copy for your TTS; run.sh pins the key itself and checks this matches"},
		{fileLogKey, isPrivate(fileLogKey), "receipt-log signing key — run.sh passes it as -log-key-file"},
		{filePublicationKey, isPrivate(filePublicationKey), "snapshot publication private key — signs registry.json.manifest.json"},
		{filePublicationPub, isPrivate(filePublicationPub), "snapshot publication public key, hex — pin it wherever the snapshot is loaded"},
		{fileRegistry, false, "trust snapshot body: one tts_issuer record for " + cfg.Issuer},
		{fileManifest, false, "trust snapshot manifest, signed; verified before this directory was written"},
		{filePolicy, false, "the policy bundle; -policy-hash is its base64url SHA-256 and every receipt carries it"},
		{fileRunScript, false, "starts the PEP with every required flag filled in"},
	}
	if cfg.Profile == profileMCP {
		if err := g.write(dir, fileMintScript, []byte(renderMintScript(cfg, policyHash)), 0o700); err != nil {
			return nil, err
		}
		files = append(files, fileInfo{fileMintScript, false, "smoke test: mints a token with cmd/mcp-mint and drives the PEP with it"})
	}
	if err := g.write(dir, fileREADME, []byte(renderREADME(cfg, ttsPubHex, hex.EncodeToString(pubPub), snapshotID, policyHash, g.now)), 0o644); err != nil {
		return nil, err
	}
	files = append(files, fileInfo{fileREADME, false, "what each file is, what to run next, and what this deployment does not have"})

	return &result{
		Profile:           cfg.Profile,
		TTSPubHex:         ttsPubHex,
		PublicationPubHex: hex.EncodeToString(pubPub),
		SnapshotID:        snapshotID,
		PolicyHash:        policyHash,
		Files:             files,
	}, nil
}

// write creates rel under dir with exactly mode. O_EXCL: this tool never
// writes over a file, not even one it created a moment ago.
func (g *generator) write(dir, rel string, data []byte, mode os.FileMode) error {
	if g.beforeWrite != nil {
		if err := g.beforeWrite(rel); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", rel, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", rel, err)
	}
	// open(2) applies the umask, which can only narrow the mode: a private
	// key is 0600 under any umask, but a strict one (0077, 0177, 0777) strips
	// the execute bit from run.sh or the read bits from the public files.
	// Restate the mode on the descriptor we already hold rather than by
	// re-resolving the path: os.Chmod follows symlinks, and acting on a name
	// checked earlier is the same class of gap as the output-path race.
	// fchmod cannot be redirected.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", rel, err)
	}
	return nil
}

func hexLine(b []byte) []byte { return []byte(hex.EncodeToString(b) + "\n") }

// buildRegistryBody registers the single issuer record in a real
// PersistentRegistry and exports the snapshot body from it. The registry's own
// file is a scratch artifact inside dir and is removed once the body is out.
//
// The registry writes its own file, so the whole step runs under the lock the
// signal handler takes.
func (g *generator) buildRegistryBody(dir, issuer string, ttsPub ed25519.PublicKey) ([]byte, []string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now
	scratch := filepath.Join(dir, ".registry-build.json")
	reg, err := trustregistry.NewPersistentRegistry(scratch)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: %w", err)
	}
	rec := &trustregistry.Record{
		Iss:        issuer,
		Role:       trustregistry.RoleTTSIssuer,
		PublicKey:  append([]byte(nil), ttsPub...),
		KeyType:    trustregistry.KeyTypeEd25519,
		ValidFrom:  now.UTC().Truncate(time.Second),
		ValidUntil: now.UTC().Truncate(time.Second).Add(issuerKeyValidity),
		Status:     trustregistry.StatusActive,
	}
	if err := reg.Register(context.Background(), rec); err != nil {
		return nil, nil, fmt.Errorf("register issuer: %w", err)
	}
	body, err := reg.ExportBody()
	if err != nil {
		return nil, nil, fmt.Errorf("export body: %w", err)
	}
	ids := reg.IssuerIDs()
	_ = reg.Close()
	if err := os.Remove(scratch); err != nil {
		return nil, nil, fmt.Errorf("remove scratch registry: %w", err)
	}
	return body, ids, nil
}

// policy is the policy bundle the PEP's receipts bind to. The PEPs take their
// policy as flags, so the bundle is the record of those flags: an auditor who
// holds policy.json can recompute the hash in any receipt and know which
// audience, target and TTL bound that decision.
type policy struct {
	Format       string `json:"spt_txn_policy"`
	GeneratedBy  string `json:"generated_by"`
	Profile      string `json:"profile"`
	PEP          string `json:"pep"`
	Target       string `json:"target"`
	Audience     string `json:"audience"`
	Issuer       string `json:"issuer"`
	TTSPublicKey string `json:"tts_pub"`
	MaxTokenTTL  string `json:"max_token_ttl"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

// policyBundle renders policy.json and the value for -policy-hash: the
// base64url SHA-256 of the file bytes, which is the encoding RECEIPT-FORMAT.md
// gives for policy_hash.
func policyBundle(cfg *config, ttsPubHex string) ([]byte, string, error) {
	p := policy{
		Format:       "1",
		GeneratedBy:  "spt-txn-init",
		Profile:      cfg.Profile,
		PEP:          pepName(cfg.Profile),
		Target:       targetIdentity(cfg),
		Audience:     cfg.Audience,
		Issuer:       cfg.Issuer,
		TTSPublicKey: ttsPubHex,
		MaxTokenTTL:  cfg.MaxTokenTTL.String(),
		Jurisdiction: cfg.Jurisdiction,
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("policy: %w", err)
	}
	b = append(b, '\n')
	return b, policyHashOf(b), nil
}

// policyHashOf is the one place the hash is computed, so the test that
// recomputes it from the file on disk is checking the same rule run.sh used.
func policyHashOf(policyJSON []byte) string {
	sum := sha256.Sum256(policyJSON)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pepName(profile string) string {
	if profile == profileA2A {
		return "a2a-pep.spt-txn"
	}
	return "mcp-pep.spt-txn"
}

func pepBinary(profile string) string {
	if profile == profileA2A {
		return "a2a-pep"
	}
	return "mcp-pep"
}

func targetIdentity(cfg *config) string {
	if cfg.Profile == profileA2A {
		return cfg.AgentIdentity
	}
	return cfg.ServerIdentity
}

// ── rendered files ─────────────────────────────────────────────────────────

// pepFlags renders the flag block the PEP is started with. It is shared by
// run.sh and mint.sh so the two cannot drift: mint.sh substitutes exactly one
// value (the issuer public key) and states that it does.
//
// ttsPub and auditLog are already shell words — run.sh passes quoted
// literals, mint.sh passes "$TTS_PUB" and "$AUDIT" — so they are placed as
// given. Every operator-supplied value is quoted here.
// pepFlags renders the flag block. logKey and auditLog arrive already in
// whatever form the caller needs — run.sh passes absolute "$HERE/..." paths so
// that it never has to change the process working directory (see
// renderRunScript); mint.sh and the README pass the plain names.
func pepFlags(cfg *config, ttsPub, policyHash, logKey, auditLog string) string {
	var b strings.Builder
	switch cfg.Profile {
	case profileMCP:
		fmt.Fprintf(&b, "  -server-identity %s \\\n", shellQuote(cfg.ServerIdentity))
	case profileA2A:
		fmt.Fprintf(&b, "  -listen %s \\\n", shellQuote(cfg.Listen))
		fmt.Fprintf(&b, "  -upstream %s \\\n", shellQuote(cfg.Upstream))
		if cfg.PublicURL != "" {
			fmt.Fprintf(&b, "  -public-url %s \\\n", shellQuote(cfg.PublicURL))
		}
		fmt.Fprintf(&b, "  -agent-identity %s \\\n", shellQuote(cfg.AgentIdentity))
	}
	fmt.Fprintf(&b, "  -audience %s \\\n", shellQuote(cfg.Audience))
	fmt.Fprintf(&b, "  -tts-pub %s \\\n", ttsPub)
	fmt.Fprintf(&b, "  -log-key-file %s \\\n", logKey)
	fmt.Fprintf(&b, "  -audit-log %s \\\n", auditLog)
	fmt.Fprintf(&b, "  -policy-hash %s \\\n", shellQuote(policyHash))
	fmt.Fprintf(&b, "  -max-token-ttl %s", cfg.MaxTokenTTL)
	if cfg.Jurisdiction != "" {
		fmt.Fprintf(&b, " \\\n  -jurisdiction %s", shellQuote(cfg.Jurisdiction))
	}
	if cfg.Profile == profileMCP {
		fmt.Fprintf(&b, " \\\n  -- %s", shellQuoteAll(cfg.ServerCmd))
	}
	return b.String()
}

// buildCommand is the one build line the README and the scripts print for a
// binary in this tree. CGO_ENABLED=0 is load-bearing: without it a2a-pep
// (net/http) links glibc for the cgo resolver and is not a static binary, and
// will not start in a scratch or distroless image.
func buildCommand(name string) string {
	return "CGO_ENABLED=0 go build -o /usr/local/bin/" + name + " ./cmd/" + name
}

// binaryCheck is the shell preamble that locates the PEP binary (and, for
// mint.sh, mcp-mint) and says how to build it when it is absent.
// binaryCheck emits the PATH-and-environment guard mint.sh uses. mint.sh is a
// developer smoke test that mints its own throwaway issuer key and proves
// nothing about the deployment, so an overridable binary name is appropriate
// there. The ENFORCEMENT path does not use this — see pepGuard.
func binaryCheck(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		v := strings.ToUpper(strings.ReplaceAll(n, "-", "_"))
		fmt.Fprintf(&b, ": \"${%s:=%s}\"\n", v, n)
		fmt.Fprintf(&b, "if ! command -v \"$%s\" >/dev/null 2>&1; then\n", v)
		fmt.Fprintf(&b, "  echo \"%s: $%s not found. Build it from the spt-txn-poc checkout:\" >&2\n", "$(basename \"$0\")", v)
		fmt.Fprintf(&b, "  echo \"  %s\" >&2\n", buildCommand(n))
		fmt.Fprintf(&b, "  echo \"or set %s to its path.\" >&2\n", v)
		fmt.Fprintf(&b, "  exit 1\nfi\n")
	}
	return b.String()
}

// pepGuard emits run.sh's guard and the word it execs. Unlike binaryCheck it
// reads NO environment variable: run.sh inherits its environment from whoever
// starts it — for MCP that is the client, whose config file the operator may
// not have written — so a "${MCP_PEP:=mcp-pep}" indirection let that party
// substitute a pass-through for the enforcement point while run.sh,
// policy.json and the policy hash stayed byte-identical. Everything else in
// this deployment is pinned; the binary that enforces it should be too.
//
// With -pep-binary the path is fixed at generation and there is no lookup at
// all. Without it the name is still fixed, but resolution is left to PATH and
// the README says so rather than implying a pin that is not there.
func pepGuard(pin, bin string) (guard, execWord string) {
	var b strings.Builder
	if pin != "" {
		fmt.Fprintf(&b, "if [ ! -x %s ]; then\n", shellQuote(pin))
		fmt.Fprintf(&b, "  echo \"%s: pinned enforcement point %s is missing or not executable\" >&2\n",
			"$(basename \"$0\")", pin)
		b.WriteString("  exit 1\nfi\n")
		return b.String(), shellQuote(pin)
	}
	fmt.Fprintf(&b, "if ! command -v %s >/dev/null 2>&1; then\n", shellQuote(bin))
	fmt.Fprintf(&b, "  echo \"%s: %s not found on PATH. Build it from the spt-txn-poc checkout:\" >&2\n",
		"$(basename \"$0\")", bin)
	fmt.Fprintf(&b, "  echo \"  %s\" >&2\n", buildCommand(bin))
	b.WriteString("  echo \"or re-run spt-txn-init with -pep-binary <absolute path> to pin it.\" >&2\n")
	b.WriteString("  exit 1\nfi\n")
	return b.String(), shellQuote(bin)
}

func renderRunScript(cfg *config, ttsPub, policyHash string, now time.Time) string {
	bin := pepBinary(cfg.Profile)
	auditLog := bin + "-audit.jsonl"
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	fmt.Fprintf(&b, "# Generated by spt-txn-init on %s.\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# Starts the SPT-Txn %s enforcement point for this deployment.\n#\n", strings.ToUpper(cfg.Profile))
	b.WriteString("# -policy-hash is the SHA-256 of policy.json, and every receipt the PEP\n")
	b.WriteString("# writes cites it. policy.json records the AUTHORIZATION facts: profile,\n")
	b.WriteString("# PEP, target, audience, issuer, issuer public key, max token TTL and\n")
	b.WriteString("# jurisdiction. Per RECEIPT-FORMAT.md that is all policy_hash is: which\n")
	b.WriteString("# policy version was in force. It does NOT cover the wiring below\n")
	b.WriteString("# (-listen, -upstream, -public-url, -log-key-file, -audit-log, and the\n")
	b.WriteString("# wrapped command). Editing one of those changes what runs and where it\n")
	b.WriteString("# goes WITHOUT changing any receipt. Edit nothing here by hand.\n")
	b.WriteString("# To change a value, run spt-txn-init again into a NEW directory\n")
	b.WriteString("# (it refuses to overwrite this one) and start from there. A new run means a\n")
	b.WriteString("# new issuer keypair and a new policy hash: tokens minted for this deployment\n")
	b.WriteString("# do not verify at the new one. That is the intended consequence of a policy\n")
	b.WriteString("# change, not a fault.\n")
	b.WriteString("set -euo pipefail\n")
	// Deliberately NOT "cd $(dirname $0)". The PEP's working directory becomes
	// the working directory of everything it starts — for MCP that is the
	// wrapped third-party server — and this directory holds log.key, the
	// receipt log and run.sh itself. Resolving an absolute base instead leaves
	// the process where its caller was, so the wrapped server sees exactly the
	// environment it would have seen had the client spawned it directly, and
	// the deployment directory is nobody's cwd. HERE keeps run.sh relocatable.
	b.WriteString("HERE=$(cd \"$(dirname \"$0\")\" && pwd)\n")
	// The pinned key is a literal HERE, in a 0700 script, not read from
	// issuer.pub, which is 0644 and therefore writable by any process running
	// as the operator. Reading it would move the trust anchor into the weaker
	// file. But the two must not be allowed to disagree silently: issuer.pub
	// is what an operator hands their TTS and what the README's file table
	// invites them to replace, and a deployment that keeps verifying against
	// a key its own directory no longer names is failing open in the half
	// that matters. So: pin the literal, and refuse to start if the copy has
	// drifted from it.
	fmt.Fprintf(&b, "PINNED=%s\n", shellQuote(ttsPub))
	fmt.Fprintf(&b, "if [ ! -r \"$HERE/%s\" ]; then\n", fileIssuerPub)
	fmt.Fprintf(&b, "  echo \"$(basename \"$0\"): %s is missing or unreadable\" >&2\n", fileIssuerPub)
	b.WriteString("  exit 1\nfi\n")
	fmt.Fprintf(&b, "if [ \"$(tr -d '[:space:]' < \"$HERE/%s\")\" != \"$PINNED\" ]; then\n", fileIssuerPub)
	fmt.Fprintf(&b, "  echo \"$(basename \"$0\"): %s does not match the key this script pins.\" >&2\n", fileIssuerPub)
	b.WriteString("  echo \"  run.sh pins: $PINNED\" >&2\n")
	b.WriteString("  echo \"Replacing a key file in place rotates nothing: run.sh, policy.json and the\" >&2\n")
	b.WriteString("  echo \"trust snapshot all still carry the old key, and the policy hash in every\" >&2\n")
	b.WriteString("  echo \"receipt is the hash of the old bundle. Run spt-txn-init into a NEW directory.\" >&2\n")
	b.WriteString("  exit 1\nfi\n")
	guard, execWord := pepGuard(cfg.PEPBinary, bin)
	b.WriteString(guard)
	fmt.Fprintf(&b, "exec %s \\\n", execWord)
	b.WriteString(pepFlags(cfg, "\"$PINNED\"", policyHash,
		"\"$HERE/"+fileLogKey+"\"", "\"$HERE/"+auditLog+"\""))
	b.WriteString("\n")
	return b.String()
}

// mintDefaultArgs is the tools/call argument object the smoke test mints
// against. It carries an amount because cmd/mcp-mint refuses to mint a priced
// token for arguments that declare no amount.
const mintDefaultArgs = `{"amount":"3000","currency":"USD"}`

// mintTamperedArgs differs from mintDefaultArgs in one value. That difference
// is the prompt-injection case the PEP exists to refuse.
const mintTamperedArgs = `{"amount":"9999","currency":"USD"}`

func renderMintScript(cfg *config, policyHash string) string {
	var b strings.Builder
	b.WriteString(`#!/usr/bin/env bash
# Smoke test for this deployment, built on cmd/mcp-mint.
#
# It runs the PEP twice, each time with a token bound to one tools/call:
#
#   1. the call exactly as minted            -> PERMIT  (rule authorize.ok)
#   2. the same call with one argument changed -> DENY  (rule intent.digest-mismatch)
#
# Two runs rather than one because a token is single-use: the PEP consumes it
# on the first decision, so a second call with the same token would be refused
# as a replay whatever its arguments said, and that would prove the wrong thing.
#
# READ THIS BEFORE TRUSTING THE RESULT. cmd/mcp-mint generates a throwaway
# issuer key on every run and has no way to sign with issuer.key. Each PEP run
# below is therefore started with THAT run's mcp-mint key in place of
# issuer.pub. It is the only flag that differs from run.sh.
#
#   What this proves: the binary starts with run.sh's flags, log.key signs
#   receipts, -policy-hash reaches every receipt (the PEP copies it in; it
#   does not check it against policy.json), the intent binding refuses a
#   changed argument, and the receipt log records both decisions.
#   What it does not prove: anything about issuer.key, which is exercised the
#   first time your own TTS mints with it. Nor that the server identity and
#   audience are RIGHT: mint.sh sets both sides from the same values, so a
#   mistyped audience passes here and only fails when a token from your TTS
#   carries the real one. This is a self-consistency check of the
#   enforcement configuration, not a check of the values.
#
# Each run spawns the wrapped server and ends when stdin closes. A wrapped
# server that does not exit when ITS stdin closes keeps the PEP waiting on it;
# Ctrl-C ends the run, and the receipts are already on disk by then.
#
# Usage: ./mint.sh [tool-name]      (default tool: payments.transfer)
set -euo pipefail
cd "$(dirname "$0")"
`)
	b.WriteString(binaryCheck("mcp-pep", "mcp-mint"))
	b.WriteString("\nTOOL=${1:-payments.transfer}\n")
	b.WriteString("AUDIT=smoke-audit.jsonl\n")
	fmt.Fprintf(&b, "TARGET=%s\n", shellQuote(cfg.ServerIdentity))
	fmt.Fprintf(&b, "AUDIENCE=%s\n", shellQuote(cfg.Audience))
	fmt.Fprintf(&b, "MINT_ARGS=%s\n", shellQuote(mintDefaultArgs))
	fmt.Fprintf(&b, "TAMPERED_ARGS=%s\n\n", shellQuote(mintTamperedArgs))
	b.WriteString(`# mint TOOL ARGS: mint one token bound to (TOOL, ARGS, TARGET, AUDIENCE). Sets
# TTS_PUB (that run's throwaway issuer public key) and TOKEN. -amount and
# -currency are mcp-mint's defaults and match MINT_ARGS, which mcp-mint checks.
mint() {
  local minted
  minted=$("$MCP_MINT" -tool "$1" -args "$2" -target "$TARGET" -audience "$AUDIENCE")
  TTS_PUB=$(printf '%s\n' "$minted" | sed -n 's/^ *"tts_pub": "\([0-9a-f]*\)",*$/\1/p')
  TOKEN=$(printf '%s\n' "$minted" | sed -n 's/^ *"token": "\([^"]*\)",*$/\1/p')
  if [ -z "$TTS_PUB" ] || [ -z "$TOKEN" ]; then
    echo "mint.sh: could not read tts_pub and token from mcp-mint's output" >&2
    exit 1
  fi
}

# call ID ARGS: one tools/call carrying TOKEN. The PEP recomputes the intent
# digest over name, arguments and its own -server-identity; whitespace does
# not matter (JCS), the argument VALUES do.
call() {
  printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s,"_meta":{"spt-txn/token":"%s"}}}\n' \
    "$1" "$TOOL" "$2" "$TOKEN"
}

# pep: start the PEP as run.sh does, except -tts-pub is this run's mcp-mint key
# and receipts go to AUDIT. Reads one call on stdin, forwards or refuses it,
# and exits when stdin closes.
pep() {
  "$MCP_PEP" \
`)
	b.WriteString(pepFlags(cfg, "\"$TTS_PUB\"", policyHash, fileLogKey, "\"$AUDIT\""))
	b.WriteString("\n}\n\n")
	b.WriteString(`rm -f "$AUDIT"

echo "== 1. as minted: expect PERMIT"
mint "$TOOL" "$MINT_ARGS"
call 1 "$MINT_ARGS" | pep

echo "== 2. one argument changed after minting: expect DENY"
mint "$TOOL" "$MINT_ARGS"
call 2 "$TAMPERED_ARGS" | pep

echo
echo "== receipts in $AUDIT (decision and rule path):"
grep -o '"decision":"[A-Z]*"\|"rule_path":"[^"]*"' "$AUDIT" | paste - - || true
echo
echo "Expected: PERMIT authorize.ok, then DENY intent.digest-mismatch."
echo "A wrapped server that lacks tool \"$TOOL\" still yields the PERMIT receipt:"
echo "the PEP decides before it forwards, and the tool error is the server's answer."
`)
	return b.String()
}

// ── Markdown rendering of operator values ──────────────────────────────────
//
// Operator values (identities, URLs, the wrapped command) land in the README as
// inline code, in table cells and inside a fenced shell block. None of that is
// executed, but a backtick, a pipe or a ``` in a value would render the file
// wrong. These three helpers make the rendering survive any value.

// longestRun returns the length of the longest run of c in s.
func longestRun(s string, c byte) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best
}

// mdCode renders s as an inline code span: the delimiter is one backtick longer
// than the longest run inside, padded with a space when the content begins or
// ends with a backtick (CommonMark §6.1). Newlines become spaces, since a blank
// line would end the span.
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "` `"
	}
	d := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return d + s + d
}

// mdCell renders s as an inline code span usable inside a GFM table cell, where
// an unescaped pipe splits the row even inside a code span.
func mdCell(s string) string { return mdCode(strings.ReplaceAll(s, "|", `\|`)) }

// mdFence returns an opening/closing fence longer than any backtick run in the
// block it encloses, so a ``` inside a quoted operator value cannot close it.
func mdFence(content string) string {
	n := longestRun(content, '`') + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

// mdText renders s as plain heading or prose text: one line.
func mdText(s string) string { return strings.ReplaceAll(s, "\n", " ") }

func renderREADME(cfg *config, ttsPub, pubPub, snapshotID, policyHash string, now time.Time) string {
	var b strings.Builder
	name := strings.ToUpper(cfg.Profile)
	bin := pepBinary(cfg.Profile)
	fmt.Fprintf(&b, "# SPT-Txn %s enforcement point — %s\n\n", name, mdText(targetIdentity(cfg)))
	fmt.Fprintf(&b, "Generated by `spt-txn-init` on %s. Everything in this directory was produced\n", now.UTC().Format(time.RFC3339))
	b.WriteString("offline on this machine. Nothing was sent anywhere.\n\n")

	b.WriteString("## What this deployment is\n\n")
	switch cfg.Profile {
	case profileMCP:
		fmt.Fprintf(&b, "`%s` wraps the MCP server %s and gates every `tools/call` on an SPT-Txn\n", bin, mdCode(shellQuoteAll(cfg.ServerCmd)))
		fmt.Fprintf(&b, "token bound to that exact call: tool, arguments and target %s, minted for\n", mdCode(cfg.ServerIdentity))
		fmt.Fprintf(&b, "audience %s. A call with a different tool, a changed argument, another target\n", mdCode(cfg.Audience))
		b.WriteString("or another audience is refused before the server sees it. Every decision, permit\n")
		b.WriteString("or deny, is a signed receipt in the audit log.\n\n")
	case profileA2A:
		fmt.Fprintf(&b, "`%s` listens on %s in front of the A2A agent at %s and gates every\n", bin, mdCode(cfg.Listen), mdCode(cfg.Upstream))
		fmt.Fprintf(&b, "`message/send` on an SPT-Txn token bound to that exact message and to target\n%s, minted for audience %s. ", mdCode(cfg.AgentIdentity), mdCode(cfg.Audience))
		if cfg.PublicURL != "" {
			fmt.Fprintf(&b, "The agent card is relayed rewritten to advertise\n%s, so clients discover the enforcement point and not the agent behind it.\n", mdCode(cfg.PublicURL))
		} else {
			b.WriteString("No public URL was given, so the agent card is NOT\nrelayed: clients that discover agents by card will not find this one. Re-run\n`spt-txn-init` with `-public-url` when you know the address clients reach the PEP on.\n")
		}
		b.WriteString("Every decision, permit or deny, is a signed receipt in the audit log.\n\n")
	}

	if cfg.TTSPubHex == "" {
		fmt.Fprintf(&b, "You are your own issuer. `%s` pins %s directly: that one key is what the PEP\n", bin, mdCode(fileIssuerPub))
		b.WriteString("verifies every token against, and it is yours. That is a complete and legitimate\n")
		b.WriteString("posture for a single operator; nothing about it is provisional or reduced. What it\n")
		b.WriteString("does not include is listed under *What this deployment does not have*.\n\n")
		fmt.Fprintf(&b, "**The issuer private key is NOT in this directory.** It was written beside it, as\n")
		fmt.Fprintf(&b, "%s. Nothing in the deployment reads it — both PEPs take `-tts-pub`, the public\n",
			mdCode(filepath.Base(issuerKeyPath(cfg.OutDir))))
		b.WriteString("half — and this directory is the thing you copy into an image, mount, archive or\n")
		b.WriteString("commit. A key that can mint should not travel with it. Move it to wherever your\n")
		b.WriteString("issuer actually runs. If it can live in a PKCS#11 token instead, generate it\n")
		b.WriteString("there and re-run `spt-txn-init` with `-tts-pub <hex>`: no issuer private key is\n")
		b.WriteString("written at all in that mode.\n\n")
		b.WriteString("Two things this does NOT protect against, stated plainly. A process running as\n")
		b.WriteString("you can read any file you can read, wherever it sits — including anything this\n")
		b.WriteString("PEP starts. And a key on disk is a key on disk: file modes bound accident, not\n")
		b.WriteString("an attacker who is already you.\n\n")
	} else {
		fmt.Fprintf(&b, "The issuer key is external to this deployment. `%s` pins the public key you\n", bin)
		b.WriteString("supplied with `-tts-pub`, and **no issuer private key was generated, written or\n")
		b.WriteString("seen by `spt-txn-init`.** Whatever holds it — your existing TTS, or a PKCS#11\n")
		b.WriteString("token — holds it still.\n\n")
		fmt.Fprintf(&b, "This directory does still contain two private keys, %s and %s. Neither can\n",
			mdCode(fileLogKey), mdCode(filePublicationKey))
		b.WriteString("mint a token: the first signs receipts, the second signs the trust snapshot.\n")
		b.WriteString("Losing them costs you evidence integrity and snapshot publication, not\n")
		b.WriteString("authority.\n\n")
	}
	fmt.Fprintf(&b, "The directory also holds a signed trust snapshot naming %s as `tts_issuer`\n", mdCode(cfg.Issuer))
	fmt.Fprintf(&b, "for that key. **The PEP does not read it.** It is for a registry-backed verifier\n")
	b.WriteString("such as `cmd/agentsvc`, and for the day you trust a second issuer; see step 2.\n\n")

	b.WriteString("## Files\n\n")
	b.WriteString("| File | Mode | What it is |\n|---|---|---|\n")
	if cfg.PEPBinary != "" {
		fmt.Fprintf(&b, "| %s | 0700 | Starts %s with every required flag. The binary is PINNED: it execs %s and does no `PATH` lookup. |\n",
			mdCell(fileRunScript), mdCode(bin), mdCell(cfg.PEPBinary))
	} else {
		fmt.Fprintf(&b, "| %s | 0700 | Starts %s with every required flag. The binary is NOT pinned: the name is fixed but it is resolved from `PATH` at start time, so whoever controls `PATH` controls what enforces. Re-run `spt-txn-init` with `-pep-binary <absolute path>` to pin it. |\n",
			mdCell(fileRunScript), mdCode(bin))
	}
	// issuer.key is intentionally absent from this table: it is not in this
	// directory. The prose above says where it is and why.
	fmt.Fprintf(&b, "| %s | 0644 | The issuer public key, hex — a copy, for handing to your TTS or another verifier. `run.sh` does NOT read it: it pins the key as a literal, because this file is 0644 and `run.sh` is 0700. It does check the two agree at every start and refuses if they do not. |\n", mdCell(fileIssuerPub))
	fmt.Fprintf(&b, "| %s | 0600 | **Private.** The receipt-log signing key (`-log-key-file`). Evidence, not authority: it signs receipts and cannot mint anything. Separate from the issuer key on purpose, with a separate rotation. |\n", mdCell(fileLogKey))
	fmt.Fprintf(&b, "| %s | 0644 | The policy bundle: profile, target, audience, issuer, issuer key and token TTL. `-policy-hash` is its base64url SHA-256; the PEP copies that hash into every receipt (it does not read this file). |\n", mdCell(filePolicy))
	if cfg.Profile == profileMCP {
		fmt.Fprintf(&b, "| %s | 0700 | Smoke test built on `cmd/mcp-mint`: one PERMIT, one DENY, receipts in `smoke-audit.jsonl`. Read its header before trusting it. |\n", mdCell(fileMintScript))
	}
	fmt.Fprintf(&b, "| %s | 0644 | Trust snapshot body: one `tts_issuer` record, %s → %s, valid one year from generation. Not read by the PEP. |\n", mdCell(fileRegistry), mdCell(cfg.Issuer), mdCell(fileIssuerPub))
	fmt.Fprintf(&b, "| %s | 0644 | The signed manifest for that body, id %s. Produced by `pkg/trustsnapshot.Sign`, re-verified with `pkg/trustsnapshot.Verify` before this directory was written. Not read by the PEP. |\n", mdCell(fileManifest), mdCell(snapshotID))
	fmt.Fprintf(&b, "| %s | 0600 | **Private.** The snapshot publication key; it signed %s. |\n", mdCell(filePublicationKey), mdCell(fileManifest))
	fmt.Fprintf(&b, "| %s | 0644 | The publication public key, hex. Pin it wherever the snapshot is loaded. |\n", mdCell(filePublicationPub))
	fmt.Fprintf(&b, "| %s | 0644 | This file. |\n", mdCell(fileREADME))
	b.WriteString("\n")

	b.WriteString("## What to run\n\n")
	b.WriteString("Build the binaries once, from the `spt-txn-poc` checkout. `CGO_ENABLED=0` is what\n")
	b.WriteString("makes them static; without it `a2a-pep` links glibc for the resolver and will not\n")
	b.WriteString("start in a scratch or distroless image.\n\n```sh\n")
	fmt.Fprintf(&b, "%s\n", buildCommand(bin))
	if cfg.Profile == profileMCP {
		fmt.Fprintf(&b, "%s   # for mint.sh only\n", buildCommand("mcp-mint"))
	}
	fmt.Fprintf(&b, "%s   # for steps 2 and 3 only\n", buildCommand("snapshot"))
	b.WriteString("```\n\nThen, from this directory:\n\n```sh\n./run.sh\n```\n\n")
	// Show exactly what run.sh contains, "$HERE" included: a README that
	// paraphrases the command it documents is a README that can drift from it.
	flags := pepFlags(cfg, ttsPub, policyHash,
		"\"$HERE/"+fileLogKey+"\"", "\"$HERE/"+bin+"-audit.jsonl\"")
	fence := mdFence(flags)
	fmt.Fprintf(&b, "which runs, exactly:\n\n%ssh\n%s \\\n%s\n%s\n\n", fence, bin, flags, fence)
	b.WriteString("`$HERE` is this directory. `run.sh` resolves it with `$(cd ... && pwd)` in a\n")
	b.WriteString("subshell and does **not** change its own working directory, so the PEP — and\n")
	b.WriteString("anything the PEP starts, which for MCP is the wrapped server — runs wherever\n")
	b.WriteString("its caller ran, and this directory is nobody's working directory.\n\n")
	switch cfg.Profile {
	case profileMCP:
		b.WriteString("An MCP client starts its servers itself, so point it at `run.sh` instead of at the\n")
		b.WriteString("wrapped server. In a `mcpServers` block:\n\n```json\n")
		fmt.Fprintf(&b, "{ \"mcpServers\": { \"guarded\": { \"command\": \"%s\" } } }\n", "<absolute path to this directory>/"+fileRunScript)
		b.WriteString("```\n\nThe PEP's diagnostics go to stderr; stdout carries the MCP protocol and nothing else.\n\n")
		b.WriteString("To see it enforce before any client is wired up:\n\n```sh\n./mint.sh\n```\n\n")
		b.WriteString("`mint.sh` mints under `cmd/mcp-mint`'s throwaway issuer, not under `issuer.key`, because\n")
		b.WriteString("`mcp-mint` cannot sign with an operator key, and it sets the server identity and\n")
		b.WriteString("audience on both sides from the same values. Its header says exactly what that does\n")
		b.WriteString("and does not prove.\n\n")
	case profileA2A:
		b.WriteString("There is no `mint.sh` for this profile. `cmd/mcp-mint` binds an MCP intent (tool name,\n")
		b.WriteString("arguments, server) and mints under its own throwaway key; an A2A token is bound to a\n")
		b.WriteString("message's parts, taskId and contextId, and nothing in this tree mints one from the\n")
		b.WriteString("command line. The proof that this deployment works is the first `message/send` your\n")
		b.WriteString("own TTS mints a token for, and the receipt it leaves in the audit log.\n\n")
	}

	b.WriteString("## What to do next\n\n")
	fmt.Fprintf(&b, "1. **Point your token issuer at `%s`.** The PEP verifies tokens against `%s`:\n", fileIssuerKey, fileIssuerPub)
	fmt.Fprintf(&b, "   a token has to be signed by the matching private key, carry `aud` %s, and\n", mdCode(cfg.Audience))
	fmt.Fprintf(&b, "   bind the exact call it authorizes. The snapshot records that key under issuer\n   %s, which is the `iss` a registry-backed verifier resolves it by.\n", mdCode(cfg.Issuer))
	b.WriteString("   Whatever mints your tokens holds the private key; the PEP does not.\n")
	fmt.Fprintf(&b, "2. **The PEP does not read the snapshot.** `run.sh` pins `%s` directly, and nothing\n", fileIssuerPub)
	fmt.Fprintf(&b, "   in `%s` or `%s` changes what it accepts. Those two files are for a\n", fileRegistry, fileManifest)
	b.WriteString("   verifier that resolves issuer keys from a trust registry — `cmd/agentsvc` is one,\n")
	fmt.Fprintf(&b, "   loading them with `%s` pinned — and for the day you trust a second issuer.\n", filePublicationPub)
	b.WriteString("   Check them as such a verifier would, from this directory:\n\n")
	fmt.Fprintf(&b, "   ```sh\n   snapshot verify -body %s -pub \"$(cat %s)\"\n   ```\n\n", fileRegistry, filePublicationPub)
	b.WriteString("3. **Re-sign before the snapshot goes stale,** if anything loads it. Verifiers refuse a\n")
	fmt.Fprintf(&b, "   snapshot older than their `max_age` (24h by default). From this directory:\n\n   ```sh\n   snapshot sign -registry %s -key %s \\\n       -id <new-id> -prev %s\n   ```\n\n", fileRegistry, filePublicationKey, snapshotID)
	b.WriteString("   `run.sh` is unaffected.\n")
	b.WriteString("4. **Keep the audit log.** Every decision is a signed receipt chained into\n")
	fmt.Fprintf(&b, "   `%s-audit.jsonl`. `cmd/receiptverify` checks a receipt; `cmd/auditverify` checks\n   the chain.\n", bin)
	b.WriteString("5. **Move the private keys somewhere better than a directory.** They were written 0600\n")
	b.WriteString("   into a 0700 directory, which is the floor. An HSM, KMS or OS keychain is where an\n")
	b.WriteString("   issuer key belongs once this is more than a first deployment.\n\n")

	b.WriteString("## Changing the configuration\n\n")
	b.WriteString("Do not edit `run.sh`: `policy.json` and the hash in every receipt would stop describing\n")
	b.WriteString("what is running. Run `spt-txn-init` again into a **new** directory — it refuses to\n")
	b.WriteString("overwrite this one — and start from there. A new run generates a new issuer keypair\n")
	b.WriteString("and a new policy hash, so tokens minted for this deployment do not verify at the new\n")
	b.WriteString("one, and your TTS has to move to the new `issuer.key`. That is the intended\n")
	b.WriteString("consequence of a policy change, not a fault. Delete this directory once nothing\n")
	b.WriteString("references it; its private keys are worth nothing to keep.\n\n")
	b.WriteString("If a run was killed outright (SIGKILL, power loss) it can leave a `.spt-txn-init-*`\n")
	b.WriteString("directory beside this one, holding keys nothing references. Ctrl-C and errors clean\n")
	b.WriteString("up after themselves; a hard kill cannot. Delete any such directory you find.\n\n")

	b.WriteString("## What this deployment does not have\n\n")
	b.WriteString("Being your own single issuer is a real posture, and this is what it does not give you.\n")
	b.WriteString("None of it is missing by accident; all of it is what a control plane is for.\n\n")
	b.WriteString("- **No revocation distribution.** If `issuer.key` is compromised, the way to stop its\n")
	b.WriteString("  tokens is to run `spt-txn-init` again (new directory, new key) and restart the PEP\n")
	b.WriteString("  from there. Until then, the PEP's `-max-token-ttl` (" + cfg.MaxTokenTTL.String() + ") is the longest any\n")
	b.WriteString("  single token stays good.\n")
	b.WriteString("- **No multi-issuer trust.** The snapshot names one `tts_issuer`. Trusting a second\n")
	b.WriteString("  issuer means adding its record to `registry.json` and re-signing; nothing here\n")
	b.WriteString("  federates or discovers issuers.\n")
	b.WriteString("- **No key-rotation service.** Rotation is a manual re-sign with `{old,new}` pinned\n")
	b.WriteString("  together during the overlap; nothing schedules it or pushes the new key to PEPs.\n")
	b.WriteString("- **No snapshot hosting or freshness feed.** The snapshot is a pair of files in this\n")
	b.WriteString("  directory. Getting a fresh one to every verifier on time is your job.\n")
	b.WriteString("- **No token issuer.** This directory holds the issuer's key; it does not run a TTS.\n")
	b.WriteString("  Something you operate has to mint tokens with `issuer.key`.\n")
	b.WriteString("- **No key custody.** Private keys are files. See step 5 above.\n\n")

	b.WriteString("## Never do this\n\n")
	fmt.Fprintf(&b, "Do not print, paste, screen-share or commit `%s`, `%s` or `%s`. The project's own\n", fileIssuerKey, fileLogKey, filePublicationKey)
	b.WriteString("demo runsheet forbids opening key files on camera, and `spt-txn-init` itself never\n")
	b.WriteString("writes a private key to its output for the same reason. The `.key` suffix is\n")
	b.WriteString("gitignored in `spt-txn-poc`; keep it that way in your own repositories.\n\n")
	fmt.Fprintf(&b, "Public values, safe to share:\n\n- issuer public key: `%s`\n- publication public key: `%s`\n- policy hash: `%s`\n- snapshot id: `%s`\n", ttsPub, pubPub, policyHash, snapshotID)
	return b.String()
}

// printSummary is the only thing written to stdout after generation. It names
// files and prints public values; it never prints a private key, and the test
// TestGenerate_NoPrivateKeyMaterialOnStdout holds it to that.
func (r *result) printSummary(w io.Writer) {
	fmt.Fprintf(w, "\nspt-txn-init: %s deployment written to %s\n\n", strings.ToUpper(r.Profile), r.OutDir)
	for _, f := range r.Files {
		tag := "        "
		if f.Private {
			tag = "PRIVATE "
		}
		fmt.Fprintf(w, "  %s%-30s %s\n", tag, f.Name, f.What)
	}
	if r.IssuerKeyPath != "" {
		fmt.Fprintf(w, "\n  PRIVATE %-30s the issuer (tts) signing key, placed BESIDE the\n", filepath.Base(r.IssuerKeyPath))
		fmt.Fprintf(w, "          %-30s deployment, not in it. Your TTS mints with it;\n", "")
		fmt.Fprintf(w, "          %-30s nothing in the deployment reads it. Move it to\n", "")
		fmt.Fprintf(w, "          %-30s wherever your issuer runs, or into a PKCS#11\n", "")
		fmt.Fprintf(w, "          %-30s token, and re-run with -tts-pub next time.\n", "")
	}
	fmt.Fprintf(w, "\n  issuer public key      %s\n", r.TTSPubHex)
	fmt.Fprintf(w, "  publication public key %s\n", r.PublicationPubHex)
	fmt.Fprintf(w, "  snapshot id            %s\n", r.SnapshotID)
	fmt.Fprintf(w, "  policy hash            %s\n", r.PolicyHash)
	fmt.Fprintf(w, "\nThe snapshot was signed and then verified with pkg/trustsnapshot.Verify.\n")
	fmt.Fprintf(w, "Private keys are 0600, the deployment is 0700, and none was printed.\n")
	fmt.Fprintf(w, "\nStart the enforcement point:\n\n  %s\n\n", r.RunCommand)
	fmt.Fprintf(w, "Read %s first.\n", filepath.Join(r.OutDir, fileREADME))
}
