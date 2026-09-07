// Command a2a-pep is the SPT-Txn A2A policy-enforcement point as a runnable
// HTTP proxy -- the A2A form factor of the gateway profiles in
// docs/spec/GATEWAY-PROFILES.md, and the sibling of cmd/mcp-pep.
//
// It sits in front of an Agent2Agent agent. Every message/send must present a
// transaction-scoped SPT-Txn token in params.message.metadata["spt-txn/token"]
// whose intent binding matches the message being delivered: its parts, its
// taskId and its contextId. A prompt-injected or hijacked send -- different
// content, redirected task, a token minted for another agent -- is denied
// before the wrapped agent sees it, and a signed receipt is written for every
// decision, permit or deny.
//
// # What this process holds
//
// No signing keys for authorization, and no custody of anything it authorizes.
// One PUBLIC key (the TTS issuer's, to verify presented tokens) and one log key
// (to sign receipts, which is evidence, not authority). It cannot mint a token,
// it cannot move value, and it is not in the settlement path.
//
// # Two transport-level properties that the middleware cannot provide
//
// internal/a2apep strips the credential out of the JSON-RPC body. That is not
// sufficient at this layer, and both gaps are closed here:
//
//   - No client header is copied upstream. Stripping the token from the body
//     and then forwarding the caller's Authorization or Cookie would hand the
//     wrapped agent a different credential for the same caller: the same
//     confused-deputy hole, one layer down (docs/THREAT-MODEL.md 4.6).
//
//   - The relayed agent card is rewritten to advertise this PEP. An agent card
//     names the endpoint clients should talk to. Relaying the wrapped agent's
//     card unmodified would publish the address of the agent BEHIND the
//     enforcement point, so the first thing any compliant client does with the
//     card is take the bypass. Card relay is therefore OFF unless -public-url
//     says what to advertise instead. Both card dialects (A2A v0.3.0 `url`,
//     A2A v1.0 `supportedInterfaces`) are rewritten, a card in neither is
//     refused, and any JWS signature over the upstream card is stripped
//     because the rewrite invalidates it (see rewriteCard).
//
// # Why this binary exists
//
// internal/a2apep was an enforcement point with no way to run it. This wires it
// to a real HTTP transport without adding trust-boundary code: every
// authorization check still happens in decision.Engine and internal/a2apep.
//
//	a2a-pep -listen :8402 \
//	        -upstream http://127.0.0.1:9000/ \
//	        -public-url https://guarded.example/ \
//	        -agent-identity a2a://payments.example \
//	        -audience payments.example \
//	        -tts-pub <hex> -log-key-file log.key -policy-hash <hash>
//
// # Known duplication
//
// buildEngine, missingRequired and parseHexKey are near-copies of cmd/mcp-pep's.
// They belong in one package and will move there. They have not moved yet
// because scripts/mutate-mcp-pep-transport.sh anchors two mutations (M-I, M-J)
// on those exact lines in cmd/mcp-pep/main.go, and relocating them silently
// would leave that script reporting "killed" for mutations it no longer applies
// to the code that runs. The extraction is a change to BOTH binaries and their
// mutation scripts together, not a tidy-up to slip in beside a new feature.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/a2apep"
	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
)

// maxMessageBytes bounds a single JSON-RPC body in either direction. An
// unbounded read on a socket an adversary can write to is a memory-exhaustion
// primitive; A2A messages carrying inline file parts are large but not this
// large.
const maxMessageBytes = 4 << 20

// defaultCardPath is where RFC 8615 says an agent card lives.
const defaultCardPath = "/.well-known/agent-card.json"

func main() {
	pepName := flag.String("pep", "a2a-pep.spt-txn", "PEP identity (trust registry name)")
	listen := flag.String("listen", ":8402", "address to listen on")
	upstream := flag.String("upstream", "",
		"JSON-RPC endpoint of the wrapped A2A agent, e.g. http://127.0.0.1:9000/ (required)")
	publicURL := flag.String("public-url", "",
		"the URL clients reach THIS PEP on. Required to relay the wrapped agent's card: "+
			"the relayed card is rewritten to advertise this address, because a card that "+
			"still names the agent behind the PEP is a published bypass.")
	agentIdentity := flag.String("agent-identity", "",
		"identity of the wrapped agent -- the intent `target`. A token minted for another "+
			"agent MUST NOT verify here (required).")
	rpcPath := flag.String("rpc-path", "/", "the single path that accepts JSON-RPC")
	cardPath := flag.String("card-path", defaultCardPath, "path the agent card is served on")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "a2a-pep-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	audience := flag.String("audience", "",
		"executing-domain identity this PEP answers for, matched against the token's aud "+
			"(required). Distinct from -pep (a registry identity) and -agent-identity (a "+
			"resource): this is the domain the token was minted FOR.")
	maxTTL := flag.Duration("max-token-ttl", 60*time.Second,
		"longest remaining token lifetime this PEP accepts. An A2A PEP does not walk the "+
			"chain, so this IS the revocation latency (GATEWAY-PROFILES.md 1.1).")
	upstreamTimeout := flag.Duration("upstream-timeout", 30*time.Second,
		"how long to wait for the wrapped agent to answer")
	flag.Parse()

	if missing := missingRequired(*upstream, *agentIdentity, *audience, *ttsPubHex,
		*logKeyFile, *policyHash); len(missing) > 0 {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\nnot set: %s\n", strings.Join(missing, ", "))
		fmt.Fprintln(os.Stderr, "Each of these must be set explicitly. This PEP has no mode that "+
			"skips verification, and no default that would let it answer for any audience: an "+
			"empty expected audience matches a token that omits aud, so a PEP configured by "+
			"omission would accept tokens minted for any domain.")
		os.Exit(2)
	}

	upURL, err := validateAbsoluteURL(*upstream)
	if err != nil {
		log.Fatalf("upstream: %v", err)
	}
	if *publicURL != "" {
		if _, err := validateAbsoluteURL(*publicURL); err != nil {
			log.Fatalf("public-url: %v", err)
		}
	}

	engine, closeAudit, err := buildEngine(pepConfig{
		pepName:      *pepName,
		ttsPubHex:    *ttsPubHex,
		logKeyFile:   *logKeyFile,
		auditPath:    *auditPath,
		policyHash:   *policyHash,
		jurisdiction: *jurisdiction,
		audience:     *audience,
		maxTTL:       *maxTTL,
	})
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer closeAudit()

	p := &proxy{
		rpcPath:   *rpcPath,
		cardPath:  *cardPath,
		publicURL: *publicURL,
		upstream:  upURL.String(),
		cardURL:   upURL.Scheme + "://" + upURL.Host + *cardPath,
		client:    newUpstreamClient(*upstreamTimeout),
	}

	mw, err := a2apep.New(engine, *agentIdentity, p.forward)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}
	p.mw = mw

	srv := &http.Server{
		Addr:              *listen,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 16,
	}

	fmt.Fprintf(os.Stderr, "spt-txn a2a-pep ready on %s -- guarding %s as %q, audience %q\n",
		*listen, upURL.Redacted(), *agentIdentity, *audience)
	if *publicURL == "" {
		fmt.Fprintf(os.Stderr, "agent card relay is OFF (no -public-url): %s returns 404 rather "+
			"than handing clients the address of the agent behind this PEP\n", *cardPath)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// handler is the enforcement surface the transport drives. It is an interface
// rather than the concrete *a2apep.Middleware for one reason: the nil-response
// branch below is unreachable through the real middleware, and a branch that
// cannot be reached in a test is a branch that cannot be shown to work.
type handler interface {
	Handle(ctx context.Context, raw []byte) []byte
}

// proxy is the HTTP transport.
type proxy struct {
	mw        handler
	rpcPath   string
	cardPath  string
	publicURL string // "" disables card relay
	upstream  string
	cardURL   string
	client    *http.Client
}

// ServeHTTP routes exactly two requests and refuses everything else.
//
// An enforcement point that proxies whatever it is given is a general-purpose
// proxy with an authorization check bolted to one of its paths. Only POST on
// the JSON-RPC path and GET on the card path exist here; there is no default
// branch that forwards.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == p.rpcPath:
		p.serveRPC(w, r)
	case r.Method == http.MethodGet && r.URL.Path == p.cardPath:
		p.serveCard(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveRPC runs one JSON-RPC message through the enforcement point.
//
// A denial is HTTP 200 carrying a JSON-RPC error, not an HTTP 4xx. The refusal
// is uniform on purpose (internal/a2apep returns one message for every failing
// check), and answering with a distinguishable status code would put back the
// oracle the uniform body exists to remove.
func (p *proxy) serveRPC(w http.ResponseWriter, r *http.Request) {
	if !isJSON(r.Header.Get("Content-Type")) {
		http.Error(w, "expected Content-Type: application/json", http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageBytes))
	if err != nil {
		http.Error(w, "unreadable or oversize request body", http.StatusBadRequest)
		return
	}

	resp := p.mw.Handle(r.Context(), raw)
	if resp == nil {
		// Handle's contract is that a request always produces a response and
		// only notifications produce none. This is belt-and-braces on that
		// contract rather than a check the PEP relies on: if a future change
		// ever returned nil for a request, an empty 204 would look to the
		// caller like success rather than a refusal.
		id, isRequest := rpcID(raw)
		if !isRequest {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		resp = denial(id)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// forward delivers a request to the wrapped agent under the dialect the
// middleware classified it as.
func (p *proxy) forward(ctx context.Context, raw []byte, dialect a2apep.Dialect) ([]byte, error) {
	// A2A-Version tells the wrapped agent which protocol semantics to parse
	// the body under. It is set from the middleware's classification of the
	// METHOD NAME and from nothing else. The caller's own A2A-Version header is
	// not consulted, like every other caller header: a version the caller
	// chose would let the caller have the agent parse an authorized body under
	// semantics the PEP did not check it against. Only the two values the
	// middleware can produce are sent; anything else is a bug upstream of
	// here, and the request is refused rather than sent unversioned, because
	// the reference server treats an absent header as 0.3 and would parse a
	// v1.0 body wrong rather than reject it.
	switch dialect {
	case a2apep.DialectV03, a2apep.DialectV1:
	default:
		return nil, fmt.Errorf("a2a-pep: refusing to forward under unknown dialect %q", dialect)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	// Only headers this PEP sets. The caller's headers are deliberately NOT
	// copied: the middleware strips the SPT-Txn credential out of the body, and
	// forwarding the caller's Authorization or Cookie would hand the wrapped
	// agent a different credential for the same caller.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("A2A-Version", string(dialect))

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if isEventStream(resp.Header.Get("Content-Type")) {
		return nil, errors.New("a2a-pep: the wrapped agent answered with a stream. This PEP " +
			"authorizes discrete message/send calls; relaying a stream would return content " +
			"the enforcement point never saw")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("a2a-pep: wrapped agent returned %s", resp.Status)
	}
	return body, nil
}

// serveCard relays the wrapped agent's card, rewritten to advertise this PEP.
func (p *proxy) serveCard(w http.ResponseWriter, r *http.Request) {
	if p.publicURL == "" {
		http.Error(w, "agent card relay is disabled: start a2a-pep with -public-url so the "+
			"relayed card advertises this PEP rather than the agent behind it",
			http.StatusNotFound)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.cardURL, nil)
	if err != nil {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageBytes))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	rewritten, rep, err := rewriteCard(body, p.publicURL)
	if err != nil {
		// The reason goes to the operator's log, not to the caller: the error
		// names card members, and the caller has no business learning the
		// shape of a card this PEP refused to publish.
		log.Printf("agent card: refusing to relay: %v", err)
		http.Error(w, "upstream agent card cannot be relayed", http.StatusBadGateway)
		return
	}
	if rep.DroppedInterfaces > 0 {
		// Every relay, not once: a persistent misconfiguration deserves a
		// persistent complaint, and a discovery endpoint is not a hot path.
		log.Printf("agent card: dropped %d interface entry/entries (v0.3.0 "+
			"additionalInterfaces, or v1.0 supportedInterfaces on a binding other than "+
			"JSONRPC). Clients can no longer discover those transports through this PEP, "+
			"which does not enforce them. If they must stay reachable, put a PEP in front "+
			"of them; do not re-advertise a route this one cannot guard.",
			rep.DroppedInterfaces)
	}
	if rep.StrippedSignatures > 0 {
		log.Printf("agent card: stripped %d JWS signature(s). The relayed card is rewritten "+
			"and the upstream signature no longer covers it; it is relayed unsigned rather "+
			"than carrying a signature that does not verify. Clients that require a signed "+
			"card will refuse this one until the PEP is given a signing key of its own.",
			rep.StrippedSignatures)
	}
	if len(rep.DroppedMembers) > 0 {
		log.Printf("agent card: dropped member(s) %s. Each carries a URL, an authentication "+
			"scheme, or a reference to one, that this PEP cannot vouch for or does not honour "+
			"(no client header reaches the wrapped agent, so its security schemes are not how a "+
			"caller authenticates here; the relayed card is deliberately silent on auth, see "+
			"docs/spec/DELEGATION-INTENT-A2A.md 6.1). If a link must be advertised, publish it "+
			"from the PEP's own documentation, not through the card of the agent behind it.",
			strings.Join(rep.DroppedMembers, ", "))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(rewritten)
}

// cardRewrite reports what rewriteCard removed from the relayed card. Every
// field exists for one reason: removing something from a discovery document
// silently is the same defect as publishing something that should not be
// there, facing the other way. The caller tells the operator.
type cardRewrite struct {
	// DroppedInterfaces is the number of upstream interface entries that are
	// not re-advertised: every v0.3.0 additionalInterfaces entry, and every
	// v1.0 supportedInterfaces entry whose protocolBinding is not JSONRPC.
	DroppedInterfaces int
	// StrippedSignatures is the number of entries removed from the card's
	// top-level signatures array.
	StrippedSignatures int
	// DroppedMembers names the recognised-but-not-relayed members that were
	// present (see droppedCardMembers and capabilities.extensions).
	DroppedMembers []string
}

// allowedCardMembers is the AgentCard surface of A2A v0.3.0 and v1.0 together.
// It is an ALLOWLIST, matched exactly and case-sensitively: a member outside it
// is refused and the card is not relayed.
//
// The earlier version of this function knew five members and relayed every
// other member verbatim. That is a denylist, and it failed the way denylists
// fail: a card carrying the upstream address under a name the function had not
// thought of -- "endpoint", or simply "Url", which Go's encoding/json decodes
// into a `json:"url"` field because struct-tag matching is case-insensitive --
// relayed the address with nothing dropped and nothing logged. Exact-case
// membership closes both at once: "Url" is not "url", so it is unrecognised, so
// the card is refused.
var allowedCardMembers = map[string]bool{
	// Both dialects.
	"name": true, "description": true, "version": true, "provider": true,
	"iconUrl": true, "documentationUrl": true, "capabilities": true,
	"securitySchemes": true, "defaultInputModes": true, "defaultOutputModes": true,
	"skills": true, "signatures": true,
	// v0.3.0.
	"protocolVersion": true, "url": true, "preferredTransport": true,
	"additionalInterfaces": true, "security": true, "supportsAuthenticatedExtendedCard": true,
	// v1.0.
	"supportedInterfaces": true, "securityRequirements": true,
}

// droppedCardMembers are recognised members that are removed rather than
// relayed, and named in the report so the operator sees it.
//
//   - iconUrl, documentationUrl, provider (whose url is REQUIRED in v1.0):
//     informational URLs. Nothing in the protocol dials them, but nothing stops
//     an operator hosting them on the agent, at which point the relayed card
//     names the host this PEP exists to hide. The PEP cannot tell a public
//     documentation site from the agent's own host without a denylist of hosts,
//     so it relays neither. The cost is cosmetic: an icon and two links.
//   - securitySchemes, security, securityRequirements: the wrapped agent's
//     authentication schemes, which carry OAuth and OIDC endpoint URLs. Through
//     this PEP they are not how a caller authenticates -- no client header
//     reaches the wrapped agent (see forward), and the credential this PEP
//     checks travels in the message body -- so advertising them would describe
//     an authentication path that does not work here, at addresses that may
//     be the agent's. Dropped for honesty as much as for hygiene.
//
// skills, defaultInputModes, defaultOutputModes, name, description, version and
// protocolVersion are relayed as-is: in both dialects' schemas they are free
// text, identifiers and media types, with no URL-typed member. A future schema
// that adds one is a reason to revisit this list, not a case it silently
// handles.
var droppedCardMembers = []string{
	"iconUrl", "documentationUrl", "provider",
	"securitySchemes", "security", "securityRequirements",
}

// cardKind is the JSON type a relayed card member must have. Name-checking a
// member and relaying its value untyped is a denylist on shape: an object where
// a boolean belongs carries whatever it likes, including the upstream address,
// and "streaming":{"u":"http://agent.internal/"} relayed cleanly under a
// name-only allowlist. Every member relayed as-is is typed against the schemas
// of both dialects (@a2a-js/sdk 0.3.0 and 1.0.0 type definitions).
type cardKind int

const (
	kindString cardKind = iota
	kindBool
	kindStringArray
	kindObject      // members typed by cardMember.schema; unknown members refused
	kindObjectArray // array of kindObject
	kindHandled     // rewritten, stripped or dropped by dedicated code above
)

type cardMember struct {
	kind   cardKind
	schema map[string]cardMember // kindObject and kindObjectArray only
}

// skillSchema is AgentSkill in both dialects. security (v0.3.0) and
// securityRequirements (v1.0) reference scheme names defined by the top-level
// securitySchemes, which is dropped; a reference to a definition that is gone
// is dropped with it (see droppedSkillMembers) rather than relayed dangling.
var skillSchema = map[string]cardMember{
	"id": {kind: kindString}, "name": {kind: kindString}, "description": {kind: kindString},
	"tags": {kind: kindStringArray}, "examples": {kind: kindStringArray},
	"inputModes": {kind: kindStringArray}, "outputModes": {kind: kindStringArray},
	"security": {kind: kindHandled}, "securityRequirements": {kind: kindHandled},
}

// droppedSkillMembers are removed from every skill and reported once.
var droppedSkillMembers = []string{"security", "securityRequirements"}

// capabilitiesSchema is AgentCapabilities in both dialects. extensions is
// recognised and dropped: each entry carries a uri and a free-form params
// object, and extensions are negotiated through the A2A-Extensions header,
// which this PEP does not forward, so advertising them describes a negotiation
// that cannot happen here.
var capabilitiesSchema = map[string]cardMember{
	"streaming": {kind: kindBool}, "pushNotifications": {kind: kindBool},
	"stateTransitionHistory": {kind: kindBool}, "extendedAgentCard": {kind: kindBool},
	"extensions": {kind: kindHandled},
}

// cardSchema types every member of allowedCardMembers. The two maps are kept
// in step by TestCardSchemaCoversEveryAllowedMember; a member allowed but not
// typed would be relayed untyped, which is the defect this exists to end.
var cardSchema = map[string]cardMember{
	// Relayed as typed values.
	"name":                              {kind: kindString},
	"description":                       {kind: kindString},
	"version":                           {kind: kindString},
	"protocolVersion":                   {kind: kindString},
	"preferredTransport":                {kind: kindString},
	"supportsAuthenticatedExtendedCard": {kind: kindBool},
	"defaultInputModes":                 {kind: kindStringArray},
	"defaultOutputModes":                {kind: kindStringArray},
	"capabilities":                      {kind: kindObject, schema: capabilitiesSchema},
	"skills":                            {kind: kindObjectArray, schema: skillSchema},
	// Rewritten, stripped or dropped by name below.
	"url":                  {kind: kindHandled},
	"additionalInterfaces": {kind: kindHandled},
	"supportedInterfaces":  {kind: kindHandled},
	"signatures":           {kind: kindHandled},
	"iconUrl":              {kind: kindHandled},
	"documentationUrl":     {kind: kindHandled},
	"provider":             {kind: kindHandled},
	"securitySchemes":      {kind: kindHandled},
	"security":             {kind: kindHandled},
	"securityRequirements": {kind: kindHandled},
}

// allowedKeys derives a ScanObject allowlist from a schema.
func allowedKeys(schema map[string]cardMember) map[string]bool {
	out := make(map[string]bool, len(schema))
	for k := range schema {
		out[k] = true
	}
	return out
}

// checkTyped verifies that raw has the JSON type m demands, recursing into
// objects. kindHandled members are not checked here; the dedicated code that
// handles them checks what it needs. null is not any of these types: a member
// that is present is present with a value, and a null where an object belongs
// is refused like an array where an object belongs.
func checkTyped(raw json.RawMessage, m cardMember, path string) error {
	switch m.kind {
	case kindHandled:
		return nil
	case kindString:
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("a2a-pep: agent card %s is not a string", path)
		}
	case kindBool:
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("a2a-pep: agent card %s is not a boolean", path)
		}
	case kindStringArray:
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil || !startsWith(raw, '[') {
			return fmt.Errorf("a2a-pep: agent card %s is not an array of strings", path)
		}
	case kindObject:
		if err := a2apep.ScanObject(raw, allowedKeys(m.schema), "agent card "+path); err != nil {
			return err
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return fmt.Errorf("a2a-pep: agent card %s is not an object", path)
		}
		for k, v := range members {
			if err := checkTyped(v, m.schema[k], path+"."+k); err != nil {
				return err
			}
		}
	case kindObjectArray:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || !startsWith(raw, '[') {
			return fmt.Errorf("a2a-pep: agent card %s is not an array", path)
		}
		for i, item := range items {
			if err := checkTyped(item, cardMember{kind: kindObject, schema: m.schema},
				fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("a2a-pep: agent card %s has no schema kind", path)
	}
	return nil
}

// startsWith reports whether the first non-space byte of raw is c. Unmarshal
// accepts null for a slice; a member that is present must be the array it
// claims to be.
func startsWith(raw json.RawMessage, c byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == c
}

// knownProtocolVersions are the A2A-Version values this PEP can forward under
// (a2apep.DialectV03, a2apep.DialectV1). A JSONRPC interface advertising any
// other version is dropped and counted like a foreign binding: the PEP sets
// A2A-Version from the method spelling it recognised, so an entry promising a
// version it does not speak would route every call into a version mismatch at
// the agent, each one costing the caller a single-use token.
var knownProtocolVersions = map[string]bool{
	string(a2apep.DialectV03): true,
	string(a2apep.DialectV1):  true,
}

// allowedInterfaceMembers is the A2A v1.0 AgentInterface surface. A JSONRPC
// entry carrying a member outside it is refused: this function re-advertises
// an interface by constructing a fresh entry from members it understands, and
// a member it does not understand may be one more place an address lives.
var allowedInterfaceMembers = map[string]bool{
	"url": true, "protocolBinding": true, "protocolVersion": true, "tenant": true,
}

// rewriteCard makes the relayed agent card point at the PEP.
//
// This is not cosmetic. An agent card names the endpoint clients should talk
// to, so relaying the wrapped agent's card unmodified publishes the address of
// the agent BEHIND the enforcement point and the first thing any compliant
// client does with it is take the bypass.
//
// The card is held to the same discipline as a request: every top-level member
// must be on allowedCardMembers (exact case; duplicates refused), every member
// relayed as-is must have the JSON type both dialects' schemas give it
// (cardSchema; an object where a boolean belongs is refused, because a value of
// the wrong type is a container for anything), members that carry URLs or
// authentication are handled by name, and anything the function does not
// recognise is an error, never a passthrough. The version of this
// function that handled only v0.3.0 found nothing to rewrite in a v1.0 card,
// reported nothing dropped, and relayed `supportedInterfaces` untouched;
// silence was the defect, and this is the shape that makes silence impossible.
//
// Two card dialects name the endpoint, and both are handled. A2A v0.3.0 names
// it in `url` (with `preferredTransport` and `additionalInterfaces` beside it);
// A2A v1.0 removed all three and names every endpoint in one ordered array,
// `supportedInterfaces`, whose entries carry `url`, `protocolBinding` and
// `protocolVersion`. A card that carries neither names no endpoint this
// function can rewrite, and is refused.
//
// v0.3.0: `url` is replaced and `additionalInterfaces` is dropped entirely
// rather than rewritten. Every entry is a second address on a transport this
// PEP does not enforce at all -- a gRPC interface cannot be pointed at a
// JSON-RPC proxy, and keeping it would advertise a bypass that happens to look
// authorized. An operator who needs those transports guarded needs a PEP for
// those transports, not a card that implies one exists.
//
// v1.0: the same policy, applied per entry. Every entry whose protocolBinding
// is exactly "JSONRPC" and whose protocolVersion is one this PEP forwards under
// ("0.3" or "1.0", see knownProtocolVersions) is re-advertised at the PEP, as a
// fresh entry carrying the PEP's url, the binding, and that protocolVersion
// unchanged. The version matters beyond honesty: the reference client sets
// A2A-Version from the protocolVersion of the entry it selected, and this PEP
// sets A2A-Version on the forwarded request from the method spelling it
// recognised, so an entry promising a version the PEP does not speak would
// route every call into a mismatch at the agent -- each one, since the permit
// is recorded before the forward, costing the caller a single-use token. Every
// entry on any other binding or version is dropped and counted. A JSONRPC entry that names a `tenant` is refused: v1.0
// requires clients to echo it in every request and this PEP forwards no such
// member, so the interface cannot be honestly advertised through it. A card
// with no JSONRPC entry at all is refused for the same reason -- advertising
// one would claim an interface the agent did not.
//
// `signatures` is stripped, and counted. v1.0 lets a card carry detached JWS
// signatures (RFC 7515) over its RFC 8785 canonical form, and this function
// changes that form, so any upstream signature no longer verifies against what
// is relayed. Three options exist. Leaving the signature is the worst: a client
// that verifies will reject the card (relay is then simply broken) and a
// client that only checks for presence will trust a card whose signature is
// stale -- a card that looks authenticated and is not. Re-signing as the PEP
// is the right eventual answer, since the PEP IS the authority for the
// endpoint it advertises, but it requires a PEP signing key, its rotation,
// and the field-presence canonicalisation the A2A signing profile layers on
// top of JCS, none of which this binary has. Stripping is the honest middle:
// the relayed card is unsigned, says so by carrying no signature, and a client
// that requires signatures refuses it for the true reason.
//
// It returns what it removed, because removing silently is the same defect as
// publishing silently, facing the other way. A value that should be an array
// but is not (additionalInterfaces, supportedInterfaces, signatures) is refused
// rather than deleted: the count is the whole point, and a value that cannot be
// counted cannot be reported.
func rewriteCard(card []byte, publicURL string) ([]byte, cardRewrite, error) {
	var rep cardRewrite
	if err := a2apep.ScanObject(card, allowedCardMembers, "agent card"); err != nil {
		return nil, rep, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(card, &obj); err != nil {
		return nil, rep, err
	}
	if obj == nil {
		return nil, rep, errors.New("a2a-pep: agent card is null")
	}
	for name, raw := range obj {
		if err := checkTyped(raw, cardSchema[name], name); err != nil {
			return nil, rep, err
		}
	}
	enc, err := json.Marshal(publicURL)
	if err != nil {
		return nil, rep, err
	}

	_, hasURL := obj["url"]
	rawInterfaces, hasInterfaces := obj["supportedInterfaces"]
	if !hasURL && !hasInterfaces {
		return nil, rep, errors.New("a2a-pep: agent card names no endpoint this PEP can rewrite: " +
			"neither a v0.3.0 url nor a v1.0 supportedInterfaces array is present")
	}

	// Members recognised and removed by name.
	for _, name := range droppedCardMembers {
		if _, ok := obj[name]; ok {
			rep.DroppedMembers = append(rep.DroppedMembers, name)
			delete(obj, name)
		}
	}
	if raw, ok := obj["capabilities"]; ok {
		// Typed and allowlisted by checkTyped above; only the drop remains.
		var caps map[string]json.RawMessage
		if err := json.Unmarshal(raw, &caps); err != nil {
			return nil, rep, err
		}
		if _, ok := caps["extensions"]; ok {
			rep.DroppedMembers = append(rep.DroppedMembers, "capabilities.extensions")
			delete(caps, "extensions")
			b, err := json.Marshal(caps)
			if err != nil {
				return nil, rep, err
			}
			obj["capabilities"] = b
		}
	}
	if raw, ok := obj["skills"]; ok {
		var skills []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &skills); err != nil {
			return nil, rep, err
		}
		dropped := map[string]bool{}
		for _, sk := range skills {
			for _, name := range droppedSkillMembers {
				if _, ok := sk[name]; ok {
					dropped[name] = true
					delete(sk, name)
				}
			}
		}
		if len(dropped) > 0 {
			for _, name := range droppedSkillMembers {
				if dropped[name] {
					rep.DroppedMembers = append(rep.DroppedMembers, "skills[]."+name)
				}
			}
			b, err := json.Marshal(skills)
			if err != nil {
				return nil, rep, err
			}
			obj["skills"] = b
		}
	}

	// v0.3.0. additionalInterfaces is handled whether or not url is present:
	// a card is rewritten member by member, and an address-bearing member left
	// alone because a sibling was absent is the leak this function exists to
	// close.
	if raw, ok := obj["additionalInterfaces"]; ok {
		var alts []json.RawMessage
		if err := json.Unmarshal(raw, &alts); err != nil {
			return nil, rep, fmt.Errorf("a2a-pep: agent card additionalInterfaces is present but is not an array: %w", err)
		}
		rep.DroppedInterfaces += len(alts)
	}
	if hasURL {
		obj["url"] = enc
	}
	if _, ok := obj["preferredTransport"]; ok || hasURL {
		// Always JSONRPC when it appears at all: it is not an address, but a
		// transport name the PEP does not serve would send a v0.3.0 client
		// looking for one, whether or not a url sits beside it.
		obj["preferredTransport"] = json.RawMessage(`"JSONRPC"`)
	}
	delete(obj, "additionalInterfaces")

	// v1.0.
	if hasInterfaces {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(rawInterfaces, &entries); err != nil {
			return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces is present but is not an array of objects: %w", err)
		}
		kept := make([]json.RawMessage, 0, len(entries))
		for i, e := range entries {
			if e == nil {
				return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces[%d] is null", i)
			}
			var binding string
			if err := json.Unmarshal(e["protocolBinding"], &binding); err != nil {
				return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces[%d] has no string protocolBinding: %w", i, err)
			}
			if binding != "JSONRPC" {
				rep.DroppedInterfaces++
				continue
			}
			for k := range e {
				if !allowedInterfaceMembers[k] {
					return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces[%d] carries unrecognised member %q", i, k)
				}
			}
			if _, ok := e["tenant"]; ok {
				return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces[%d] names a tenant, which this PEP does not forward", i)
			}
			// Typed, like its sibling: a "fresh entry from members this
			// function understands" cannot carry an object it never read.
			// REQUIRED in v1.0, so absent is malformed and refused; present
			// but a version this PEP does not forward under is a foreign
			// interface, dropped and counted (see knownProtocolVersions).
			var version string
			if err := json.Unmarshal(e["protocolVersion"], &version); err != nil {
				return nil, rep, fmt.Errorf("a2a-pep: agent card supportedInterfaces[%d] protocolVersion is absent or not a string", i)
			}
			if !knownProtocolVersions[version] {
				rep.DroppedInterfaces++
				continue
			}
			entry := map[string]json.RawMessage{
				"url":             enc,
				"protocolBinding": json.RawMessage(`"JSONRPC"`),
				"protocolVersion": e["protocolVersion"],
			}
			b, err := json.Marshal(entry)
			if err != nil {
				return nil, rep, err
			}
			kept = append(kept, b)
		}
		if len(kept) == 0 {
			return nil, rep, errors.New("a2a-pep: agent card supportedInterfaces has no JSONRPC entry; " +
				"this PEP will not advertise an interface the agent did not")
		}
		b, err := json.Marshal(kept)
		if err != nil {
			return nil, rep, err
		}
		obj["supportedInterfaces"] = b
	}

	if raw, ok := obj["signatures"]; ok {
		var sigs []json.RawMessage
		if err := json.Unmarshal(raw, &sigs); err != nil {
			return nil, rep, fmt.Errorf("a2a-pep: agent card signatures is present but is not an array: %w", err)
		}
		rep.StrippedSignatures = len(sigs)
		delete(obj, "signatures")
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, rep, err
	}
	return out, rep, nil
}

// newUpstreamClient builds the client used for both the agent and its card.
//
// Redirects are refused rather than followed. A proxy that follows a redirect
// can be pointed at a host the operator never configured, which would send a
// request the PEP has just authorized for one agent to a different one.
func newUpstreamClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("a2a-pep: the wrapped agent redirected. Following it would send " +
				"an authorized request to a host the operator never configured")
		},
	}
}

// isJSON reports whether ct is exactly the JSON media type, parameters aside.
func isJSON(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// isEventStream reports whether ct announces Server-Sent Events.
func isEventStream(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "text/event-stream"
}

// validateAbsoluteURL rejects anything that is not an absolute http(s) endpoint.
//
// It guards BOTH -upstream and -public-url. -public-url was previously taken on
// trust and marshalled straight into the relayed card, which made the weakest
// link the one value whose entire purpose is to be an address clients dial: a
// typo published a broken endpoint to every client that fetched the card. The
// whole argument for requiring the operator to state it (rather than
// reconstructing it from forwarded headers) is that a stated value is
// trustworthy. That only holds if it is checked.
func validateAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("want an http or https URL, got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", raw)
	}
	return u, nil
}

// rpcID extracts a usable JSON-RPC id, reporting whether this was a request
// (as opposed to a notification, which is answered with nothing).
func rpcID(raw []byte) (json.RawMessage, bool) {
	var m struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	if len(m.ID) == 0 || string(bytes.TrimSpace(m.ID)) == "null" {
		return nil, false
	}
	return m.ID, true
}

// denial is the same uniform refusal internal/a2apep puts on the wire: the
// failing check stays in the receipt, not in the error the caller reads.
func denial(id json.RawMessage) []byte {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": a2apep.CodeDenied, "message": "spt-txn: denied"},
	})
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"spt-txn: denied"}}`)
	}
	return b
}

// pepConfig is the resolved startup configuration.
type pepConfig struct {
	pepName      string
	ttsPubHex    string
	logKeyFile   string
	auditPath    string
	policyHash   string
	jurisdiction string
	audience     string
	maxTTL       time.Duration
}

// buildEngine loads the key material and assembles the decision core. Every
// failure here is a startup failure by design: there is no verification-less
// mode and no evidence-less mode to fall back to, so a bad key, an unreadable
// key file or an unopenable audit log must stop the process rather than produce
// a PEP that answers anyway. It returns a closer for the audit log.
func buildEngine(c pepConfig) (*decision.Engine, func() error, error) {
	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("tts-pub: %w", err)
	}
	logKeyHex, err := os.ReadFile(c.logKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("log-key-file: %w", err)
	}
	logKey, err := parseHexKey(string(bytes.TrimSpace(logKeyHex)), ed25519.PrivateKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("log key: %w", err)
	}
	auditLog, err := audit.Open(c.auditPath)
	if err != nil {
		return nil, nil, fmt.Errorf("audit log: %w", err)
	}
	emitter, err := receiptlog.NewLogEmitter(auditLog, ed25519.PrivateKey(logKey))
	if err != nil {
		auditLog.Close()
		return nil, nil, fmt.Errorf("emitter: %w", err)
	}
	engine, err := decision.New(decision.Config{
		PEP:          c.pepName,
		PolicyHash:   c.policyHash,
		Jurisdiction: c.jurisdiction,
		Verify: func(_ context.Context, token string) (map[string]any, error) {
			return txntoken.Verify(token, ed25519.PublicKey(ttsPub))
		},
		Emit:        emitter.Emit,
		Audience:    c.audience,
		MaxTokenTTL: c.maxTTL,
	})
	if err != nil {
		auditLog.Close()
		return nil, nil, fmt.Errorf("engine: %w", err)
	}
	return engine, auditLog.Close, nil
}

// missingRequired names the settings that have no safe default, in the order an
// operator would fix them. Each one is required rather than defaulted because
// the natural default is the empty string and the empty string is a fail-open:
// an absent audience matches a token that omits `aud`, an absent tts-pub means
// nothing to verify against, and an absent upstream means there is nothing
// being guarded. Returning the list rather than a bool exists so the operator is
// told which, instead of re-reading the whole usage block.
//
// -public-url is NOT here. Its absence disables agent-card relay, which is a
// refusal, not a fail-open; requiring it would force every operator who does
// not want the card relayed to invent a value for it.
func missingRequired(upstream, agentIdentity, audience, ttsPub, logKeyFile, policyHash string) []string {
	var missing []string
	for _, f := range []struct {
		name  string
		value string
	}{
		{"-upstream", upstream},
		{"-agent-identity", agentIdentity},
		{"-audience", audience},
		{"-tts-pub", ttsPub},
		{"-log-key-file", logKeyFile},
		{"-policy-hash", policyHash},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	return missing
}

func parseHexKey(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d bytes, got %d", size, len(b))
	}
	return b, nil
}
