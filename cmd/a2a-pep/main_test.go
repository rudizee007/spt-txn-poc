package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/a2apep"
)

// stubHandler stands in for the enforcement point. Transport tests are about
// what reaches the wrapped agent and what comes back, so the authorization
// decision is stubbed and internal/a2apep carries its own coverage.
type stubHandler struct {
	seen  [][]byte
	reply []byte
	fn    func(ctx context.Context, raw []byte) []byte
}

func (s *stubHandler) Handle(ctx context.Context, raw []byte) []byte {
	s.seen = append(s.seen, append([]byte(nil), raw...))
	if s.fn != nil {
		return s.fn(ctx, raw)
	}
	return s.reply
}

func newProxy(h handler, upstream, publicURL string) *proxy {
	return &proxy{
		mw:        h,
		rpcPath:   "/",
		cardPath:  defaultCardPath,
		publicURL: publicURL,
		upstream:  upstream,
		cardURL:   upstream + defaultCardPath,
		client:    newUpstreamClient(5 * time.Second),
	}
}

func jsonPost(target string, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// ── routing ───────────────────────────────────────────────────────────────

// An enforcement point that proxies whatever it is given is a general-purpose
// proxy with an authorization check bolted to one of its paths. Only two
// requests exist; everything else is a 404 that never reaches the handler.
func TestRoute_EverythingButTheTwoKnownRequestsIs404(t *testing.T) {
	h := &stubHandler{reply: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")

	for _, c := range []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodPut, "/"},
		{http.MethodDelete, "/"},
		{http.MethodPost, "/somewhere-else"},
		{http.MethodPost, "/a2a/v1"},
		{http.MethodPost, defaultCardPath},
		{http.MethodGet, "/anything"},
	} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(c.method, c.target, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.target, w.Code)
		}
	}
	if len(h.seen) != 0 {
		t.Fatalf("a refused route still reached the enforcement point (%d times)", len(h.seen))
	}
}

func TestServeRPC_RefusesANonJSONContentType(t *testing.T) {
	h := &stubHandler{reply: []byte(`{}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")

	for _, ct := range []string{"", "text/plain", "application/xml", "application/json-patch+json"} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0"}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q = %d, want 415", ct, w.Code)
		}
	}
	if len(h.seen) != 0 {
		t.Fatal("a body with the wrong media type reached the enforcement point")
	}
}

func TestServeRPC_AcceptsJSONWithParameters(t *testing.T) {
	h := &stubHandler{reply: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(h.seen) != 1 {
		t.Fatal("a well-formed request did not reach the enforcement point")
	}
}

// An unbounded read on a socket an adversary can write to is a memory
// exhaustion primitive, so the cap has to be refused BEFORE the enforcement
// point is asked to parse it.
func TestServeRPC_RefusesAnOversizeBody(t *testing.T) {
	h := &stubHandler{reply: []byte(`{}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	big := `{"jsonrpc":"2.0","id":1,"pad":"` + strings.Repeat("a", maxMessageBytes) + `"}`
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", big))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if len(h.seen) != 0 {
		t.Fatal("an oversize body reached the enforcement point")
	}
}

func TestServeRPC_ReturnsTheEnforcementPointsAnswerVerbatim(t *testing.T) {
	want := `{"jsonrpc":"2.0","id":1,"result":{"kind":"message"}}`
	h := &stubHandler{reply: []byte(want)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// A denial is HTTP 200 carrying a JSON-RPC error, not a 4xx. The refusal is
// uniform on purpose; a distinguishable status code would put back the oracle
// the uniform body exists to remove.
func TestServeRPC_ADenialIsA200NotAnHTTPError(t *testing.T) {
	denied := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"spt-txn: denied"}}`
	h := &stubHandler{reply: []byte(denied)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("a denial answered with HTTP %d; the status code now distinguishes "+
			"a refusal from an answer", w.Code)
	}
	if w.Body.String() != denied {
		t.Fatalf("body = %s", w.Body.String())
	}
}

// ── the nil-response backstop ─────────────────────────────────────────────

type nilHandler struct{ seen int }

func (n *nilHandler) Handle(_ context.Context, _ []byte) []byte { n.seen++; return nil }

// The real middleware always answers a request. If a future change ever did
// not, an empty 204 would look to the caller like success rather than refusal.
func TestServeRPC_ARequestNeverGoesUnanswered(t *testing.T) {
	h := &nilHandler{}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":7,"method":"message/send"}`))
	if h.seen != 1 {
		t.Fatal("the enforcement point was not consulted")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var e struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("unparseable backstop answer %s", w.Body.String())
	}
	if e.Error == nil || e.Error.Message != "spt-txn: denied" {
		t.Fatalf("backstop is not the uniform denial: %s", w.Body.String())
	}
	if string(e.ID) != "7" {
		t.Fatalf("backstop answered id %s, want 7", e.ID)
	}
}

// A refused notification has nothing to answer, and inventing an id would be
// a protocol violation.
func TestServeRPC_ANotificationStaysUnanswered(t *testing.T) {
	h := &nilHandler{}
	p := newProxy(h, "http://127.0.0.1:1", "")
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"message/send"}`,
		`{"jsonrpc":"2.0","id":null,"method":"message/send"}`,
	} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, jsonPost("/", body))
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s = %d, want 204", body, w.Code)
		}
		if w.Body.Len() != 0 {
			t.Fatalf("%s answered with a body: %s", body, w.Body.String())
		}
	}
}

// ── forwarding ────────────────────────────────────────────────────────────

// upstreamSpy records what the wrapped agent actually received.
type upstreamSpy struct {
	srv *httptest.Server

	// The upstream handler runs on the server's goroutine and the assertions
	// run on the test's, so the record is guarded. An unguarded counter here
	// is a data race the test would report as a flake.
	mu      sync.Mutex
	hits    int
	headers []http.Header
	bodies  []string
}

func newUpstreamSpy(t *testing.T, reply string) *upstreamSpy {
	t.Helper()
	s := &upstreamSpy{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hits++
		s.headers = append(s.headers, r.Header.Clone())
		s.bodies = append(s.bodies, string(b))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// record returns a snapshot of what the wrapped agent received.
func (s *upstreamSpy) record() (int, []http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, append([]http.Header(nil), s.headers...)
}

// The middleware strips the SPT-Txn credential out of the body. Forwarding the
// caller's Authorization or Cookie would hand the wrapped agent a different
// credential for the same caller: the same confused-deputy hole, one layer
// down. No client header is copied, so there is nothing to get wrong later.
func TestForward_NoClientHeaderReachesTheWrappedAgent(t *testing.T) {
	up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	var p *proxy
	h := &stubHandler{fn: func(ctx context.Context, raw []byte) []byte {
		out, err := p.forward(ctx, raw, a2apep.DialectV03)
		if err != nil {
			t.Errorf("forward: %v", err)
			return []byte(`{}`)
		}
		return out
	}}
	p = newProxy(h, up.srv.URL, "")

	r := jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`)
	r.Header.Set("Authorization", "Bearer caller-secret")
	r.Header.Set("Cookie", "session=caller-secret")
	r.Header.Set("X-Api-Key", "caller-secret")
	// The caller's protocol version claim is a caller header like any other.
	// The middleware classified this body as v0.3.0; the header the agent
	// sees is that classification, not the caller's "9.9".
	r.Header.Set("A2A-Version", "9.9")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	hits, headers := up.record()
	if hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	got := headers[0]
	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if v := got.Get(name); v != "" {
			t.Errorf("CONFUSED DEPUTY: %s reached the wrapped agent as %q", name, v)
		}
	}
	for name, vals := range got {
		if strings.Contains(strings.Join(vals, " "), "caller-secret") {
			t.Errorf("caller credential leaked through header %s: %v", name, vals)
		}
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if v := got.Get("A2A-Version"); v != "0.3" {
		t.Errorf("A2A-Version = %q, want the middleware's classification 0.3, never the caller's", v)
	}
}

// A2A-Version is set from the dialect the middleware classified the request
// as, and only the two values it can produce are ever sent. An unknown dialect
// is refused rather than sent unversioned: the reference server treats an
// absent header as 0.3, so an unversioned v1.0 body would be parsed wrong, not
// rejected -- and the permit for it has already been recorded.
func TestForward_SetsA2AVersionFromTheVerifiedDialect(t *testing.T) {
	for _, c := range []struct {
		dialect a2apep.Dialect
		want    string
	}{
		{a2apep.DialectV03, "0.3"},
		{a2apep.DialectV1, "1.0"},
	} {
		up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		p := newProxy(&stubHandler{}, up.srv.URL, "")
		if _, err := p.forward(context.Background(), []byte(`{}`), c.dialect); err != nil {
			t.Fatalf("%s: %v", c.dialect, err)
		}
		hits, headers := up.record()
		if hits != 1 {
			t.Fatalf("%s: hits = %d", c.dialect, hits)
		}
		if got := headers[0].Get("A2A-Version"); got != c.want {
			t.Fatalf("dialect %q sent A2A-Version %q, want %q", c.dialect, got, c.want)
		}
	}
	up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	p := newProxy(&stubHandler{}, up.srv.URL, "")
	for _, bad := range []a2apep.Dialect{"", "2.0", "0.3.0"} {
		if _, err := p.forward(context.Background(), []byte(`{}`), bad); err == nil {
			t.Fatalf("dialect %q was forwarded", bad)
		}
	}
	if hits, _ := up.record(); hits != 0 {
		t.Fatalf("an unknown dialect reached the wrapped agent %d time(s)", hits)
	}
}

func TestForward_ADeniedCallNeverReachesTheWrappedAgent(t *testing.T) {
	up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	h := &stubHandler{reply: []byte(
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"spt-txn: denied"}}`)}
	p := newProxy(h, up.srv.URL, "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if hits, _ := up.record(); hits != 0 {
		t.Fatalf("a denied call reached the wrapped agent %d time(s)", hits)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// Relaying a stream would return content the enforcement point never saw.
func TestForward_RefusesAStreamedAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`), a2apep.DialectV03); err == nil {
		t.Fatal("a streamed answer was relayed")
	} else if !strings.Contains(err.Error(), "stream") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// A proxy that follows a redirect can be pointed at a host the operator never
// configured, which would send an authorized request to a different agent.
func TestForward_RefusesARedirect(t *testing.T) {
	elsewhere := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{"stolen":true}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`), a2apep.DialectV03); err == nil {
		t.Fatal("the redirect was followed")
	}
	if hits, _ := elsewhere.record(); hits != 0 {
		t.Fatalf("an authorized request was delivered to the redirect target %d time(s)",
			hits)
	}
}

func TestForward_RefusesANon2xxAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"oops":true}`))
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`), a2apep.DialectV03); err == nil {
		t.Fatal("a 500 from the wrapped agent was treated as an answer")
	}
}

// ── the agent card ────────────────────────────────────────────────────────

const upstreamCard = `{"protocolVersion":"0.3.0","name":"payments",` +
	`"url":"http://internal-agent.invalid:9000/a2a/v1","preferredTransport":"JSONRPC",` +
	`"additionalInterfaces":[{"url":"http://internal-agent.invalid:9000/a2a/grpc","transport":"GRPC"}],` +
	`"version":"1.0.0"}`

func newCardServer(t *testing.T, card string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultCardPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(card))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Relaying the wrapped agent's card unmodified publishes the address of the
// agent BEHIND the enforcement point. Without somewhere to point clients
// instead, the honest answer is to serve no card at all.
func TestCard_RelayIsOffWithoutAPublicURL(t *testing.T) {
	srv := newCardServer(t, upstreamCard, http.StatusOK)
	p := newProxy(&stubHandler{}, srv.URL, "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "internal-agent.invalid") {
		t.Fatal("the refusal leaked the wrapped agent's address")
	}
}

func TestCard_RelayAdvertisesThePEPAndDropsAlternateInterfaces(t *testing.T) {
	srv := newCardServer(t, upstreamCard, http.StatusOK)
	const public = "https://guarded.example/"
	p := newProxy(&stubHandler{}, srv.URL, public)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "internal-agent.invalid") {
		t.Fatalf("BYPASS PUBLISHED: the relayed card still names the agent behind the "+
			"PEP: %s", body)
	}
	var card map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil {
		t.Fatalf("relayed card is not JSON: %v", err)
	}
	if card["url"] != public {
		t.Fatalf("url = %v, want %s", card["url"], public)
	}
	if _, ok := card["additionalInterfaces"]; ok {
		t.Fatal("additionalInterfaces survived: every entry is a second address on a " +
			"transport this PEP does not enforce")
	}
	if card["name"] != "payments" || card["version"] != "1.0.0" {
		t.Fatalf("the rest of the card did not survive: %s", body)
	}
	if card["protocolVersion"] != "0.3.0" {
		t.Fatalf("protocolVersion was lost: %s", body)
	}
	if _, ok := card["supportedInterfaces"]; ok {
		t.Fatal("a v1.0 supportedInterfaces was invented on a v0.3.0 card")
	}
}

func TestCard_UpstreamFailureIsABadGateway(t *testing.T) {
	srv := newCardServer(t, `{"url":"x"}`, http.StatusInternalServerError)
	p := newProxy(&stubHandler{}, srv.URL, "https://guarded.example/")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
}

func TestRewriteCard_RejectsWhatIsNotAnObject(t *testing.T) {
	for _, bad := range []string{`[]`, `"a string"`, `null`, `not json`, ``} {
		if _, _, err := rewriteCard([]byte(bad), "https://guarded.example/"); err == nil {
			t.Errorf("rewriteCard accepted %q", bad)
		}
	}
}

// Dropping alternate interfaces silently degrades a multi-transport agent to
// JSON-RPC only, and the clients that stop discovering those transports have no
// way to learn why. The count is what lets the operator be told.
func TestRewriteCard_ReportsHowManyInterfacesItDropped(t *testing.T) {
	if _, rep, err := rewriteCard([]byte(upstreamCard), "https://guarded.example/"); err != nil {
		t.Fatal(err)
	} else if rep.DroppedInterfaces != 1 {
		t.Fatalf("dropped = %d, want 1", rep.DroppedInterfaces)
	}
	none := `{"name":"x","url":"http://a.invalid/"}`
	if _, rep, err := rewriteCard([]byte(none), "https://guarded.example/"); err != nil {
		t.Fatal(err)
	} else if rep.DroppedInterfaces != 0 {
		t.Fatalf("dropped = %d on a card with no alternates, want 0", rep.DroppedInterfaces)
	}
}

// ── the agent card, A2A v1.0 ──────────────────────────────────────────────
//
// v1.0 removed url, preferredTransport and additionalInterfaces and names
// every endpoint in one array, supportedInterfaces. Before this dialect was
// handled, rewriteCard set a url no v1.0 client reads, counted zero
// additionalInterfaces, and relayed supportedInterfaces untouched -- the
// upstream address, published, with nothing logged. Every test here asserts on
// the CONTENT of the relayed card, because "no error" is exactly what the
// defect produced.

const upstreamCardV1 = `{"name":"payments","description":"pays","version":"1.0.0",` +
	`"supportedInterfaces":[` +
	`{"url":"http://internal-agent.invalid:9000/a2a/jsonrpc","protocolBinding":"JSONRPC","protocolVersion":"1.0"},` +
	`{"url":"internal-agent.invalid:9001","protocolBinding":"GRPC","protocolVersion":"1.0"},` +
	`{"url":"http://internal-agent.invalid:9000/a2a/rest","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],` +
	`"capabilities":{"streaming":true,"extendedAgentCard":true},` +
	`"signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"c2lnbmVkLWJ5LXVwc3RyZWFt"}]}`

// interfaces parses the relayed supportedInterfaces as a list of objects, and
// fails the test if it is anything else.
func interfaces(t *testing.T, card map[string]any) []map[string]any {
	t.Helper()
	raw, ok := card["supportedInterfaces"].([]any)
	if !ok {
		t.Fatalf("supportedInterfaces is %T, want an array: %v", card["supportedInterfaces"], card)
	}
	out := make([]map[string]any, 0, len(raw))
	for i, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("supportedInterfaces[%d] is %T, want an object", i, e)
		}
		out = append(out, m)
	}
	return out
}

func TestCard_V1RelayRewritesSupportedInterfacesAndDropsOtherBindings(t *testing.T) {
	srv := newCardServer(t, upstreamCardV1, http.StatusOK)
	const public = "https://guarded.example/"
	p := newProxy(&stubHandler{}, srv.URL, public)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "internal-agent.invalid") {
		t.Fatalf("BYPASS PUBLISHED: the relayed v1.0 card still names the agent behind the "+
			"PEP: %s", body)
	}
	var card map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil {
		t.Fatalf("relayed card is not JSON: %v", err)
	}
	ifs := interfaces(t, card)
	if len(ifs) != 1 {
		t.Fatalf("supportedInterfaces has %d entries, want exactly the one JSONRPC entry: %s",
			len(ifs), body)
	}
	if ifs[0]["url"] != public {
		t.Fatalf("supportedInterfaces[0].url = %v, want %s", ifs[0]["url"], public)
	}
	if ifs[0]["protocolBinding"] != "JSONRPC" {
		t.Fatalf("supportedInterfaces[0].protocolBinding = %v, want JSONRPC", ifs[0]["protocolBinding"])
	}
	if ifs[0]["protocolVersion"] != "1.0" {
		t.Fatalf("the upstream protocolVersion was not carried: %v", ifs[0]["protocolVersion"])
	}
	// The PEP rewrites the dialect it was given; it does not invent the other.
	for _, member := range []string{"url", "preferredTransport", "additionalInterfaces"} {
		if _, ok := card[member]; ok {
			t.Errorf("v0.3.0 member %q was invented on a v1.0 card", member)
		}
	}
	if _, ok := card["signatures"]; ok {
		t.Fatal("a signature over the UPSTREAM card survived the rewrite: the relayed card " +
			"looks authenticated and is not")
	}
	if card["name"] != "payments" || card["version"] != "1.0.0" || card["description"] != "pays" {
		t.Fatalf("the rest of the card did not survive: %s", body)
	}
	if caps, ok := card["capabilities"].(map[string]any); !ok || caps["extendedAgentCard"] != true {
		t.Fatalf("capabilities did not survive: %s", body)
	}
}

// The operator is told what was removed, through the same report as the
// v0.3.0 count: two non-JSONRPC bindings and one signature. The card with
// nothing to remove reports zero of each, so a count that is merely "always
// positive" cannot pass.
func TestRewriteCard_V1ReportsDroppedBindingsAndStrippedSignatures(t *testing.T) {
	_, rep, err := rewriteCard([]byte(upstreamCardV1), "https://guarded.example/")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DroppedInterfaces != 2 {
		t.Errorf("dropped = %d, want 2 (GRPC and HTTP+JSON)", rep.DroppedInterfaces)
	}
	if rep.StrippedSignatures != 1 {
		t.Errorf("stripped signatures = %d, want 1", rep.StrippedSignatures)
	}

	plain := `{"name":"x","supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	_, rep, err = rewriteCard([]byte(plain), "https://guarded.example/")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DroppedInterfaces != 0 || rep.StrippedSignatures != 0 {
		t.Errorf("report = %+v on a card with nothing to remove, want zeros", rep)
	}
}

// A signature is stripped from a v0.3.0 card too (the field exists in both
// dialects), and the counted report is the evidence it happened.
func TestRewriteCard_StripsSignaturesFromAV03Card(t *testing.T) {
	signed := `{"name":"x","url":"http://a.invalid/","signatures":[` +
		`{"protected":"e30","signature":"YQ"},{"protected":"e30","signature":"Yg"}]}`
	out, rep, err := rewriteCard([]byte(signed), "https://guarded.example/")
	if err != nil {
		t.Fatal(err)
	}
	if rep.StrippedSignatures != 2 {
		t.Fatalf("stripped signatures = %d, want 2", rep.StrippedSignatures)
	}
	var card map[string]any
	if err := json.Unmarshal(out, &card); err != nil {
		t.Fatal(err)
	}
	if _, ok := card["signatures"]; ok {
		t.Fatalf("signatures survived: %s", out)
	}
	if card["url"] != "https://guarded.example/" {
		t.Fatalf("url = %v", card["url"])
	}
}

// An agent may expose JSON-RPC under more than one protocol version. Every
// JSONRPC entry is re-advertised, in order, each at the PEP and each keeping
// its own version, because the PEP forwards either dialect and does not decide
// which one the agent speaks.
func TestRewriteCard_V1KeepsEveryJSONRPCInterfaceRewritten(t *testing.T) {
	two := `{"name":"x","supportedInterfaces":[` +
		`{"url":"http://a.invalid/v1","protocolBinding":"JSONRPC","protocolVersion":"1.0"},` +
		`{"url":"grpc.a.invalid:443","protocolBinding":"GRPC","protocolVersion":"1.0"},` +
		`{"url":"http://a.invalid/legacy","protocolBinding":"JSONRPC","protocolVersion":"0.3"}]}`
	const public = "https://guarded.example/"
	out, rep, err := rewriteCard([]byte(two), public)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DroppedInterfaces != 1 {
		t.Fatalf("dropped = %d, want 1", rep.DroppedInterfaces)
	}
	if strings.Contains(string(out), "a.invalid") {
		t.Fatalf("upstream address survived: %s", out)
	}
	var card map[string]any
	if err := json.Unmarshal(out, &card); err != nil {
		t.Fatal(err)
	}
	ifs := interfaces(t, card)
	if len(ifs) != 2 {
		t.Fatalf("kept %d entries, want 2: %s", len(ifs), out)
	}
	for i, want := range []string{"1.0", "0.3"} {
		if ifs[i]["url"] != public || ifs[i]["protocolBinding"] != "JSONRPC" || ifs[i]["protocolVersion"] != want {
			t.Errorf("entry %d = %v, want url %s, JSONRPC, version %s", i, ifs[i], public, want)
		}
	}
}

// A card carrying both dialects is rewritten in both. Neither member may be
// left alone because the other was handled.
func TestRewriteCard_DualDialectCardIsRewrittenInBoth(t *testing.T) {
	dual := `{"name":"x","url":"http://a.invalid/v1","preferredTransport":"GRPC",` +
		`"additionalInterfaces":[{"url":"grpc.a.invalid:443","transport":"GRPC"}],` +
		`"supportedInterfaces":[{"url":"http://a.invalid/v1","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	const public = "https://guarded.example/"
	out, rep, err := rewriteCard([]byte(dual), public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "a.invalid") {
		t.Fatalf("upstream address survived: %s", out)
	}
	if rep.DroppedInterfaces != 1 {
		t.Fatalf("dropped = %d, want 1 (the additionalInterfaces entry)", rep.DroppedInterfaces)
	}
	var card map[string]any
	if err := json.Unmarshal(out, &card); err != nil {
		t.Fatal(err)
	}
	if card["url"] != public || card["preferredTransport"] != "JSONRPC" {
		t.Fatalf("v0.3.0 members not rewritten: %s", out)
	}
	if _, ok := card["additionalInterfaces"]; ok {
		t.Fatalf("additionalInterfaces survived: %s", out)
	}
	if ifs := interfaces(t, card); len(ifs) != 1 || ifs[0]["url"] != public {
		t.Fatalf("v1.0 member not rewritten: %s", out)
	}
}

// A card whose shape this function does not recognise is refused, never
// relayed. Each case is a well-formed JSON object that a passthrough would
// happily publish, and each assertion names the member the refusal is about,
// so a refusal for some OTHER reason -- or a refusal of everything -- does not
// pass for the one under test.
func TestRewriteCard_RefusesWhatItCannotRewrite(t *testing.T) {
	cases := []struct {
		name string
		card string
		want string // a substring of the error naming the refused member
	}{
		{"no endpoint in either dialect",
			`{"name":"x","version":"1"}`,
			"names no endpoint"},
		{"additionalInterfaces that is not an array",
			`{"url":"http://a.invalid/","additionalInterfaces":{"url":"http://b.invalid/"}}`,
			"additionalInterfaces is present but is not an array"},
		{"supportedInterfaces that is not an array",
			`{"supportedInterfaces":{"url":"http://a.invalid/","protocolBinding":"JSONRPC"}}`,
			"supportedInterfaces is present but is not an array"},
		{"supportedInterfaces entry that is not an object",
			`{"supportedInterfaces":["http://a.invalid/"]}`,
			"supportedInterfaces is present but is not an array of objects"},
		{"supportedInterfaces entry that is null",
			`{"supportedInterfaces":[null]}`,
			"supportedInterfaces[0] is null"},
		{"entry with no protocolBinding",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolVersion":"1.0"}]}`,
			"no string protocolBinding"},
		{"entry with a non-string protocolBinding",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":7}]}`,
			"no string protocolBinding"},
		{"no JSONRPC entry",
			`{"supportedInterfaces":[{"url":"grpc.a.invalid:443","protocolBinding":"GRPC","protocolVersion":"1.0"}]}`,
			"no JSONRPC entry"},
		{"binding matched by case is not JSONRPC",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"jsonrpc","protocolVersion":"1.0"}]}`,
			"no JSONRPC entry"},
		{"JSONRPC entry naming a tenant",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC","protocolVersion":"1.0","tenant":"t1"}]}`,
			"tenant"},
		{"JSONRPC entry with an unrecognised member",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC","fallbackUrl":"http://b.invalid/"}]}`,
			"unrecognised member"},
		{"signatures that is not an array",
			`{"url":"http://a.invalid/","signatures":{"protected":"e30","signature":"YQ"}}`,
			"signatures is present but is not an array"},
		{"JSONRPC entry whose protocolVersion is not a string",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC","protocolVersion":{"url":"http://a.invalid/"}}]}`,
			"protocolVersion is absent or not a string"},
		{"unrecognised top-level member",
			`{"name":"x","url":"http://a.invalid/","endpoint":"http://a.invalid/"}`,
			`unrecognised agent card member "endpoint"`},
		{"duplicated top-level member",
			`{"url":"http://a.invalid/","url":"http://b.invalid/"}`,
			`duplicate agent card member "url"`},
		{"capabilities that is not an object",
			`{"url":"http://a.invalid/","capabilities":["streaming"]}`,
			"capabilities is not an object"},
		{"capabilities with an unrecognised member",
			`{"url":"http://a.invalid/","capabilities":{"streaming":true,"callbackUrl":"http://a.invalid/"}}`,
			`unrecognised agent card capabilities member "callbackUrl"`},
		// Typed members. Each carries the address inside a value of the wrong
		// type; under a name-only allowlist every one relayed.
		{"capabilities.streaming that is an object",
			`{"url":"http://a.invalid/","capabilities":{"streaming":{"u":"http://a.invalid/"}}}`,
			"capabilities.streaming is not a boolean"},
		{"supportsAuthenticatedExtendedCard that is an object",
			`{"url":"http://a.invalid/","supportsAuthenticatedExtendedCard":{"u":"http://a.invalid/"}}`,
			"supportsAuthenticatedExtendedCard is not a boolean"},
		{"protocolVersion that is an object",
			`{"url":"http://a.invalid/","protocolVersion":{"u":"http://a.invalid/"}}`,
			"protocolVersion is not a string"},
		{"defaultInputModes that is not an array of strings",
			`{"url":"http://a.invalid/","defaultInputModes":[{"u":"http://a.invalid/"}]}`,
			"defaultInputModes is not an array of strings"},
		{"defaultInputModes that is null",
			`{"url":"http://a.invalid/","defaultInputModes":null}`,
			"defaultInputModes is not an array of strings"},
		{"capabilities that is null",
			`{"url":"http://a.invalid/","capabilities":null}`,
			"capabilities is not an object"},
		{"skill with an unrecognised member",
			`{"url":"http://a.invalid/","skills":[{"id":"s","name":"n","description":"d","tags":[],"endpoint":"http://a.invalid/"}]}`,
			`unrecognised agent card skills[0] member "endpoint"`},
		{"skill member of the wrong type",
			`{"url":"http://a.invalid/","skills":[{"id":"s","name":{"u":"http://a.invalid/"},"description":"d","tags":[]}]}`,
			"skills[0].name is not a string"},
		{"skills that is not an array",
			`{"url":"http://a.invalid/","skills":{"id":"s"}}`,
			"skills is not an array"},
		{"name that is not a string",
			`{"url":"http://a.invalid/","name":["http://a.invalid/"]}`,
			"name is not a string"},
		{"JSONRPC entry with no protocolVersion",
			`{"supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC"}]}`,
			"protocolVersion is absent or not a string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := rewriteCard([]byte(c.card), "https://guarded.example/")
			if err == nil {
				t.Fatalf("relayed as %s", out)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for a different reason: %v (want %q)", err, c.want)
			}
			if out != nil {
				t.Fatalf("a refused card still produced output: %s", out)
			}
		})
	}
}

// Through the transport, a refused card is a 502 that says nothing about the
// card, not a 200 carrying the upstream address.
//
// The fixture has a perfectly good url, so the ONLY reason to refuse it is the
// member the function does not recognise. An earlier fixture omitted url too
// and was refused for that instead, which made this test pass without the
// allowlist existing.
func TestCard_ARefusedCardIsABadGatewayThatLeaksNothing(t *testing.T) {
	unrecognised := `{"name":"x","url":"http://internal-agent.invalid:9000/",` +
		`"endpoint":"http://internal-agent.invalid:9000/"}`
	srv := newCardServer(t, unrecognised, http.StatusOK)
	p := newProxy(&stubHandler{}, srv.URL, "https://guarded.example/")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
	}
	// The body is the fixed phrase and nothing else. The reason (which names
	// card members) goes to the operator's log; a caller who can read it can
	// map the card's shape from the outside, one refusal at a time.
	if got := w.Body.String(); got != "upstream agent card cannot be relayed\n" {
		t.Fatalf("the refusal is not the fixed phrase: %q", got)
	}
}

// A case variant of an address-bearing member must not survive. Go's
// encoding/json decodes "Url" into a `json:"url"` field (struct-tag matching is
// case-insensitive), so a relayed "Url" IS the upstream address to a Go client.
// An earlier version rewrote url only when "url" (exact) was present, and let
// "Url" through untouched. Exact-case allowlisting refuses every variant as an
// unrecognised member; both the function and the transport are checked, and the
// exact-spelling card beside them shows the refusal is about the case.
func TestCard_ACaseVariantOfURLIsRefusedNotRelayed(t *testing.T) {
	const public = "https://guarded.example/"
	for _, variant := range []string{"Url", "URL", "uRL"} {
		card := `{"name":"x","` + variant + `":"http://internal-agent.invalid:9000/",` +
			`"supportedInterfaces":[{"url":"http://internal-agent.invalid:9000/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
		out, _, err := rewriteCard([]byte(card), public)
		if err == nil {
			t.Fatalf("%s: relayed as %s", variant, out)
		}
		if !strings.Contains(err.Error(), `"`+variant+`"`) {
			t.Fatalf("%s: refused for a different reason: %v", variant, err)
		}
		srv := newCardServer(t, card, http.StatusOK)
		p := newProxy(&stubHandler{}, srv.URL, public)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
		if w.Code != http.StatusBadGateway {
			t.Fatalf("%s: status = %d, want 502: %s", variant, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "internal-agent.invalid") {
			t.Fatalf("%s: BYPASS PUBLISHED through a case variant: %s", variant, w.Body.String())
		}
	}
	exact := `{"name":"x","url":"http://internal-agent.invalid:9000/"}`
	out, _, err := rewriteCard([]byte(exact), public)
	if err != nil {
		t.Fatalf("the exact spelling was refused too, so the test above is not about case: %v", err)
	}
	if strings.Contains(string(out), "internal-agent.invalid") {
		t.Fatalf("exact url not rewritten: %s", out)
	}
}

// Recognised members that carry URLs or authentication schemes are dropped by
// name and reported, and the card without them reports nothing. The asserted
// output is the card, not the count: a count could be right while the member
// stayed.
func TestRewriteCard_DropsAndReportsURLAndAuthBearingMembers(t *testing.T) {
	const public = "https://guarded.example/"
	loaded := `{"name":"x","url":"http://internal-agent.invalid:9000/",` +
		`"iconUrl":"http://internal-agent.invalid:9000/icon.png",` +
		`"documentationUrl":"http://internal-agent.invalid:9000/docs",` +
		`"provider":{"organization":"acme","url":"http://internal-agent.invalid:9000/"},` +
		`"securitySchemes":{"oidc":{"type":"openIdConnect","openIdConnectUrl":"http://internal-agent.invalid:9000/.well-known/openid-configuration"}},` +
		`"security":[{"oidc":[]}],"securityRequirements":[{"oidc":[]}],` +
		`"capabilities":{"streaming":true,"extensions":[{"uri":"http://internal-agent.invalid:9000/ext","params":{"cb":"http://internal-agent.invalid:9000/"}}]},` +
		`"skills":[{"id":"pay","name":"pay","description":"pays","tags":["money"]}]}`
	out, rep, err := rewriteCard([]byte(loaded), public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "internal-agent.invalid") {
		t.Fatalf("upstream address survived in an informational or auth member: %s", out)
	}
	var card map[string]any
	if err := json.Unmarshal(out, &card); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"iconUrl", "documentationUrl", "provider", "securitySchemes", "security", "securityRequirements"} {
		if _, ok := card[m]; ok {
			t.Errorf("%s survived: %s", m, out)
		}
	}
	caps, ok := card["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities lost: %s", out)
	}
	if _, ok := caps["extensions"]; ok {
		t.Errorf("capabilities.extensions survived: %s", out)
	}
	if caps["streaming"] != true {
		t.Errorf("capabilities.streaming did not survive: %s", out)
	}
	if _, ok := card["skills"]; !ok {
		t.Errorf("skills did not survive: %s", out)
	}
	want := "capabilities.extensions documentationUrl iconUrl provider security securityRequirements securitySchemes"
	got := append([]string(nil), rep.DroppedMembers...)
	sort.Strings(got)
	if strings.Join(got, " ") != want {
		t.Errorf("DroppedMembers = %v, want %s", rep.DroppedMembers, want)
	}

	// Nothing to drop, nothing reported, and the survivors are intact.
	plain := `{"name":"x","url":"http://a.invalid/","capabilities":{"streaming":true},"skills":[]}`
	out, rep, err = rewriteCard([]byte(plain), public)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DroppedMembers) != 0 {
		t.Errorf("DroppedMembers = %v on a card with nothing to drop", rep.DroppedMembers)
	}
	if !strings.Contains(string(out), `"capabilities":{"streaming":true}`) {
		t.Errorf("capabilities not relayed intact: %s", out)
	}
}

// Every allowed member has a schema entry, and vice versa. A member allowed
// but untyped is relayed untyped, which is the name-only allowlist this round
// replaced; a member typed but not allowed is dead weight that reads as
// coverage.
func TestCardSchemaCoversEveryAllowedMember(t *testing.T) {
	for name := range allowedCardMembers {
		if _, ok := cardSchema[name]; !ok {
			t.Errorf("allowed member %q has no schema entry: it would be relayed untyped", name)
		}
	}
	for name := range cardSchema {
		if !allowedCardMembers[name] {
			t.Errorf("schema entry %q is not an allowed member", name)
		}
	}
	// Every member dropped by name is marked handled, so checkTyped does not
	// demand a type of something that is about to be deleted.
	for _, name := range droppedCardMembers {
		if cardSchema[name].kind != kindHandled {
			t.Errorf("dropped member %q is typed rather than handled", name)
		}
	}
}

// A skill's security references name schemes defined by the top-level
// securitySchemes, which is dropped. The references are dropped with it and
// reported, so the relayed card does not point at definitions it no longer
// carries. The other skill members survive typed.
func TestRewriteCard_DropsSkillSecurityReferencesWithTheSchemes(t *testing.T) {
	card := `{"url":"http://a.invalid/","securitySchemes":{"oidc":{"type":"openIdConnect","openIdConnectUrl":"http://a.invalid/"}},` +
		`"skills":[{"id":"pay","name":"pay","description":"pays","tags":["money"],"security":[{"oidc":["pay"]}]},` +
		`{"id":"view","name":"view","description":"views","tags":[],"securityRequirements":[{"schemes":{"oidc":{"list":["view"]}}}]}]}`
	out, rep, err := rewriteCard([]byte(card), "https://guarded.example/")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "oidc") {
		t.Fatalf("a reference to a dropped scheme survived: %s", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	skills, ok := parsed["skills"].([]any)
	if !ok || len(skills) != 2 {
		t.Fatalf("skills did not survive: %s", out)
	}
	if skills[0].(map[string]any)["id"] != "pay" || skills[1].(map[string]any)["name"] != "view" {
		t.Fatalf("skill members did not survive: %s", out)
	}
	got := append([]string(nil), rep.DroppedMembers...)
	sort.Strings(got)
	if strings.Join(got, " ") != "securitySchemes skills[].security skills[].securityRequirements" {
		t.Fatalf("DroppedMembers = %v", rep.DroppedMembers)
	}
}

// preferredTransport names a transport, not an address, but a name the PEP
// does not serve would send a v0.3.0 client looking for one. It is JSONRPC
// whenever it appears, with or without a url beside it. The card without one
// does not get one invented.
func TestRewriteCard_PreferredTransportIsAlwaysJSONRPCWhenPresent(t *testing.T) {
	const public = "https://guarded.example/"
	stray := `{"name":"x","preferredTransport":"GRPC","supportedInterfaces":[` +
		`{"url":"http://a.invalid/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	out, _, err := rewriteCard([]byte(stray), public)
	if err != nil {
		t.Fatal(err)
	}
	var card map[string]any
	if err := json.Unmarshal(out, &card); err != nil {
		t.Fatal(err)
	}
	if card["preferredTransport"] != "JSONRPC" {
		t.Fatalf("preferredTransport = %v without a url beside it, want JSONRPC", card["preferredTransport"])
	}
	if _, ok := card["url"]; ok {
		t.Fatalf("a url was invented: %s", out)
	}
	out, _, err = rewriteCard([]byte(upstreamCardV1), public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "preferredTransport") {
		t.Fatalf("preferredTransport was invented on a card without one: %s", out)
	}
}

// A JSONRPC interface advertising a protocol version the PEP does not forward
// under is dropped and counted, like a foreign binding: the reference client
// sets A2A-Version from the entry it picked, the PEP sets it from the method
// spelling it recognised, and an entry promising "1.1" would route every call
// into a version mismatch at the agent, each one costing a single-use token.
func TestRewriteCard_DropsJSONRPCInterfacesOnVersionsThePEPDoesNotSpeak(t *testing.T) {
	card := `{"name":"x","supportedInterfaces":[` +
		`{"url":"http://a.invalid/next","protocolBinding":"JSONRPC","protocolVersion":"1.1"},` +
		`{"url":"http://a.invalid/v1","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	out, rep, err := rewriteCard([]byte(card), "https://guarded.example/")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DroppedInterfaces != 1 {
		t.Fatalf("dropped = %d, want 1 (the 1.1 entry)", rep.DroppedInterfaces)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	ifs := interfaces(t, parsed)
	if len(ifs) != 1 || ifs[0]["protocolVersion"] != "1.0" {
		t.Fatalf("kept %v, want only the 1.0 entry", ifs)
	}
	only := `{"name":"x","supportedInterfaces":[{"url":"http://a.invalid/","protocolBinding":"JSONRPC","protocolVersion":"1.1"}]}`
	if out, _, err := rewriteCard([]byte(only), "https://guarded.example/"); err == nil {
		t.Fatalf("a card whose only JSONRPC entry is on an unknown version was relayed: %s", out)
	} else if !strings.Contains(err.Error(), "no JSONRPC entry") {
		t.Fatalf("refused for a different reason: %v", err)
	}
}

// -public-url is marshalled straight into the relayed card, so it is an address
// clients dial. It was previously taken on trust while -upstream was checked,
// which put the weakest validation on the value with the widest blast radius.
func TestPublicURLIsHeldToTheSameStandardAsUpstream(t *testing.T) {
	for _, bad := range []string{"banana", " ", "/relative/path", "ftp://x.invalid/", "http://"} {
		if u, err := validateAbsoluteURL(bad); err == nil {
			t.Errorf("a card would have advertised %q (parsed as %v)", bad, u)
		}
	}
}

// ── configuration ─────────────────────────────────────────────────────────

func TestValidateAbsoluteURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:9000/", "https://agent.example/a2a/v1"} {
		if _, err := validateAbsoluteURL(ok); err != nil {
			t.Errorf("validateAbsoluteURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/just/a/path", "agent.example:9000",
		"file:///etc/passwd", "ftp://agent.example/", "http://"} {
		if u, err := validateAbsoluteURL(bad); err == nil {
			t.Errorf("validateAbsoluteURL(%q) accepted it as %v", bad, u)
		}
	}
}

type args struct {
	upstream, agentIdentity, audience, ttsPub, logKeyFile, policyHash string
}

func TestMissingRequired_NamesEachFailOpenSetting(t *testing.T) {
	full := func() args {
		return args{upstream: "http://127.0.0.1:9000/", agentIdentity: "a2a://agent",
			audience: "aud", ttsPub: "abcd", logKeyFile: "key.hex", policyHash: "phash"}
	}
	a := full()
	if got := missingRequired(a.upstream, a.agentIdentity, a.audience, a.ttsPub,
		a.logKeyFile, a.policyHash); len(got) != 0 {
		t.Fatalf("a fully-configured PEP reported missing settings: %v", got)
	}

	cases := []struct {
		name string
		want string
		mut  func(a *args)
	}{
		{"upstream", "-upstream", func(a *args) { a.upstream = "" }},
		{"agent identity", "-agent-identity", func(a *args) { a.agentIdentity = "" }},
		{"audience", "-audience", func(a *args) { a.audience = "" }},
		{"tts public key", "-tts-pub", func(a *args) { a.ttsPub = "" }},
		{"log key file", "-log-key-file", func(a *args) { a.logKeyFile = "" }},
		{"policy hash", "-policy-hash", func(a *args) { a.policyHash = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := full()
			c.mut(&a)
			got := missingRequired(a.upstream, a.agentIdentity, a.audience, a.ttsPub,
				a.logKeyFile, a.policyHash)
			if len(got) != 1 || got[0] != c.want {
				t.Fatalf("missingRequired = %v, want exactly [%s]", got, c.want)
			}
		})
	}
}

func writeKey(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A PEP that starts anyway on bad configuration is a PEP that answers without
// verification or without evidence. Each of these must be a startup failure.
func TestBuildEngine_FailsClosedOnBadConfiguration(t *testing.T) {
	dir := t.TempDir()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	goodLogKey := writeKey(t, dir, "log.key", logKey)
	shortLogKey := writeKey(t, dir, "short.key", logKey[:16])
	ttsPub := strings.Repeat("ab", ed25519.PublicKeySize)

	base := func() pepConfig {
		return pepConfig{
			pepName:    "a2a-pep.test",
			ttsPubHex:  ttsPub,
			logKeyFile: goodLogKey,
			auditPath:  filepath.Join(dir, "audit.jsonl"),
			policyHash: "policy-hash",
			audience:   "aud.test",
			maxTTL:     time.Minute,
		}
	}

	cases := []struct {
		name string
		want string
		mut  func(c *pepConfig)
	}{
		{"tts key is not hex", "tts-pub", func(c *pepConfig) { c.ttsPubHex = "zzzz" }},
		{"tts key is the wrong length", "tts-pub", func(c *pepConfig) { c.ttsPubHex = "abcd" }},
		{"log key file is absent", "log-key-file", func(c *pepConfig) {
			c.logKeyFile = filepath.Join(dir, "nope.key")
		}},
		{"log key is the wrong length", "log key", func(c *pepConfig) { c.logKeyFile = shortLogKey }},
		{"audience is unset", "engine", func(c *pepConfig) { c.audience = "" }},
		{"max token ttl is unset", "engine", func(c *pepConfig) { c.maxTTL = 0 }},
		{"policy hash is unset", "engine", func(c *pepConfig) { c.policyHash = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mut(&cfg)
			eng, closer, err := buildEngine(cfg)
			if err == nil {
				if closer != nil {
					closer()
				}
				t.Fatalf("startup succeeded with %s; engine=%v", c.name, eng != nil)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name the failing setting %q", err, c.want)
			}
			if eng != nil {
				t.Fatal("a failed startup returned an engine anyway")
			}
		})
	}

	t.Run("a correct configuration starts", func(t *testing.T) {
		eng, closer, err := buildEngine(base())
		if err != nil {
			t.Fatalf("a correct configuration failed to start: %v", err)
		}
		if eng == nil {
			t.Fatal("no engine")
		}
		if err := closer(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})
}

func TestParseHexKey_RejectsWrongLength(t *testing.T) {
	if _, err := parseHexKey("abcd", ed25519.PublicKeySize); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := parseHexKey("zz", ed25519.PublicKeySize); err == nil {
		t.Fatal("a non-hex key was accepted")
	}
	if _, err := parseHexKey(strings.Repeat("ab", ed25519.PublicKeySize),
		ed25519.PublicKeySize); err != nil {
		t.Fatalf("a correct key was rejected: %v", err)
	}
}

func TestRPCID(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want string
		is   bool
	}{
		{`{"jsonrpc":"2.0","id":7,"method":"m"}`, "7", true},
		{`{"jsonrpc":"2.0","id":"abc","method":"m"}`, `"abc"`, true},
		{`{"jsonrpc":"2.0","method":"m"}`, "", false},
		{`{"jsonrpc":"2.0","id":null,"method":"m"}`, "", false},
		{`not json`, "", false},
	} {
		id, is := rpcID([]byte(c.raw))
		if is != c.is {
			t.Errorf("%s: isRequest = %v, want %v", c.raw, is, c.is)
			continue
		}
		if is && string(id) != c.want {
			t.Errorf("%s: id = %s, want %s", c.raw, id, c.want)
		}
	}
}

func TestDenial_IsWellFormedAndUniform(t *testing.T) {
	var got struct {
		Jsonrpc string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(denial(json.RawMessage("7")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Jsonrpc != "2.0" || got.ID != 7 {
		t.Fatalf("malformed denial: %+v", got)
	}
	if got.Error.Code != -32001 {
		t.Fatalf("code = %d, want the PEP's denied code", got.Error.Code)
	}
	if got.Error.Message != "spt-txn: denied" {
		t.Fatalf("message = %q; a denial must not name the failing check", got.Error.Message)
	}
}
