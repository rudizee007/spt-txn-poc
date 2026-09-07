# SPT-Txn Specification — A2A PEP Profile

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/a2apep`, `cmd/a2a-pep`, shared with MCP: `internal/decision`, `internal/intent`, `internal/jcs`.
**Wire protocol:** Agent2Agent (A2A) v0.3.0 and v1.0, JSON-RPC 2.0 transport.
v1.0 renamed every JSON-RPC method and re-spelled several members; both
dialects are accepted, and each v1.0 spelling is classified exactly as its
v0.3.0 counterpart. Where this document names a v0.3.0 method or member, the
v1.0 spelling in §3.5 is bound by the same rule.
**Threat model:** `docs/THREAT-MODEL.md` §3.3, §4.1, §4.2, §4.6.

---

## 0. Relationship to the MCP profile

`docs/spec/DELEGATION-INTENT-MCP.md` §1 (delegation chains with offline
attenuation) and §2 (intent binding, JCS canonicalization, verification) apply
here **unchanged and normatively**. They are protocol-independent: the question
"was this actor allowed to do exactly this" does not vary with the transport
that carried the request.

This document specifies only what differs — the A2A wire binding, the method
surface, and the transport profile. `internal/a2apep` shares `internal/decision`
with `internal/mcppep` byte for byte; a divergence between the two decision
paths is a defect, not a profile difference.

---

## 1. Placement

The PEP wraps an A2A agent. Every `message/send` MUST carry a valid SPT-Txn
token whose intent binding matches the message being delivered. The wrapped
agent is reachable only through the PEP; an operator who leaves the agent's own
port reachable has not deployed an enforcement point, they have deployed a
second address for the same agent (see §6.1, which is the same failure in
documentary form).

---

## 2. Intent construct for A2A

    intent.tool   = "message/send"
    intent.params = JCS(bound)
    intent.target = the PEP's configured agent identity

where `bound` is the subobject of the A2A `Message` that the digest covers:

    bound = {
      "parts":     <the message's parts array, byte-exact>,
      "taskId":    <string, omitted when absent>,
      "contextId": <string, omitted when absent>
    }

### 2.1 What is bound, and why

- **`parts`** — the content the agent acts on. This is the analogue of MCP's
  `arguments` and is the reason the profile exists.
- **`taskId`** — WHERE the message lands. Without it, a token authorizing a
  message into one task authorizes the same content into another.
- **`contextId`** — the same argument one level up.

### 2.2 What is deliberately NOT bound

- **`messageId`** — generated per send by the client. The minter cannot predict
  it, so binding it would make every token unusable on first presentation.
  Replay of a whole message is handled by the decision engine's `jti` replay
  window (MCP profile §3.2 rule 4), not here.
- **`role`** — a client sending a message is always `"user"` (v1.0 serialises
  the same constant as `"ROLE_USER"`). Binding a constant asserts nothing, so
  the PEP pins it instead: a `role` other than those two spellings (or a
  `kind` other than `"message"`; v1.0 messages carry no `kind`, which is the
  absent case) is refused: a token minted for a user message authorizes a user
  message.
- **`metadata`** — carries the credential itself and is stripped before
  forwarding. A field cannot both be the key and be locked by it. Any OTHER
  member of `metadata` is refused (`rpc.metadata-uncovered`): it is extension
  payload the digest does not cover.

A future revision that binds `messageId` MUST also change the minting path, and
the happy-path test will fail loudly if only one side changes: the minter
constructs `bound` from the same struct the PEP does, so a field added to one is
added to both or the digests diverge.

---

## 3. Method surface (normative)

A2A v0.3.0 defines ten JSON-RPC methods. This profile partitions them into
exactly three classes. **The partition is an allowlist.** A method absent from
§3.3 MUST be denied whether or not it existed when this document was written.

### 3.1 Authorized

`message/send` (v1.0: `SendMessage`). Requires a token; enforced per §2 and
§4. The intent binds ONE tool name, `message/send`, whichever spelling
arrived: the token authorizes the action, not the wire spelling of it, and both
spellings forward the same allowlisted params surface.

### 3.2 Refused as unmodelled

`message/stream` (v1.0: `SendStreamingMessage`), and any future `message/*`
sibling. These deliver payloads this profile does not model — a stream is not
a discrete message and cannot be matched against a single intent digest. They
MUST be denied, never proxied. Forwarding an unmodelled payload is precisely
the gap the PEP exists to close.

Receipt rule path: `rpc.unmodelled-message-method`.

### 3.3 Passed through as observation

Exactly three operations, under their two spellings, and only these:

    tasks/get                          GetTask
    tasks/pushNotificationConfig/get   GetTaskPushNotificationConfig
    tasks/pushNotificationConfig/list  ListTaskPushNotificationConfigs

These read and do not act. They pass unauthenticated but receipted as
`observed`, subject to two checks that make "a read of one task" a property
rather than a method name:

1. **The params are allowlisted**, per method, exactly as a send's are. A
   member outside the method's set, a duplicated member, absent or non-object
   params, or a task-naming member that is absent, non-string or empty MUST be
   refused (rule path `rpc.passthrough-params-refused`). A v0.3.0 params-level
   `metadata` and a v1.0 `tenant` are outside every set. The allowed sets are
   `tasks/get` and `GetTask`: `id` (required), `historyLength`;
   `tasks/pushNotificationConfig/get`: `id` (required),
   `pushNotificationConfigId`; `tasks/pushNotificationConfig/list`: `id`
   (required); `GetTaskPushNotificationConfig`: `taskId`, `id` (both
   required); `ListTaskPushNotificationConfigs`: `taskId` (required),
   `pageSize`, `pageToken`. No set admits a parent or wildcard member; neither
   specification defines one for these methods.
2. **A read carrying the credential key is refused**, not forwarded and not
   stripped: it is unauthenticated, so it has no credential to carry, and
   stripping would forward a request the PEP verified nothing about. The key is
   looked for at any depth, as a member name only (rule path
   `rpc.credential-on-passthrough`).

### 3.4 Denied

Everything else, including the remaining A2A methods:

| Method | Why it is not observation |
|---|---|
| `tasks/pushNotificationConfig/set` | Installs a client-supplied webhook URL that all subsequent task updates are pushed to, and task updates carry message content. A hijacked agent need not defeat the intent binding at all: it points the webhook at a host it controls, and every authorized message thereafter is copied out. |
| `tasks/pushNotificationConfig/delete` | Removes a webhook, silencing the operator's own notifications. |
| `tasks/cancel` | Transitions a task to `canceled`. A denial of service against work already authorized. |
| `tasks/resubscribe` | Reopens a stream this profile does not model — §3.2's objection, on a different method name. |
| `agent/getAuthenticatedExtendedCard` | Returns an agent card, and a card names endpoints. Passing it through republishes over JSON-RPC the bypass §6.1 exists to close, where the card rewriter never looks. |
| `ListTasks` (v1.0 only) | Enumerates every task the agent holds. §3.3 only ever let a caller read a task whose id it already held, and the passthrough is unauthenticated; enumeration is a new capability wearing a read's name, not a rename of one. |

The v1.0 spellings of the first five (`CreateTaskPushNotificationConfig`,
`DeleteTaskPushNotificationConfig`, `CancelTask`, `SubscribeToTask`,
`GetExtendedAgentCard`) are denied by the same rule.

Receipt rule path: `rpc.method-not-permitted`.

**Rationale for the allowlist shape.** An earlier revision of this profile used
a denylist — refuse `message/*` siblings, pass everything else as observation —
on the assumption that non-message traffic does not act. Only three of ten
methods are reads. The assumption was wrong, and the shape is what made it
dangerous: a denylist is wrong by default for every method its author did not
consider, including every method added after they stopped considering.

A second property follows. The observation rule path is constructed as
`observe.passthrough.<method>`. Under a denylist that concatenated
attacker-supplied text, giving the receipt log an unbounded cardinality of rule
paths whose contents an adversary chose — a log-injection and log-flooding
primitive inside the evidence layer, which is the one component that must remain
trustworthy when every other is in doubt. Under an allowlist it can only be one
of six constants.

### 3.5 v1.0 spellings

| v0.3.0 | v1.0 | Class |
|---|---|---|
| `message/send` | `SendMessage` | §3.1 authorized |
| `message/stream` | `SendStreamingMessage` | §3.2 unmodelled |
| `tasks/get` | `GetTask` | §3.3 observation |
| `tasks/pushNotificationConfig/get` | `GetTaskPushNotificationConfig` | §3.3 observation |
| `tasks/pushNotificationConfig/list` | `ListTaskPushNotificationConfigs` | §3.3 observation |
| `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | §3.4 denied |
| `tasks/pushNotificationConfig/delete` | `DeleteTaskPushNotificationConfig` | §3.4 denied |
| `tasks/cancel` | `CancelTask` | §3.4 denied |
| `tasks/resubscribe` | `SubscribeToTask` | §3.4 denied |
| `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` | §3.4 denied |
| — | `ListTasks` | §3.4 denied |

---

## 4. Params surface (normative)

`MessageSendParams` members MUST be allowlisted. This profile accepts exactly
one member, `message`; a params-level `metadata` and any unrecognised sibling
MUST be denied.

`Message` members MUST be allowlisted against the A2A v0.3.0 surface (`role`,
`parts`, `messageId`, `taskId`, `contextId`, `metadata`, `kind`). A duplicated
member name MUST be rejected at parse — not last-wins, not first-wins (MCP
profile §2.2).

Member names are matched in the lowerCamelCase the A2A specification mandates
for every JSON serialisation (A2A §5.5, "MUST use camelCase"). Proto3's JSON
parser also accepts snake_case on input and a hand-rolled client might send
it; this profile refuses it, deliberately, on every path. Accepting both
spellings would double every allowlist and the digest would still be computed
over one of them; the specification's MUST is the allowlist.

A2A v1.0 adds members this profile has not classified, and the allowlists
refuse them: `Message.extensions`, `Message.referenceTaskIds` (names other
tasks the agent should read for context — a disclosure control at least), and
the params-level `tenant` (routes the request to a different agent behind the
same endpoint — a target). Each needs a binding decision before it is
forwarded; until one is made they are denied, which is what an allowlist is
for.

### 4.1 `configuration` — three tiers, not one decision

`MessageSendConfiguration` is not a homogeneous field, and treating it as one is
the mistake this section exists to prevent. Its four members fall into three
classes with three different answers:

**Tier 1 — a capability grant. `pushNotificationConfig` (v1.0:
`taskPushNotificationConfig`).**
It carries a URL and authentication material: the same webhook as
`tasks/pushNotificationConfig/set` (§3.4), reachable inside a single
`message/send`. Both spellings MUST land on the same receipt rule path
(`rpc.webhook-refused`), not the generic unrecognised-member path: the signal
that distinguishes an attack from a client bug is the point of the rule. A caller who can set it can redirect the results of a message
they were authorized to send. It MUST NOT be forwarded unbound. It MUST either
be refused, or be covered by the intent digest so the minter names the
destination. A token that authorizes "send this content to this agent" does not
authorize "and copy the results to this host", and no ergonomic argument reaches
this tier.

**Tier 2 — a disclosure control. `historyLength`.**
It governs how much prior conversation is returned. Letting the caller choose it
is letting the caller choose how much history to extract. It SHOULD be bound
into the intent digest, or clamped by policy at the PEP. It MUST NOT be
forwarded unbound and unclamped.

**Tier 3 — presentation and transport. `acceptedOutputModes`, `blocking`
(v1.0: `returnImmediately`).**
These change how the answer is shaped and whether the call returns immediately.
They do not change what the agent does, and they do not change who sees the
result. They MAY be forwarded unbound. v1.0 replaced `blocking` with
`returnImmediately`, the same knob with the sense inverted; a member that is
`blocking`'s complement cannot be in a different tier from `blocking`.

The implementation applies this tiering: tier 1 is refused with its own rule
path, tier 2 is bound into the digest, tier 3 is forwarded unbound, and any
other member is refused. An earlier implementation refused `configuration`
entirely as an interim; that interim is over.

---

## 5. Credential carriage

The token travels in `params.message.metadata["spt-txn/token"]` — the direct
analogue of MCP's `params._meta["spt-txn/token"]`.

The PEP MUST strip that key before forwarding, and MUST remove `metadata`
entirely if stripping empties it, so that no residue signals to the agent that a
credential was present. If the PEP cannot prove the credential was removed, it
MUST NOT forward (rule path `rpc.strip-failed`).

That position is the ONLY one accepted. A send whose request carries the token
key anywhere else -- a part's `metadata`, the interior of a data part,
`configuration`, at any depth -- MUST be refused (`rpc.credential-misplaced`),
not stripped: `parts` are bound into the digest and `configuration` is content
the agent acts on, so rewriting either would forward something other than what
was authorized. The check runs on the stripped request, before the decision, so
a misplaced credential neither records a permit nor consumes the `jti`.

On the read-only passthrough (§3.3) there is no credential to strip; a read
that carries the token key anywhere MUST be refused (`rpc.credential-on-passthrough`).

Under the token key, at any position, the wrapped agent never sees, stores or
re-presents the credential (THREAT-MODEL §4.6). A client that ships its secret
under some other member name has shipped a string the PEP cannot tell from
data; the allowlists in §3.3 and §4 keep such a string from being forwarded as
an unrecognised member, but cannot recognise it as a secret. That is the
boundary of the claim.

---

## 6. Transport profile (`cmd/a2a-pep`)

A2A rides JSON-RPC over HTTP, so the profile has obligations below the body that
the middleware cannot discharge.

### 6.1 Agent card rewriting

An agent card names the endpoint clients should talk to. A PEP that relays the
wrapped agent's card unmodified publishes the address of the agent *behind* the
enforcement point, and the first thing any compliant client does with that card
is route around the PEP. The enforcement point ships its own bypass.

**This is established practice, not an observation of this profile's.** Kong's
AI A2A Proxy rewrites the card's `url` and its `additionalInterfaces[].url` to
the gateway address; Gravitee and Agentgateway ship A2A proxies of the same
shape. One protocol out, Azure API Management rewrites an OpenAPI document's
`servers` block to the gateway rather than the backend, and rewriting OIDC
`.well-known/openid-configuration` at a reverse proxy has many independent
implementations. This section is written to say what THIS profile requires, not
to claim the requirement is new.

Two requirements below diverge from that practice, deliberately:

- Kong REWRITES `additionalInterfaces[].url` to the gateway. This profile
  DROPS those entries (rule 3). A JSON-RPC PEP cannot enforce a gRPC interface,
  so rewriting one advertises a route the enforcement point does not guard.
- Kong derives the gateway address from `X-Forwarded-*` headers. This profile
  requires the operator to state it (rule 1), because a value reconstructed
  from forwarded headers is influenced by the caller.

Therefore:

1. Card relay MUST be disabled unless the operator supplies the URL clients
   reach the PEP on. A PEP with nothing to advertise serves no card.
2. When relaying, `url` MUST be replaced with the PEP's own address.
3. `additionalInterfaces` MUST be dropped, not rewritten. Every entry is a
   second address on a transport this PEP does not enforce; a gRPC interface
   cannot be pointed at a JSON-RPC proxy, and keeping it would advertise a
   bypass that happens to look authorized. An operator who needs those
   transports guarded needs a PEP for those transports, not a card implying one
   exists.
4. Dropping them MUST be reported to the operator. A multi-transport agent
   silently degraded to JSON-RPC only leaves its gRPC clients unable to discover
   an endpoint, with nothing anywhere saying why. A card that misleads is what
   rules 1 to 3 prevent; a card that silently loses capability is the same
   defect facing the other way.
5. The advertised URL MUST be validated as an absolute http(s) URL before it is
   published. Rule 1 requires the operator to state the address precisely
   because a stated value can be trusted where a reconstructed one cannot --
   which only holds if the stated value is checked.
6. **A2A v1.0 cards.** v1.0 removed `url`, `preferredTransport` and
   `additionalInterfaces` and names every endpoint in one ordered array,
   `supportedInterfaces`, whose entries carry `url`, `protocolBinding` and
   `protocolVersion`. Rules 2 to 4 apply per entry: every entry whose
   `protocolBinding` is exactly `JSONRPC` and whose `protocolVersion` is one
   the PEP forwards under (`0.3` or `1.0`, §6.4) MUST be re-advertised at the
   PEP's address with that `protocolVersion` carried unchanged; every entry on
   any other binding or version MUST be dropped and counted. `protocolVersion`
   is REQUIRED in v1.0; an entry without one MUST be refused. A JSONRPC entry naming a
   `tenant` MUST be refused (v1.0 requires clients to echo it in every request
   and §4 refuses that member). A card with no JSONRPC entry MUST be refused
   rather than given one. A card that carries neither `url` nor
   `supportedInterfaces` names no endpoint the PEP can rewrite and MUST be
   refused, not relayed: the version of this profile that knew only v0.3.0
   relayed v1.0 cards untouched, and silence was the defect.
7. **Signatures.** v1.0 lets a card carry detached JWS signatures (RFC 7515)
   over its RFC 8785 canonical form, in a top-level `signatures` array. The
   rewrite in rules 2 to 6 changes that form, so an upstream signature no
   longer covers what is relayed. `signatures` MUST be stripped and the
   stripping MUST be reported to the operator alongside rule 4's count. A
   relayed card is honestly unsigned; a relayed card carrying the upstream
   signature would look authenticated and not be. Re-signing as the PEP is
   the intended eventual behaviour (the PEP is the authority for the endpoint
   it advertises) and requires a PEP signing key and the v1.0 field-presence
   canonicalisation; it is not part of this profile yet.

8. **The card is an allowlist.** Every top-level member MUST be on the union
   of the v0.3.0 and v1.0 AgentCard surfaces, matched exactly and
   case-sensitively, with duplicates refused; a card carrying any other member
   MUST be refused, not relayed. Exact case is load-bearing: Go's
   `encoding/json` decodes `"Url"` into a `json:"url"` field, so a relayed
   `Url` IS the upstream address to a Go client, and a rewrite keyed on the
   exact spelling alone let it through. Every member relayed as-is MUST also
   have the JSON type both dialects' schemas give it (string, boolean, array
   of strings, or a typed object), and `null` is none of those: a name-only
   allowlist is a denylist on shape, and an object where a boolean belongs is
   a container for anything, the upstream address included. `capabilities`
   and each entry of `skills` are allowlisted and typed the same way.
9. **URL- and auth-bearing members are dropped by name and reported.**
   `iconUrl`, `documentationUrl`, `provider`, `securitySchemes`, `security`,
   `securityRequirements` and `capabilities.extensions` MUST be removed and
   named to the operator. The first three are informational URLs the PEP
   cannot tell apart from the agent's own host without a denylist of hosts;
   the security members describe an authentication path that does not work
   through this PEP (§6.2 forwards no client header, and the credential
   travels in the body) at endpoints that may be the agent's; extensions are
   negotiated through a header this PEP does not forward. `skills[].security`
   (v0.3.0) and `skills[].securityRequirements` (v1.0) reference scheme names
   defined by the dropped `securitySchemes` and MUST be dropped with it.
   `skills`, `defaultInputModes`, `defaultOutputModes`, `name`,
   `description`, `version` and `protocolVersion` are relayed typed: in both
   schemas they are free text, identifiers and media types with no URL-typed
   member.
10. **The relayed card is deliberately silent on authentication.** Having
    dropped the agent's schemes, the PEP advertises none of its own. The
    SPT-Txn credential is a member of the message body specified by §5 of
    this profile, not an HTTP security scheme: no `SecurityScheme` type in
    either dialect (apiKey, http, oauth2, openIdConnect, mutualTLS) describes
    it, and advertising one would send a conforming client's credential into a
    header this PEP does not read. A card with no `securitySchemes` says "no
    HTTP-layer authentication is demanded here", which is true of the PEP.
    How a caller obtains and presents an SPT-Txn token is this profile's
    business, not the card's; a future revision MAY declare it through
    `capabilities.extensions` once the PEP forwards extension negotiation.

### 6.2 Header isolation

No client header is copied upstream. Stripping the credential from the body and
then forwarding the caller's `Authorization` or `Cookie` hands the wrapped agent
a different credential for the same caller — the confused-deputy hole of §5, one
layer down.

This SHOULD be structural rather than checked: the forwarding function receives
the token-stripped body and nothing else, so no header map is in scope to copy.
A refactor that threads the client request downward (to reuse a trace header,
or to adopt a general-purpose reverse proxy) reopens this in one line and MUST
be treated as a change to the trust boundary.

### 6.3 Transport rules

1. Exactly two requests exist: POST on the JSON-RPC path, GET on the card path.
   There MUST be no default branch that forwards.
2. The request body MUST be capped before the enforcement point is consulted.
3. A `text/event-stream` answer from the wrapped agent MUST be refused, not
   relayed: relaying it returns content the enforcement point never saw.
4. A redirect from the wrapped agent MUST NOT be followed. Following one sends
   an authorized request to a host the operator never configured.
5. A denial MUST be HTTP 200 carrying a JSON-RPC error. The refusal is uniform
   by design (§7); a distinguishable status code restores the oracle the uniform
   body exists to remove.

---

### 6.4 A2A-Version

A2A v1.0 clients send `A2A-Version: <Major.Minor>` and servers parse the body
under that version's semantics, treating an absent header as `0.3`. The
reference client sets the header from the `protocolVersion` of the interface
entry it selected in the card; the reference server routes `0.3` (and absent)
to its legacy handler and `1.0` to the current one. A PEP that forwards no
client header (§6.2) and sets no version of its own therefore has a v1.0-native
agent parse every forwarded v1.0 body as v0.3.0 -- where `SendMessage` does not
exist -- or reject it, after the PEP has already recorded a permit.

Therefore:

1. The middleware MUST classify every forwarded request into a dialect from
   the method name it recognised (`message/send` and the slash-namespaced
   reads are `0.3`; `SendMessage` and the renamed reads are `1.0`), and hand
   that dialect to the transport with the request.
2. The transport MUST set `A2A-Version` on the forwarded request from that
   dialect and from nothing else. The caller's own `A2A-Version` is a caller
   header like any other (§6.2) and MUST NOT be consulted: a version the
   caller chose would have the agent parse an authorized body under semantics
   the PEP did not check it against -- a parser differential between the
   enforcement point and the thing it guards.
3. The transport MUST send only the values the middleware can produce and MUST
   refuse to forward under any other, rather than send unversioned.
4. The card MUST re-advertise only JSONRPC interfaces on versions the PEP
   forwards under (§6.1 rule 6), so that the version a client derives from the
   card is one the PEP will set.

**Permit ordering, recorded and not changed.** The decision engine records the
permit and consumes the `jti` at `Decide`, before `Forward`. A forward that
fails -- the agent is down, or rejects the version -- therefore costs the caller
its single-use token: the retry is refused as `replay.duplicate`. This is
deliberate at-most-once semantics. Releasing the `jti` on "upstream failed"
would release it on "upstream executed and the response was lost", which is a
double-execution primitive on exactly the transactions this token exists to
scope; a reserve-then-commit scheme would need the agent's cooperation to be
safe. The consequence for clients is that a retry needs a fresh token. This
section changes nothing about it and records it because §6.4 is what routes
v1.0 traffic through it.

## 7. Uniform refusal

Every denial returns one message. The failing check is recorded in the receipt,
which the operator reads, and not in the error, which the caller reads. A caller
who can distinguish "wrong audience" from "digest mismatch" from "replayed jti"
can search for a token that works.

---

## 8. What this profile does not do

It does not evaluate whether the declared message is *wise* — that is the policy
layer. It does not authenticate the human principal — that is issuance
(CAT/IdP exchange). It does not model streaming, and refuses rather than
pretends. It does not guard transports other than JSON-RPC over HTTP, and §6.1
requires it to stop advertising the ones it does not guard.

It constrains a holder to its declared action. State this plainly; do not
overclaim.
