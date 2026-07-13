# SPT-Txn P3 Specification — Gateway Form Factor (Skins over One Decision Core)

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/decision`, `cmd/extauthz`, `cmd/opashim`, `internal/mcppep`.

---

## 1. Architecture rule

Three thin skins over **one** decision core:

    Envoy ext_authz  ┐
    OPA decision API ├──►  internal/decision.Engine  ──►  receipts
    MCP middleware   ┘

Skins are stateless, hold no signing keys, and contain **no decision logic**.
A compromised skin can deny service; it MUST NOT be able to mint authority.
If a change would let a skin influence a decision, that change moves the skin
inside the trust boundary — reject or re-scope it (THREAT-MODEL §1).

**Structural deny-by-default:** the core returns an opaque `Decision` value
that can only be constructed by the engine. A skin cannot fabricate a permit;
an error path that loses the decision object has nothing to forward and the
skin's zero-value answer is deny. It is impossible to construct a request
that "passed through" without a decision attached (CLAUDE.md §2).

**Latency is a security requirement:** decision path budget p99 < 10 ms. The
skins add serialization only.

## 2. Envoy `ext_authz` (HTTP mode)

- Endpoint: `POST /authz` receiving the ext_authz HTTP-service payload
  (request headers as JSON). Covers Istio, service mesh, and most API
  gateways by extension.
- Token: `x-spt-txn-token` request header. Declared intent: the PEP derives
  `intent.tool` from `:method`, `intent.target` from configured upstream
  identity, `intent.params` from the digest-relevant headers profile.
- Response: `200` (permit; strips the token header before upstream — no
  credential passthrough) or `403` (deny; uniform body, receipt records the
  detail). Engine unreachable/timeout ⇒ `403`, class `unavailable`. Never
  5xx for a decision — Envoy fail-open configs treat 5xx as "authz service
  broken"; a decision is always an authz answer.

## 3. OPA-compatible decision API

- Endpoint: `POST /v1/data/spttxn/authz` accepting `{"input": {...}}`,
  answering `{"result": {"allow": bool, "class": "...", "receipt_ref": "..."}}` —
  the input/output shapes existing OPA integrations already send and expect.
  Every existing OPA integration point becomes an SPT-Txn integration point
  for free.
- `allow` is `true` only on a `PERMIT` from the core. Absent fields, wrong
  types, unparseable input ⇒ `{"result": {"allow": false, "class": "violation"}}`.
- The shim performs **no** Rego evaluation and holds **no** policy. It is a
  socket shape, nothing more.

## 4. MCP middleware

Shared with P1 — see `docs/spec/DELEGATION-INTENT-MCP.md` §3. Same core,
agent-shaped socket.

## 5. Deployment bar

Deployable in an afternoon by someone else's platform team, or it does not
count: single static binary per skin, one YAML/env config (core address,
trust-registry keys, jurisdiction profile), no database, health endpoint,
structured logs to stdout.
