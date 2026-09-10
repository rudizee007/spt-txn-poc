# SPT-Txn Specification — Scope dimensions: delegation constraints and execution assertions

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/tbac` (`Contains`, `TxnScope`, `ValidateIssuance`),
`internal/verifier` (`step6Chain`, `step7Scope`), `internal/txntoken`.

A `capability_scope` is a set of named dimensions. This document states, normatively,
**what a dimension does** — because the two things a dimension can do are different,
and the difference is not visible from the scope itself.

---

## 1. Every dimension constrains delegation

`tbac.Contains(parent, child)` is evaluated at every delegation hop. A child MUST NOT
hold authority on a dimension its parent did not hold, and on each dimension the
child's value MUST be within the parent's, per the per-type semantics documented in
the `tbac` package comment.

Dropping a dimension in a child does not widen authority at transaction time: the
verifier computes the **intersection** of every scope from the root CAT to the leaf
(`verifier.step6Chain`) and evaluates the transaction against that intersection, so a
ceiling omitted by an intermediate hop is inherited from the nearest ancestor that
still declares it.

This half of the model applies to **every** dimension, whatever it is named.

## 2. A subset of dimensions is additionally asserted against the transaction

Containment answers *"may this holder delegate this?"* It does not by itself answer
*"does the transaction in front of us satisfy this?"* The second question is answered
only for dimensions that `tbac.TxnScope` projects from a `ledger.TxnContext`.

`TxnScope` projects exactly three dimensions:

| Dimension | Projected from | Asserted at execution |
|---|---|---|
| `max_amount` | `TxnContext.Amount` | **yes** |
| `max_cumulative` | `TxnContext.Amount`, against the cumulative budget | **yes** |
| `currency` | `TxnContext.Currency` | **yes** |
| every other dimension | — | **no** — delegation only |

Both enforcement points inherit this set: `txntoken.Issue` at issuance and
`verifier.step7Scope` in the full verification, each of which calls
`TxnScope` and then `Contains`.

`Contains` iterates the **child** scope, so a dimension the projection does not
mention is not examined. This is the specified behaviour of a projection that, per its
own contract, asserts containment "only where the capability speaks" — not a defect in
`Contains` or in `TxnScope`.

### 2.1 Why some dimensions cannot be execution-asserted

`ledger.TxnContext` is the canonical transaction description shared by every rail
adapter. A dimension has nothing to be compared against unless the context carries a
corresponding field. `tier` and `region`, for example, have no counterpart in
`TxnContext` and are therefore **legitimately delegation-only**: they shape who may
hold and pass on a capability, not what a given transaction may be.

This is a deliberate boundary, not an omission. `TxnContext` is canonicalized into
`spt_txn_context_hash` by every ledger adapter, so adding a field to it changes that
preimage on every rail — a change that MUST NOT be made casually, and never to give a
single dimension something to compare against.

## 3. How `capability_scope` MUST be read

A dimension's presence in a `capability_scope` is evidence that **the delegation
chain was constrained on that dimension**. It is **NOT** evidence that the action
performed was checked against it.

Consumers of a token or a receipt:

- MUST NOT infer from `capability_scope` alone that a named constraint was evaluated
  against the transaction.
- MUST treat the table in §2 as the authoritative list of execution-asserted
  dimensions for this version.
- SHOULD, where a stronger statement about what was *done* is required, rely on the
  intent digest (`internal/intent`, see `docs/spec/DELEGATION-INTENT-MCP.md` and
  `DELEGATION-INTENT-A2A.md`), which binds the invoked tool and its arguments
  byte-exact. That is a materially stronger statement than any scope string.

## 4. Where the claim travels

`capability_scope` is carried in the **token**, not in the Transaction Receipt. The
receipt (`docs/spec/RECEIPT-FORMAT.md`) commits to the token it evaluated via
`token_hash`, so a receipt together with its token does present the scope — but a
receipt on its own carries only `jurisdiction` from the set in §2's final row.

`jurisdiction` is therefore the one unasserted dimension a receipt reproduces
directly, and `RECEIPT-FORMAT.md` states its meaning accordingly.

## 5. Adding a dimension

An author adding a dimension to the vocabulary MUST determine which half of this model
it belongs to, and record the answer:

1. Is there a `ledger.TxnContext` field it can be compared against? If not, it is
   delegation-only, and that MUST be stated where the dimension is introduced.
2. If it is numeric, it MUST additionally declare a direction in
   `tbac.numericDirection` — there is no default, because guessing whether a number is
   a ceiling or a floor is the error that registry exists to prevent.

At this version the first question is a **review obligation, not a mechanical check**:
nothing refuses a dimension whose classification has not been decided. Treat it as
part of the spec-first step for any scope change, and do not rely on tests to surface
it — a dimension that is never asserted produces no failing test.
