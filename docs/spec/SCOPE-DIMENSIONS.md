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
`token_hash`, so a receipt together with its token does present the scope. A receipt
on its own reproduces **no** scope dimension.

**One name collision, stated because it invites exactly the wrong inference.** The
receipt has a `jurisdiction` field and a `capability_scope` may have a
`jurisdiction` dimension. **They are unrelated.** The receipt's field is set from
the enforcement point's own configuration; nothing reads the scope's dimension.
Consumers MUST NOT read the receipt's `jurisdiction` as a statement about the
presented token, and MUST NOT expect the two to agree — nothing binds them, so an
auditor cannot detect a disagreement.

## 5. Adding a dimension

An author adding a dimension to the vocabulary MUST determine which half of this model
it belongs to, and record the answer:

1. Is there a `ledger.TxnContext` field it can be compared against? If not, it is
   delegation-only, and that MUST be stated where the dimension is introduced.
2. If it is numeric, it MUST additionally declare a direction in
   `tbac.numericDirection` — there is no default, because guessing whether a number is
   a ceiling or a floor is the error that registry exists to prevent.

## 6. The classification registry (normative)

Every dimension MUST be registered with its kind before it can be sealed into a token.
`tbac` holds the registry; `ValidateIssuance` enforces it.

- `execution-asserted` — the dimension is projected by `TxnScope` and compared against
  the transaction. Registering a dimension this way is a claim that such a comparison
  exists; it MUST NOT be used to express an intention.
- `delegation-only` — the dimension constrains the chain and nothing else.

**There is NO default kind and there MUST never be one.** An unregistered dimension has
an undecided kind, and a scope carrying one is refused at issuance. This mirrors
`numericDirection`, which refuses an unregistered numeric dimension for the same
reason: the registry exists so that the answer is decided once, in the open, by
whoever adds the dimension — and a default would silently supply an answer nobody
chose.

Registration rules:

- **Object-valued dimensions are registered too.** A container is a dimension like
  any other: containment evaluates it, and a child that drops the whole object drops
  the constraint. Classifying only its members would exempt the container name, and
  would exempt an EMPTY container entirely — it has no members to classify in its
  place. A nested dimension is additionally registered under its own **leaf** name,
  because containment and intersection recurse per dimension — `region.tier`
  resolves to `tier`.
- Adding an entry is a security decision, not bookkeeping. The question is not
  *"what did I mean by this?"* but *"is there a `ledger.TxnContext` field this is
  compared against today?"* If there is not, it is `delegation-only`, whatever the
  name suggests.
- A dimension MUST NOT be registered `execution-asserted` in anticipation of a
  projection that does not exist yet. That would restore exactly the reading §3
  forbids, with the registry's authority behind it.

### 6.1 Both directions are asserted

The registry is a statement about the code, so both halves are tested, not just the
safe one:

- every dimension registered `execution-asserted` MUST be projected by `TxnScope`;
- everything `TxnScope` projects MUST be registered `execution-asserted`.

The second is the one with teeth. Without it a projection added later would silently
make a dimension enforced while this specification still told a second
implementation it was not — two implementations evaluating the same claim
differently, which is the bug class this project ranks first.

`kindOf` MUST remain a lookup. A naming convention ("anything beginning `max_` is a
ceiling") would let it answer for dimensions nobody classified, which is the
anti-pattern `numericDirection` already forbids for the same reason.

### 6.2 Compatibility

The registry is seeded with the vocabulary the package actually evaluates — obtained
by instrumenting `Contains`, `Intersect` and both passes of `ValidateIssuance` and
running the full suite, because reading call sites missed five dimensions the first
time. Classified as they behave today, so enabling the check changes no existing
behaviour for that vocabulary. The guard bites only on a dimension whose kind nobody
has decided.

It is nonetheless a **breaking change for operators**: a service that loads a
policy-permitted scope ceiling from configuration (`cmd/idp-bridge`,
`cmd/workload-bridge`) calls `ValidateIssuance` at startup precisely so a malformed
ceiling fails the deploy rather than the first request. A deployment whose configured
scope carries an unregistered dimension will fail to start. That is the intended
direction of failure, and it MUST be in the release note.
