package tbac

import "errors"

// ErrUnregisteredDimension is returned by ValidateIssuance for a scope carrying a
// dimension whose kind has not been declared in dimensionKind.
var ErrUnregisteredDimension = errors.New("scope dimension has no declared kind")

// dimensionKindT says what a dimension actually constrains.
//
// Every dimension constrains DELEGATION: Contains narrows parent to child at each
// hop, and the verifier evaluates a transaction against the intersection of the
// whole chain. Only some dimensions are additionally compared against the
// transaction, and only because TxnScope projects them out of a ledger.TxnContext.
// The two are not interchangeable, and which one a dimension is cannot be guessed
// from its name — "action" reads like a statement about what may be done and is
// not one.
//
// See docs/spec/SCOPE-DIMENSIONS.md.
type dimensionKindT int

const (
	// kindExecutionAsserted: TxnScope projects this dimension, so a transaction is
	// compared against it at issuance and at the verifier's scope step.
	kindExecutionAsserted dimensionKindT = iota
	// kindDelegationOnly: this dimension constrains the chain and nothing else.
	// There is nothing in ledger.TxnContext to compare it against.
	kindDelegationOnly
	// kindRailAsserted: a RAIL-SPECIFIC projection compares this dimension against
	// the action, but TxnScope does not project it.
	//
	// TxnScope projects a ledger.TxnContext, which is the rail-independent
	// description of a transaction. A rail profile may define its own projection
	// over its own call shape and compare the result with Contains; such a
	// dimension is genuinely asserted at execution on that rail, and is genuinely
	// not asserted by the ledger projection.
	//
	// Neither other kind can describe that without lying. kindExecutionAsserted
	// would claim TxnScope projects it, which the test below disproves;
	// kindDelegationOnly would claim nothing compares a transaction against it,
	// which is false on that rail. A profile registering a dimension here MUST name
	// the projection that asserts it, in the comment on its entry, so the claim can
	// be checked against code rather than taken on trust.
	//
	// There are no entries yet. The kind exists because the alternative is a
	// registry that is wrong for the first rail profile that needs it.
	kindRailAsserted
)

// dimensionKind declares every scope dimension this package will seal into a
// token. There is NO default entry and there must never be one: an unregistered
// dimension has an undecided kind, and supplying one by default is exactly the
// silent answer this registry exists to prevent. Same rule, same reason, as
// numericDirection.
//
// Nested dimensions are registered by their own LEAF name, because Contains and
// Intersect recurse per dimension — `region.tier` is registered as "tier".
// Registration is per dimension NAME, and a name needs an entry whenever it can
// appear as a LEAF. A name used only ever as an object container does not:
// validateIssuance recurses into it and classifies its members, so `limits` is
// deliberately absent. `region` IS registered, because the tree uses it both ways —
// as a container (`region: {tier: 2}`) and as a leaf (`region: "EU"`) — and the
// leaf form is a constraint like any other.
//
// Adding an entry is a security decision, not bookkeeping. The question is NOT
// "what did I intend this to mean?" but "does TxnScope project it today?" If it
// does not, it is kindDelegationOnly whatever the name suggests. Registering a
// dimension kindExecutionAsserted in anticipation of a projection that does not
// exist yet would put this registry's authority behind a claim the code does not
// make — which is worse than leaving it unclassified, because it reads as decided.
var dimensionKind = map[string]dimensionKindT{
	// Projected from TxnContext.Amount.
	"max_amount": kindExecutionAsserted,
	// Projected from TxnContext.Amount against the cumulative budget.
	"max_cumulative": kindExecutionAsserted,
	// Projected from TxnContext.Currency, and the unit that makes the two ceilings
	// above mean anything.
	"currency": kindExecutionAsserted,

	// Delegation-only. ledger.TxnContext carries no action/kind field, so there is
	// nothing to compare this against. It bounds which capabilities may be derived
	// from this one, not what a transaction may be. Giving it teeth would mean
	// adding a field to TxnContext, which is canonicalized into the context hash by
	// every rail adapter — see docs/spec/SCOPE-DIMENSIONS.md §2.1. The intent digest
	// already binds the invoked tool and its arguments byte-exact, which is a
	// stronger statement about what was done than this string can be.
	"action": kindDelegationOnly,
	// Delegation-only: a privilege level, with no counterpart in TxnContext.
	"tier": kindDelegationOnly,
	// Delegation-only: the generic nested bound inside a `limits` object. It takes
	// its meaning from whatever object carries it and is not projected.
	"max": kindDelegationOnly,
	// Delegation-only: a geographic or organisational region. No counterpart in
	// TxnContext. Appears both as a leaf and as a container of `tier`.
	"region": kindDelegationOnly,
	// Delegation-only: a LIST of permitted action names, narrowed by subset at each
	// hop. Same reasoning as "action" — TxnContext carries no action field, so the
	// set bounds what may be delegated, not what a transaction may be. Exercised by
	// the attenuation property test, which is the highest-value test in the
	// codebase; its widening case appends to this list.
	"actions": kindDelegationOnly,
	// Delegation-only: a sub-region, nested inside `region`. Registered by its LEAF
	// name because Contains and Intersect recurse per dimension.
	"zone": kindDelegationOnly,
	// Delegation-only containers. A name used as an object is still a dimension --
	// Contains evaluates it and a child dropping the object drops the constraint --
	// so the container name is classified and its members are classified in turn.
	"limits": kindDelegationOnly,
	"route":  kindDelegationOnly,
	// Delegation-only: a list of permitted payment methods, narrowed by subset.
	// Structurally identical to "actions".
	"methods": kindDelegationOnly,
	// Delegation-only: a boolean permission flag. TxnContext has no counterpart.
	"refund": kindDelegationOnly,
	// Delegation-only: this package's canonical FLOOR example -- a minimum
	// acceptable output. Registered for completeness; numericDirection refuses it
	// first, because this package cannot yet express a floor and registering one as
	// a ceiling would authorize accepting an arbitrarily bad output. A kind entry
	// does NOT make it usable.
	"min_out": kindDelegationOnly,
	// Delegation-only: names the jurisdiction profile a capability was issued under.
	// Nothing in this tree reads it. In particular it is NOT the source of the
	// receipt's `jurisdiction` field, which decision.go sets from the PEP's own
	// configuration — the two are independent values that happen to share a name,
	// and nothing binds them to each other.
	"jurisdiction": kindDelegationOnly,
}

// kindOf reports the declared kind for a dimension. The second return is false for
// an unregistered dimension; callers must fail closed on it rather than assuming.
func kindOf(dim string) (dimensionKindT, bool) {
	k, ok := dimensionKind[dim]
	return k, ok
}
