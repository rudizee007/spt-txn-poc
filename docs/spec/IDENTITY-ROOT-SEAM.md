# SPT-Txn Identity-Root Seam

**Status:** v0.1. **Companion code:** `internal/identityroot`, `internal/zkdidmock`,
`internal/civicpass`, `internal/cattoken` (the `IdentityAnchor` seam),
`cmd/civicdemo`. **Related:** the `humanAnchor` in `internal/zkdid` and
`draft-coetzee-oauth-spt-txn-tokens` §5.4.

## Why this exists

SPT-Txn carries a commitment to the authorizing human — the `humanAnchor` — from
the root CAT, unchanged, through every delegated capability token and every
transaction token, so any tool call traces back to the accountable person without
exposing them. But SPT-Txn does not itself establish that the person is a
*genuine, unique human*. That claim comes from an **identity root**: a personhood
or uniqueness provider.

The design decision this document records: **the identity root is a pluggable
interface, not a hard dependency on any one provider.** SPT-Txn is not blocked on
the timeline of any single personhood system. It consumes a verified attestation
from whatever root is available — Civic Pass, the Solana Attestation Service, or a
future `.zkdid` — behind one seam, and the issuance and verification code never
changes when the root is swapped.

## The seam

`internal/identityroot` defines the whole contract:

```go
type Assertion struct {
    Method    string           // provider tag, e.g. "zkdid-mock", "civic-pass"
    Anchor    zkdid.Commitment // fresh per issuance; sealed as the CAT humanAnchor
    Nullifier [32]byte         // context-specific; stable per (subject, context)
    Context   string
    Proof     []byte           // root/adapter proof that personhood was vouched for
    IssuedAt  time.Time
}

type Provider interface {
    Resolve(ctx context.Context, subjectRef, contextLabel string) (*Assertion, error)
}
```

An identity root supplies three things, in a fixed shape, per `(subject,
context)`:

- a fresh **Anchor** (a zkDID commitment over BN254, Poseidon2) that the issuer
  seals as the CAT `humanAnchor` via `cattoken.IssueRequest.IdentityAnchor`;
- a context-specific **Nullifier** — stable per `(subject, context)` so a service
  can detect the same human enrolling twice in *its* context (Sybil resistance),
  yet unlinkable across contexts so two services cannot correlate the person;
- a **Proof** that a trusted root vouched for the above.

Issuance depends only on this interface. That is the entire point: swap the
provider, `cattoken.Issue` is unchanged.

## Two providers, one honest distinction

**`internal/zkdidmock` — a labelled MOCK. It *asserts* personhood.** It stands in
for the shape of a decentralised root (Toby Bolton's `.zkdid™` initiative,
https://zkd.id — a proposed integration, not implemented or endorsed) so the seam
can be exercised without a real root wired in. It proves nothing cryptographically
about personhood or uniqueness; it *asserts* them with a mock-authority signature
— which is exactly the centralised trust a real `.zkdid` removes. The package doc
says so loudly. Its role is the reference marker for "here is where the real root
plugs in."

**`internal/civicpass` — a real, VERIFYING adapter. It *verifies* someone else's
personhood.** It consumes an attestation a shipping root already issued — a Civic
Pass / Civic Proof-of-Personhood, or a Solana Attestation Service credential — and
maps it onto the seam. It mints nothing. `Present()` is the fail-closed gate:
unknown scheme, an untrusted attester, a claim not on the allowlist, a bad
signature, or an expired window all reject and store nothing. Only after a valid
attestation is presented does `Resolve()` return an anchor and nullifier, in an
adapter-signed assertion so downstream verification has the same shape as the
mock's.

The difference in one line: **the mock invents personhood; civicpass verifies a
personhood someone else established.** The trust anchor for civicpass is the Civic
gatekeeper network / the SAS attester — not our code.

## Nullifier and anchor semantics

- **Nullifier** is stable per `(subject, context)` and diverges across contexts.
  Within a context it lets a relying party detect the same human twice (Sybil
  resistance); across contexts two relying parties cannot correlate the same
  person. `civicpass` prefers a native, provider-computed per-context nullifier
  when the attestation carries one (the most private path — Civic and World ID
  compute these natively); otherwise it derives one keyed by an adapter secret.
- **Anchor** is freshly randomised on every `Resolve`, so tokens are unlinkable
  across issuances even for the same human — the property SPT-Txn already requires
  of its `humanAnchor`.

## Trust and linkability model (stated plainly)

The identity root and the adapter **can** link a subject across contexts — they
hold the subject reference. The nullifier only prevents *relying parties* from
correlating the same person across their respective contexts. This is exactly
Civic's and World ID's real model: the provider knows who you are; the apps do
not. A decentralised root like `.zkdid` is the design that removes even the
provider's ability to link, which is why it is the privacy-superior swap-in — but
it is not a precondition for shipping. Where the native per-context nullifier path
is used, the adapter itself needs no subject linkage at all.

## Where it seals into the token chain

`cattoken.IssueRequest.IdentityAnchor` takes a pre-computed 32-byte commitment and
uses it directly as the CAT `humanAnchor` (a non-32-byte value is rejected; empty
falls back to the POC test-principal derivation). From there the anchor propagates
unchanged into every downstream CT and SPT-Txn token, and the verifier's Human
Anchor step checks it is consistent across the whole chain. The identity root
therefore touches exactly one field at exactly one point — the cleanest possible
integration surface.

## What civicpass does *not* do yet

It does not read Solana directly. Real Civic/SAS state lives on-chain (a gateway
token / an SAS attestation account); a production deployment reads that account
and checks pass status against the gatekeeper network, then constructs the
`Attestation`. That on-chain read slots in behind `Present()` unchanged — this
tree stays offline and unit-tested, verifying the attester signature exactly as
the on-chain check would gate trust. The adapter models the verification and
mapping, not the RPC.

## Run it

```
go run ./cmd/civicdemo
```

The demo issues a stand-in Civic/SAS attestation, verifies it (and refuses an
impostor), resolves the same subject in two contexts to show the nullifier stay
stable within a context but diverge across them with a fresh anchor each time,
verifies the adapter assertion, seals the anchor into a real CAT, and then swaps
in the mock through the same interface to show the issuance code path is
unchanged.

## Posture

Civic Pass and the Solana Attestation Service are Solana-native and live today, so
a demo (or a hackathon entry) ships now on a real root. `.zkdid` is the proposed
privacy-superior swap-in for later. Building the seam and wiring a shipping
provider into it is a stronger collaboration signal to a decentralised-root
project than waiting: it demonstrates the integration point is real and
provider-agnostic. Other roots that fit the same seam without code changes include
World ID (native nullifiers, not Solana-native), Semaphore (the ZK
membership-plus-nullifier primitive, if building a root rather than consuming one),
and Privado ID / iden3.
