# SPT-Txn Specification — Token Status List (revocation at scale)

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/statuslist`, verifier integration (`Engine.StatusResolver`).
**Aligns with:** IETF `draft-ietf-oauth-status-list-21` (Token Status List).
**Threat model:** `docs/THREAT-MODEL.md` §3.3 (revocation gap), §4.6 fail-closed.

---

## 1. Why

Issuer-key-cascade revocation (revoke a delegator's key → its whole subtree
dies) is coarse and immediate but blunt: it kills *everything* an issuer
signed. Per-token revocation needs a mechanism that (a) scales to millions of
tokens, (b) is checkable **offline** by a verifier holding a cached snapshot,
and (c) fails closed when the snapshot is missing or stale. A Token Status
List gives all three: one small, signed, compressed bit array encodes the
status of every token an issuer minted.

This complements, does not replace, key-cascade revocation. Key cascade is the
break-glass; the status list is the routine, granular, scalable path.

## 2. Status List (normative)

A Status List assigns each referenced token an **index** into a bit array.
Each entry is `bits` wide (`bits` ∈ {1, 2, 4, 8}), encoding a status value:

| Value | Name | Meaning (this profile) |
|---|---|---|
| 0 | VALID | token is not revoked or suspended |
| 1 | INVALID | token is **permanently revoked** → DENY |
| 2 | SUSPENDED | token is **temporarily suspended** → DENY (distinct reason) |
| 3+ | (reserved) | application-specific; unknown values fail closed to DENY |

The array is compressed with DEFLATE (RFC 1951) in the ZLIB (RFC 1950) data
format, then base64url-encoded (no padding) as `lst`. Serialized form matches
the IETF draft:

```json
"status_list": { "bits": 1, "lst": "<base64url(zlib(deflate(bitarray)))>" }
```

## 3. Status List Token (normative)

The list is distributed inside a **signed Status List Token** — a JWT with:

- header `typ: statuslist+jwt`, `alg: EdDSA` (allowlisted; `alg: none` rejected)
- `sub`: the Status List URI (identifies this list)
- `iat`: issuance time
- `exp`: expiry — a verifier MUST reject an expired Status List Token and
  treat the referenced statuses as **unavailable** (fail closed)
- `ttl` (optional): seconds a cached copy may be considered fresh
- `status_list`: the object from §2

The signing key is the issuer's **status key**, distinct from its token
issuance key (same separation-of-duties rationale as the log signing key,
`docs/THREAT-MODEL.md` §3.5), resolved from the Trust Registry
(role `status_issuer`).

## 4. Referenced token binding (normative)

A CAT / CT / SPT-Txn token that participates in status-list revocation carries
a `status` claim:

```json
"status": { "status_list": { "idx": 1234, "uri": "https://issuer.example/statuslists/9" } }
```

- `idx` MUST be within the list's length; an out-of-range index fails closed.
- `uri` selects which list; the verifier resolves it from its local cache.
- A token **without** a `status` claim is not subject to status-list
  revocation (it relies on key-cascade + short TTL alone). Absence never
  upgrades a revoked token to valid — it simply is not in scope for this
  check. Deployments that require status coverage reject a status-less token
  by policy.

## 5. Verifier behavior (normative)

When a verifier is configured with a `StatusResolver` and a presented token
carries a `status` claim:

1. Resolve the signed Status List Token for `uri` from the local cache.
   - Not cached, signature invalid, wrong `sub`, or expired ⇒ DENY, class
     `unavailable`, reason `status-unavailable`. **Never** treat an
     unresolvable list as "valid."
2. Read the `bits`-wide value at `idx`.
   - `0` (VALID) ⇒ pass this check.
   - `1` (INVALID) ⇒ DENY, class `violation`, reason `status-revoked`.
   - `2` (SUSPENDED) ⇒ DENY, class `violation`, reason `status-suspended`.
   - any other value or out-of-range `idx` ⇒ DENY, class `violation`, reason
     `status-unknown` (fail closed on unknown states).
3. The check runs for **every** token in the chain that carries a `status`
   claim (root CAT and each CT), not only the leaf — a revoked intermediate
   invalidates the chain.

Distribution of the signed list to verifiers is out of band (pull from the
`uri`, push to a cache, or bundle with the Trust Registry snapshot). The
verifier only ever consumes a **signed** list; it never fetches status in the
hot authorization path (offline-first).

## 6. Non-goals

- We do not define the issuer's status-management workflow (when to set a bit)
  — that is operational.
- We do not carry PII or token contents in the list — it is a pure bit array
  indexed by position.
- Real-time (per-request network) status lookup is explicitly avoided: it
  reintroduces a call-home the offline model exists to remove.
