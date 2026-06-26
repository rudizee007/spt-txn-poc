# Scoping — `agentsvc` daemon + ZK delegation-chain proof (`zkChain`)

Design scope for the two deliberate next steps after the agentic MVP
(CT→CT delegation, N-hop verifier, revocation cascade — built and tested
2026-06-26). Neither is required for the MVP to function or demo; both are
productization/research steps. Grounded in the existing service pattern
(`cmd/catsvc`, `cmd/tr-svc`) and ZK stack (`internal/zkproof`, gnark Groth16 /
BN254 / Poseidon2, one circuit per `CircuitID`, one-time `cmd/zk-setup`).

---

## Part A — `agentsvc`: expose issue/delegate + verify as a live endpoint

### Why it exists, and the one honest boundary

The agentic capability layer is a *library* today (`cttoken.Delegate`,
`verifier.Engine`). `agentsvc` wraps it as an HTTP daemon for platforms that
want hosted issue/verify instead of embedding the library.

The boundary that must be stated up front: **verification is and stays
offline-first.** The whole Shape-C claim is that a verifier needs only the
library + a cached Trust Registry snapshot, no online call. A hosted
`/agent/verify` endpoint is a *convenience* for adopters who don't embed the
library — it must never become a *required* online dependency, or we have
re-introduced the online-availability/two-sided-adoption problem the design
exists to avoid. The library remains the primary path; the endpoint is optional.

### Two roles, very different trust profiles (mirror `tr-svc`'s role split)

`-role issue|verify|both` (env `SPT_AGENT_ROLE`), exactly like `tr-svc`'s
`originator|beneficiary|both`.

- **issue role — the authority side.** Holds a `ct_issuer` signing key; mints
  delegated CTs. This is the crown-jewel surface: the key *is* the authority to
  grant capability. Must be authenticated (cf. `catsvc` requiring a signed
  `subject_token` — issuance is never open).
- **verify role — the enforcement side ("Domain B").** Holds **no** signing
  key — only a Trust Registry snapshot and the verifier library. Runs the
  eight-step engine on a presented chain. Can run on untrusted/edge hosts with
  no secrets at all. Splitting the roles is privilege separation at the
  deployment level: the verifier process literally cannot mint anything.

### Endpoints

```
POST /agent/delegate   (issue role)   CT → CT delegation
POST /agent/verify     (verify role)  run the eight-step engine
GET  /agent/health
```

`POST /agent/delegate`
- Body (JSON): parent CT (compact JWT), requested narrower scope, sub-agent
  holder pubkey, optional TTL.
- Auth (critical): the caller must prove **possession of the parent CT's holder
  key** — a DPoP-style proof-of-possession bound to this request — so a stolen
  parent CT alone cannot be used to mint children. Reuse the `dpop` package and
  the verifier's `replayCache` (single-use jti) to stop replayed delegation
  requests.
- Server: resolve the parent issuer key from the registry, call
  `cttoken.Delegate`, sign with the `ct_issuer` key, append the event to the
  tamper-evident audit log (`internal/audit`) — who delegated what scope to whom,
  when. Returns the signed child CT.

`POST /agent/verify`
- Body: SPT-Txn token, DPoP proof, HTM/HTU, `CTChain` (root→leaf), CAT, txn
  context, audience — i.e. a serialized `verifier.Input`.
- Returns the `Decision` (allow, step, stepName, reason). No key required;
  reads only the registry snapshot. Can be stateless.

### Security model (OpenBSD — same shape as `catsvc`/`tr-svc`)

- Listen `127.0.0.1:8086` (catsvc 8082, tr-svc 8085); relayd terminates TLS on a
  public port (e.g. `:4445`) and proxies, with the same HSTS/headers as the rest.
- `pledge "stdio rpath inet"`. `unveil` read-only: issue role → the `ct_issuer`
  key path + registry snapshot; verify role → registry snapshot only. `unveilLock`.
- Dedicated `_agentsvc` user; key file `0400` owned by it (same ownership fix we
  applied to the relayd key).
- `http.MaxBytesReader` body caps, method checks, JSON structured errors —
  copied from `catsvc`/`tr-svc`.
- `/etc/rc.d/agentsvc` rc script (mirror the existing two); env
  `SPT_AGENTSVC_ADDR`, `SPT_AGENT_ROLE`, key path.
- relayd.conf: add a relay block forwarding the public TLS port → `127.0.0.1:8086`.

### Effort & risk

Moderate. The library is done and tested; `agentsvc` is HTTP wiring + the
OpenBSD hardening already established for the other services. The genuinely new
security-sensitive surface is `/agent/delegate` (holds a signing key + must
authenticate proof-of-possession of the parent holder key). That endpoint is
exactly where the independent audit (already requested in the grant) should
focus. Build/deploy on the Mac, scp the binary to the host (sandbox has no Go).

---

## Part B — `zkChain`: prove a valid chain without revealing it

### The privacy gap it closes

Today the verifier requires the **full chain presented** (CAT + every CT). The
verifier — and anyone on the path — therefore sees the entire delegation graph:
every intermediate agent's issuer, scope, jti, and holder key. For multi-hop
agent delegation that leaks real structure (which agents act for whom, internal
scopes, org topology).

Goal: let the leaf prove
> "I hold a capability that chains to a CAT with humanAnchor H, is a scope-subset
> at every hop, within delegation depth D, and is bound to my holder key"

**without revealing the intermediate CTs.** This is the contribution that maps
directly onto the Anthropic AI-control + privacy framing.

### Approach 1 — fixed-max-depth single circuit (recommended first)

A `ChainCircuit` (one `CircuitID`, Groth16/BN254/Poseidon2, like the existing
three) over a chain padded to `MaxDepth` (e.g. 4 or 8, fixed at setup).

- **Public inputs:** root humanAnchor (or a commitment to it), leaf holder-key
  thumbprint, `MaxDepth`, and the registry root / a root-scope commitment.
- **Private inputs:** the ordered per-hop records (issuer, scope encoding,
  remaining depth, parent-commitment, holder key) up to `MaxDepth`, padded with
  null hops.
- **In-circuit constraints, per hop i:**
  - `scope[i] ⊆ scope[i-1]` — the attenuation predicate (see schema note below);
  - `depth[i] == depth[i-1] − 1 ≥ 0` — the depth bound;
  - `humanAnchor[i] == rootAnchor` — anchor equality;
  - `parentCommit[i] == Poseidon2(serialize(record[i-1]))` — the same hash-chain
    the cleartext verifier checks, but as a Poseidon2 commitment over each record
    instead of SHA-256 over JWT bytes.
- Leaf binds to the public holder key, so the SPT-Txn's DPoP still ties the proof
  to the acting key. The verifier checks one Groth16 proof against
  `ChainCircuit.vk` and learns nothing about the middle.

This replaces step-6's cleartext walk with a single proof check. Steps 1–5,7,8
stay as-is on the leaf SPT-Txn (signature, DPoP, txn-vs-leaf-scope, context).

### The hard part — attenuation in-circuit (scope the schema down)

`tbac.Contains` handles arbitrary scope maps; arbitrary map-subset in a circuit
is expensive. Pragmatic move: define a **fixed agentic scope schema** — a small
typed vector:
- ceiling dims (e.g. `max_amount: uint`) → child ≤ parent (range check, like the
  existing `ThresholdCircuit`);
- enum/bitmask dims (e.g. `allowed_actions`) → `child & parent == child` (subset);
- resource-set dim → child Merkle root is a subset/subtree of parent (membership).

That makes attenuation a fixed, bounded arithmetic predicate. Cost: agentic
scopes must conform to this schema; the cleartext path stays fully general.

### What the `zkChain` MVP builds

1. Define the fixed agentic scope schema (typed dimension vector).
2. `ChainCircuit` (MaxDepth N) in `internal/zkproof`: per-hop attenuation + depth
   + anchor-equality + Poseidon2 parent-commitment chain.
3. `cttoken.Delegate` additionally emits a Poseidon2 commitment of each CT record
   (new claim `spt_zk_commit`) so the chain is committed in a ZK-friendly
   encoding, not only SHA-256 over JWT bytes.
4. A prover (leaf/agent side) that builds the witness from the held chain and
   outputs a Groth16 proof.
5. A verifier mode: instead of cleartext `CTChain`, accept
   `{zkChainProof, public inputs}` and verify against `ChainCircuit.vk` —
   replacing the step-6 walk.
6. `cmd/zk-setup` adds `ChainCircuit`; regenerate keys; extend `cmd/zk-bench`.

### Honest caveats

- The leaf scope is still needed for step-7 (`txn ⊆ leaf scope`). Either reveal
  only the leaf scope (hides the whole chain above it — already a big win) or
  prove txn-in-scope in-circuit too.
- Groth16 ⇒ per-circuit trusted setup and a **fixed** `MaxDepth`; shorter chains
  pad with null hops.
- Pairing-based ⇒ **not post-quantum** — consistent with the existing honest PQ
  posture (the proof layer is the last PQ item; PLONK/STARK is the long-term path).
- Recursive composition (each hop proves its parent's proof) is Approach 2 —
  more general but much heavier (in-circuit proof verification, larger setup,
  BN254-recursion caveats). Defer; Approach 1 delivers the privacy property
  without recursion.

### Effort & risk

Significant, and research-grade. Highest-risk item is the in-circuit attenuation
predicate. Recommended path: prototype `ChainCircuit` with **only** numeric
ceiling + depth + anchor first (drop bitmask/Merkle scope dims), prove the
privacy property end-to-end, benchmark, then enrich the schema. The cleartext
multi-hop verifier (already shipped) remains the production MVP; `zkChain` is the
privacy upgrade layered on top.

---

## Sequencing recommendation

1. **`agentsvc` verify role first** (no secrets, low risk) — gives adopters a
   hosted check and exercises the serialized `Input` path.
2. **`agentsvc` issue/delegate role** (signing key + proof-of-possession) — the
   audit-worthy surface; pairs naturally with the grant's independent-audit line.
3. **`zkChain` Approach 1, minimal schema** — the research deliverable; aligns
   with the Anthropic AI-control + privacy framing. Do this once the cleartext
   path has a design partner exercising it.
