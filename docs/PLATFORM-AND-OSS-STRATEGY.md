# Platform & open-source strategy (research — preliminary)

Companion to [SCALING-AND-SUBSTRATE.md](SCALING-AND-SUBSTRATE.md). Where that doc
answers "how does the architecture scale," this one answers three questions the
project (and any VASP / L1 / L2 evaluating it) will ask: **is it open source and
can its parts be reused/audited; do we have to run OpenBSD; and what open-source
components carry us to millions of requests/day with real uptime.** This is a
direction record — the research is not finished, and several items are flagged
open.

## 1. Open-source posture

- The SPT-Txn authorization layer is **Apache-2.0** today and stays that way —
  open source is a hard requirement (drives adoption + the trust the model needs).
  Sustainability comes from a managed layer on top (hosted Trust Registry /
  issuance-verification service), not from closing the core.
- **Reusing DWN parts is license-compatible.** `dwn-sdk-js` and `web5-js` are
  **Apache-2.0**, and a **`web5-go`** repo exists (DID/VC building blocks in Go).
  So "fork + audit + extend a specific component as a subproject" is legally open;
  the cost is not licensing but maintenance (DWN is a draft spec with ~0
  maintainers — see SCALING-AND-SUBSTRATE). If anything from that world is reused,
  the Go path (`web5-go`) is the OpenBSD/Go-friendly entry, and only after a
  threat-model + audit gate — never an unvetted dependency in the trust core.

## 2. Operating system: OpenBSD now, a FIPS-Linux production profile next

The honest tension: OpenBSD's `pledge`/`unveil` + privsep give an excellent
*defense-in-depth* story for the POC — but **OpenBSD has no FIPS 140-3 validation**,
and regulated-finance buyers increasingly require FIPS-validated cryptography
(FIPS 140-2 certificates move to the CMVP Historical List on **2026-09-21**).
Hardened Linux — **RHEL / Rocky / AlmaLinux** — is FIPS 140-3 capable. So a VASP or
bank asking "can you run on something battle-tested and FIPS-validated?" is a fair
and likely question.

**Why this is cheap, not a rewrite:** the stack is **portable Go**. The
OpenBSD-specific bits (`pledge`/`unveil`) are already behind build tags with no-op
fallbacks on other OSes, so the same binaries build and run on Linux unchanged.
And **Go 1.24+ ships a FIPS 140-3 mode** (`GODEBUG=fips140=on`, the Go
Cryptographic Module went through CMVP) — so a FIPS posture is a build/runtime
flag on a FIPS-validated Linux, using the crypto we already use (Ed25519 etc.),
not a crypto re-implementation.

**Recommended phased platform strategy:**

| Phase | Platform | Why |
|---|---|---|
| Now (POC / narrative) | OpenBSD, pledge/unveil/privsep | Strongest defense-in-depth story; differentiator; the audit at FAIL=0 lives here |
| Buyer-facing (regulated) | Hardened Linux (RHEL/Rocky/Alma) + **Go FIPS 140-3 mode** | FIPS-validated crypto; the distro security teams already trust; same Go binaries |
| Either | Document both as supported deployment **profiles** | "Runs on OpenBSD *or* a FIPS-hardened Linux" answers the question without abandoning the OpenBSD story |

**Linux equivalents to keep the hardening narrative** (so moving off OpenBSD
doesn't mean giving up sandboxing): **seccomp-bpf** + **Landlock** (mainline LSM)
for syscall/filesystem confinement (the pledge/unveil analogues), **SELinux /
AppArmor** for MAC, **systemd** unit hardening (`ProtectSystem`, `NoNewPrivileges`,
etc.), and minimal/distroless or immutable images. The honest framing: OpenBSD
gives it to you in the base system; on Linux you assemble an equivalent — both are
defensible, and the Go FIPS module is the piece OpenBSD can't offer.

**Open decision:** whether to make the FIPS-Linux profile a funded milestone now
or on first regulated-buyer demand. Recommendation: write the deployment profile +
CI matrix (build/test on both) early; defer a full FIPS-validated production
deployment until a buyer needs it.

### 2a. FIPS boundary & claim wording (hand this to a VASP security team)

FIPS 140-3 validates a **cryptographic module inside a defined boundary**, not an
operating system. So "are you FIPS 140-3?" has three different answers depending
on *which boundary* the asker means. Be precise — overclaiming "we're FIPS" is
both wrong and a credibility risk; underclaiming concedes ground you don't have to.

**The three layers:**

| Layer | What it covers | Status | How it gets FIPS |
|---|---|---|---|
| **1. Application crypto** | SPT-Txn token signing/verification, the ZK proofs, hashing — the trust-critical operations | **Validated-capable today** | Build the Go binaries with **Go's FIPS 140-3 module** (`GODEBUG=fips140=on`); runs on any OS |
| **2. Data-in-transit (TLS) + SSH** | TLS termination, admin SSH | **Non-FIPS on OpenBSD** (relayd/LibreSSL, SSH) | Either terminate TLS **in the Go service** (Go FIPS module — see lever below), or run on a FIPS-validated Linux whose OpenSSL is validated |
| **3. Full OS** | Kernel crypto, disk encryption, system libraries | **Non-FIPS on OpenBSD** | Deploy the FIPS-validated **Linux profile** (RHEL / CIQ-Rocky / Ubuntu Pro) |

**Which layer a buyer actually needs:** US-federal / FedRAMP / FISMA → all three.
Most VASPs / L1 / L2 → typically Layer 1 (validated crypto for the data they
exchange), sometimes Layer 2; full-OS (Layer 3) only if their internal policy
blanket-mandates it. Establish the buyer's scope before assuming Layer 3.

**Exact wording to use (verbatim):**

> "SPT-Txn's application cryptography — token signing and verification, the
> zero-knowledge proofs, and hashing — is performed by the **FIPS 140-3-validated
> Go Cryptographic Module** (CMVP), so the trust-critical cryptography is validated
> on any host. For deployments whose compliance scope requires validated crypto for
> data-in-transit or the full operating system, we provide a **FIPS-validated Linux
> deployment profile** (RHEL / Rocky-via-CIQ / Ubuntu Pro) using the same Go
> binaries — no cryptographic re-implementation, because the stack is portable Go."

- **Do say:** "our application crypto runs in a FIPS 140-3-validated module"; "a
  full-system FIPS Linux profile is available on request."
- **Don't say:** a bare "we are FIPS 140-3" (it implies the whole system is
  validated and SSH/TLS today are not); or that OpenBSD is "not secure" (the gap is
  a procurement certificate, not security — OpenBSD's pledge/unveil hardening is a
  strength, orthogonal to FIPS).

**The TLS-in-Go lever:** today TLS is terminated by relayd (LibreSSL, non-FIPS). By
terminating TLS **inside the Go service** using the Go FIPS module instead, both
Layer 1 *and* Layer 2 fall inside the validated boundary **even on a non-FIPS OS** —
which lets you answer "validated app crypto + validated data-in-transit" without
migrating the OS at all. Only Layer 3 (full-OS FIPS) then strictly requires the
Linux profile. This is the cheapest way to widen the honest FIPS claim, and worth
doing before a full OS migration.

**Bottom line:** the OS migration is a **compliance** lever (per-buyer, deferrable,
a cheap recompile because the code is portable Go), **not a cryptography or
security** necessity. Don't pre-migrate; scope it to the buyer who actually
mandates Layer 3.

## 3. Scaling to millions of requests/day (open-source stack)

The reassuring math: "millions/day" is ~tens of requests/second on average. A
**stateless** Ed25519-verify + hash is sub-millisecond, so even bursty peaks are
modest. Scaling is easy **if the hot path stays stateless** (the whole thesis):

- **Hot path — verifier.** Best: **ship it as an embedded Go library** so each
  consumer absorbs its own load in its own infra — there is no server of ours to
  scale. Fallback: N identical stateless replicas behind a load balancer
  (**relayd** today; **HAProxy / Envoy / Caddy / nginx** are all OSS options),
  health-checked, fronted by anycast/DNS for multi-region uptime.
- **Observability (OSS):** **OpenTelemetry** + **Prometheus** + **Grafana** for
  metrics/traces; structured logs. Needed for SLOs once there are real consumers.
- **Issuer.** Per-participant (each VASP runs its own), so no global throughput
  bottleneck. The real constraint is **key custody** — HSM / KMS via **PKCS#11**,
  threshold/MPC signing, rotation. This is a security-scaling problem, not a
  compute one.
- **Registry + audit substrate.** Per SCALING-AND-SUBSTRATE: rare writes,
  **on-chain Merkle root** anchor + **signed Go snapshots** read locally by
  verifiers; CDN/object-store the snapshots for distribution. No hot-path
  dependency.
- **Uptime.** Comes from statelessness + replication + health checks + multi-host
  (relayd already fronts everything; add replicas or split daemons per the
  SCALING doc). Not from a heavyweight orchestrator — though if a buyer runs
  Kubernetes, stateless Go containers drop in trivially.

**The real operational risks at scale are not compute** — they are key custody,
registry-snapshot freshness/distribution, and anchor cost/cadence. Plan those;
the verify throughput will not be the bottleneck.

## 4. Components to research further (and the gate for each)

| Component | Possible role | Gate before adoption |
|---|---|---|
| `web5-go` / DWN parts (Apache-2.0) | DID/VC interop; capability-pattern study | Maintenance + threat model; Go-only; not in trust core |
| IPFS (kubo, Go) | Public availability of non-sensitive blobs | Threat model; use content-addressing only, not networking, in trust path |
| On-chain Merkle anchor | Audit-trail / registry-root tamper-evidence | Anchor cadence + chain choice (cost/finality) |
| HSM/KMS (PKCS#11, e.g. SoftHSM → cloud HSM) | Issuer + escrow key custody | **Implemented & validated 2026-07-02** (SoftHSM2/PKCS#11 on OpenBSD, non-extractable Ed25519, issuer signing → `crypto.Signer`); cloud HSM (AWS/GCP KMS, both sign Ed25519) is a config swap; live-service wiring + escrow/threshold pending |
| FIPS Linux (Rocky/Alma/RHEL) + Go FIPS mode | Regulated-buyer deployment profile | Deployment-profile doc + CI matrix |

## Honest open items

Research is preliminary. Undecided: FIPS-Linux profile timing; whether to publish
the verifier as a standalone Go library now; HSM vendor (SoftHSM validated now → AWS/GCP KMS or hardware HSM next); whether to invest in a
DWN/`web5-go` subproject at all (currently: study patterns, don't depend). None of
these blocks the current POC; they shape the production/scale roadmap. Next
concrete step from SCALING-AND-SUBSTRATE remains: split verifier / issuer /
registry-sync into separate daemons — which also makes the OpenBSD↔Linux profile
split and per-component scaling clean.
