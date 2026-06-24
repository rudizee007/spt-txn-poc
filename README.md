# SPT-Txn — Privacy-Preserving Compliance & Travel Rule Authorization (Reference POC)

SPT-Txn verifies compliance **once** and proves it **everywhere**, in zero
knowledge — so regulated institutions and VASPs can transact, tokenise, and settle
on-chain without exposing PII. A user holds a **Compliance Attestation Token
(CAT)** (a W3C Verifiable Credential bound to a zero-knowledge identity commitment,
**zkDID/humanAnchor**); a platform checks a ZK proof of the CAT against a policy and
issues a scope-bounded **Capability Token (CT)**; each action emits a
transaction-bound **SPT-Txn token**. For inter-VASP transfers it carries a
payload-level **FATF Travel Rule** ZK attestation. No PII on the wire; no native
token; blockchain-agnostic (XRPL is the primary integration target).

> **Status: working, security-audited reference implementation** — not a skeleton,
> and not yet production. Deployed and running on a hardened OpenBSD host with a
> live two-party Travel Rule demo. See the roadmap below for what production needs.

## What's built and running

- **Real zero-knowledge** — Groth16/BN254 circuits (identity commitment,
  amount-over-threshold, VASP membership), **not stubs**. Hash migrated MiMC →
  **Poseidon2** (benchmarked: −44 % constraints, −41 % prove). `internal/zkproof`,
  `internal/zkhash`, `cmd/zk-setup`, `cmd/zk-bench`.
- **Live FATF Travel Rule** — IVMS101 + selective-disclosure SD-JWT + the three ZK
  predicates, carried over the OpenVASP **Travel Rule Protocol (TRP)** between two
  **separate VASP services** (originator proves, beneficiary verifies with the
  verifying key only). Cleartext-only transfers refused. `internal/travelrule`,
  `internal/trp`, `internal/ivms101`, `internal/vaspregistry`, `cmd/tr-svc`.
- **The token chain** — CAT → CT → SPT-Txn with scope attenuation, bounded
  delegation depth, immutable humanAnchor, 30 s transaction-bound tokens, DPoP
  sender-constraint, and the eight-step offline enforcement engine.
- **Security by design (OpenBSD)** — real `pledge(2)`/`unveil(2)` sandboxing,
  privilege separation, relayd TLS, signify keys; a host-runnable audit at
  **FAIL=0** (`scripts/security-audit.sh`). See `docs/SECURITY-REVIEW.md`.
- **Audit log** with hash-chain + signed Merkle roots; **escrow** envelope for
  lawful deanonymization.
- **EO-14409 ready** — a CycloneDX **Cryptographic Bill of Materials**
  (`docs/cbom.json`, `docs/CBOM.md`) and a lifetime-triaged hybrid post-quantum
  migration plan.

## Documentation

- [`docs/WORKING-PAPER-v2.md`](docs/WORKING-PAPER-v2.md) — the framework paper
  (architecture, zkDID, zkDNS + alternatives, measured crypto, PQ, Travel Rule).
- [`docs/GLOSSARY.md`](docs/GLOSSARY.md) — **authoritative** terminology + the
  CAT/attribute model + standards mapping.
- [`docs/CBOM.md`](docs/CBOM.md) / [`docs/cbom.json`](docs/cbom.json) — Cryptographic Bill of Materials.
- [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md) — full security review (FAIL=0; roadmap items noted).
- [`docs/TRP-TRISA-INTEROP.md`](docs/TRP-TRISA-INTEROP.md) — Travel Rule transport + TRISA bridge design.
- [`docs/V2-TOPICS-CHECKLIST.md`](docs/V2-TOPICS-CHECKLIST.md) / [`docs/V2-RESEARCH-NOTES.md`](docs/V2-RESEARCH-NOTES.md) — v2 coverage + research.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/OPENBSD-SETUP.md`](docs/OPENBSD-SETUP.md) — design + provisioning (some sections predate the current deployment).

## Repository layout

`cmd/` services + tools (tr-svc, catsvc, trsvc, zk-setup, zk-bench, regkey,
mksubject) · `internal/` libraries (zkproof, zkhash, zkdid, travelrule, trp,
ivms101, vaspregistry, sdjwt, dpop, escrow, verifier, trustregistry, tbac, …) ·
`docs/` · `scripts/` (security-audit, rc services, register-issuers) · `configs/`
· `web/` (the foss.violetskysecurity.com site source).

## Standards & links

Terminology anchors to W3C Verifiable Credentials / DID Core, SD-JWT, OAuth
Transaction Tokens (`draft-coetzee-oauth-spt-txn-tokens`), DPoP (RFC 9449), NIST SP
800-207/162, FIPS 203/204, FATF Rec 16 / IVMS101. Live: <https://foss.violetskysecurity.com>.
Preprints: Zenodo `10.5281/zenodo.19299787`, `10.5281/zenodo.18917439`.

## Build & test

Go 1.25+, gnark v0.15. The reference deployment runs on OpenBSD; the Go code is
OS-portable (the pledge/unveil layer is behind build tags, with a no-op for
non-OpenBSD). `go build ./...`; `go test ./internal/...`. ZK setup writes circuit
keys via `cmd/zk-setup`.

## Roadmap (honest)

Not production-ready. Agentic AI authorization is **designed (humanAnchor +
delegation-depth + attenuation) but not yet tested end-to-end**. Production needs:
XRPL-native anchoring + XRPL Credentials integration; biometric uniqueness (fuzzy
extractor + nullifier, currently a placeholder); the `.zkdid`/`.zkdns` production
identity/naming layer (integrated behind an adapter — interim works today);
persistent Trust Registry; hybrid PQ key migration; and an independent ZK-circuit +
protocol audit. See `docs/XRPL-GRANT-PROPOSAL.md` for the funded plan.

## License

Apache-2.0 (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). All dependencies are
permissive (Apache-2.0 / BSD / MIT / ISC); no copyleft. Copyright 2026 Rudolf J.
Coetzee / Violet Sky Security SEZC.
