# SPT-Txn — Cryptographic Bill of Materials (CBOM)

A complete inventory of the cryptographic algorithms, protocols, and
implementations in SPT-Txn, with quantum-safety status and migration targets.

**Why this exists.** US Executive Order 14409, *"Securing the Nation Against
Advanced Cryptographic Attacks"* (2026-06-22), directs CISA + NIST to publish
CBOM minimum-elements guidance within 270 days and sets federal PQC-migration
deadlines (sensitive-system **encryption by 2030-12-31**, **authentication by
2031-12-31**; federal contractors to PQ FIPS by end of 2030). A CBOM is the
inventory those deadlines are measured against. SPT-Txn is **crypto-agile by
design** (algorithm identifiers in every token/attestation), so this inventory
doubles as the migration plan.

**Machine-readable companion:** [`cbom.json`](cbom.json) — CycloneDX 1.6
cryptography BOM. **Status** column is honest: `deployed` (running on the host),
`designed` (specified, not yet running), `planned` (migration target).

**Migration principle — triage by data lifetime, not by hype.** A future quantum
adversary cannot retroactively forge a proof or token whose value already expired.
So the priority is **long-lived, retained data**, not ephemeral tokens. (Aligns
with NIST/IETF guidance: short-lived JWTs are not the urgent target.)

## Disclosure posture

A CBOM lists **algorithms, not secrets** — no keys, no exploitable configuration.
For this open-source POC the inventory is already visible in the source and the
TLS handshake, so publishing it here carries negligible marginal risk and signals
crypto hygiene. EO 14409 requires *having* and *providing* a CBOM (to CISA /
federal customers), **not broadcasting it**. The commercial/production posture is
therefore: a one-line *"CycloneDX CBOM available on request"* in public materials,
with the full inventory shared to partners (e.g. an ecosystem grant reviewer) or
under NDA. A CBOM is an attacker aid only when it exposes *deprecated/weak*
primitives — which this one does not.

## Inventory

| Algorithm | Primitive | Where used | Classical | Quantum-safe? | PQ priority | Migration target | Status |
|---|---|---|---|---|---|---|---|
| **Ed25519** | signature | CAT / SD-JWT signing; VASP-registry signed roots; audit log; signify keys | ~128-bit | No (Shor) | **High** — long-lived/retained | ML-DSA-65 (FIPS 204), hybrid | deployed |
| **Ed25519** | signature | SPT-Txn token (≈30 s) | ~128-bit | No (Shor) | Low — ephemeral | ML-DSA-65, later | deployed |
| **X25519 + ECIES** | KEM / key-agree | escrow envelope (lawful deanonymization, 5–7 yr retention) | ~128-bit | No (Shor) | **High** — harvest-now-decrypt-later | ML-KEM-768 (FIPS 203), hybrid | deployed |
| **Groth16 / BN254** | zk-SNARK (pairing) | 3 Travel Rule proofs (commitment, threshold, VASP membership) | ~100-bit (BN254) | No (Shor) | Low — proofs verified once, discarded | transparent/PQ proving (STARK / lattice) | deployed |
| **BLS12-381** | pairing curve | high-assurance proving config (benchmarked alt) | ~128-bit | No (Shor) | Low | STARK / lattice | planned (opt-in) |
| **Poseidon2** | hash (ZK-friendly) | humanAnchor + amount commitments; VASP Merkle tree | ~127-bit (BN254 field) | Grover-only (halved) | Low | widen output if required | deployed |
| **SHA-256** | hash | audit-log Merkle root; general hashing | 128-bit | Grover-only | Low | SHA-384/512 if required | deployed |
| **AES-256-GCM** | authenticated encryption | TLS 1.3 transport (relayd); escrow envelope payload; TRISA payload | 256→128-bit (Grover) | **Yes** (NIST level 1) | None | none — PQ-OK | deployed (TLS, escrow) / designed (TRISA) |
| **HKDF-SHA-256** | KDF | escrow AEAD key derivation (X25519 secret → AES-256-GCM key) | 128-bit | Grover-only | Low | none | deployed |
| **HMAC-SHA-256** | MAC | TRISA SecureEnvelope integrity | 128-bit | Grover-only | Low | none | designed |
| **TLS 1.3** | protocol | relayd edge (X25519 KEX + AES-256-GCM + SHA-384) | — | KEX not PQ | **High** — transport | hybrid X25519+ML-KEM (TLS) | deployed |
| **RSA (Let's Encrypt)** | signature / X.509 cert | edge TLS server certificate | ~128-bit | No (Shor) | Medium | PQ cert when CA + browsers support | deployed |

## Reading the triage

**Migrate first (long-lived / retained, PQ-urgent):**
- Ed25519 on the **CAT** (credential lives months–years), **VASP-registry roots**,
  and the **audit log** → hybrid Ed25519 + **ML-DSA-65**.
- **Escrow** X25519/ECIES (5–7 yr retention, classic harvest-now-decrypt-later) →
  hybrid X25519 + **ML-KEM-768**.
- **TLS transport** key exchange → hybrid X25519 + ML-KEM (track the IETF TLS work).
- The **TLS server cert** (RSA) → a PQ certificate once the CA/browser ecosystem
  supports it (not yet actionable).

**Defer (ephemeral / hash-only, not PQ-urgent):**
- Ed25519 on the **30-second SPT-Txn token** and the **Groth16/BN254 ZK proofs** —
  their value expires before any quantum threat lands; PQ-ZK (STARK/lattice) is a
  measured roadmap item, not an emergency.
- **Poseidon2 / SHA-256 / HMAC / HKDF** (hashes/MACs/KDF) — only weakened by Grover
  (quadratic), already at comfortable margins; widen output if ever required.
- **AES-256-GCM** — already PQ-OK at NIST level 1.

## Crypto-agility (how migration happens without breaking the wire format)

Every SPT-Txn token and attestation carries explicit algorithm identifiers, and
the Trust Registry — not the token header — governs which algorithm a verifier
accepts (downgrade-resistant). A hybrid suite (classical ∥ PQC) can therefore be
rolled per-issuer without a flag day. The hash migration **MiMC → Poseidon2** (done
2026-06-24) is the proof of concept: a two-file, matched native/in-circuit change.

## Measured basis

Algorithm choices are benchmarked, not assumed — see
[`V2-RESEARCH-NOTES.md`](V2-RESEARCH-NOTES.md) for the MiMC-vs-Poseidon2 and
BN254-vs-BLS12-381 measurements on the OpenBSD host (Poseidon2: −44 % constraints,
−41 % prove; BLS12-381: ~2× prove + larger proofs for the ~128-bit margin).

## Regenerating / validating
`cbom.json` is CycloneDX 1.6; validate with `cyclonedx validate --input-file
docs/cbom.json`. Update both files together when a primitive changes (e.g., when
ML-DSA/ML-KEM hybrids land).
