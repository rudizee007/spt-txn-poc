# SPT-Txn v2 — Research Notes (PQ · Poseidon · zkDNS)

Source-grounded findings for drafting -02. Each section: what the field says →
the SPT-Txn design implication → the standard to anchor to (per the GLOSSARY §4
anchor-on-first-use rule). Citations at the end.

---

## 1. Post-quantum migration (the §11 of -02)

**State of the field.** NIST finalised the PQC suite on 2024-08-13: **FIPS 203
ML-KEM** (KEM, ex-Kyber), **FIPS 204 ML-DSA** (signatures, ex-Dilithium),
**FIPS 205 SLH-DSA** (hash-based, conservative); **FALCON → FIPS 206** in
progress. The accepted transition is **hybrid** — classical + PQC concatenated,
secure if *either* holds (IETF already standardised hybrid ML-KEM for TLS 1.3).
Crucially, the field consensus is that **short-lived tokens (JWTs) are NOT the
urgent target**; the priority is **long-lived signed data**: federation metadata,
**audit attestations**, and archived records.

**SPT-Txn implication (this is the honest, defensible posture).** Triage by
lifetime, not by hype:
- **High PQ priority (long-lived / retained):** the **CAT** (a credential that
  lives months–years), **registry/trust-anchor roots**, the **audit log**, and
  the **escrow records** (5–7 yr retention → classic harvest-now-decrypt-later).
  → migrate these signatures to **hybrid Ed25519 + ML-DSA-65**, and escrow KEM to
  **hybrid X25519 + ML-KEM-768**.
- **Low PQ priority (ephemeral):** the **SPT-Txn token** (~30 s) and the **ZK
  proofs** (verified once, never retained) — a future quantum adversary cannot
  retroactively forge a proof whose value already expired.
- **Crypto-agility:** algorithm identifiers in every token/attestation so the
  suite rolls without breaking the wire format.

Anchor: [FIPS203] / [FIPS204] / [FIPS205]; cite the IETF PQC-in-JOSE/COSE work as
the serialization path (monitor; JWTs are not the long pole).

## 2. ZK hash migration: MiMC → Poseidon2

**State of the field.** Under **R1CS / Groth16** (our exact setup), the Poseidon
family is the clear winner: Neptune/Poseidon/Poseidon2 have the **least
constraints** (~228/hash for Neptune vs MiMC's ~1,764 under Plonkish), and Poseidon
& Poseidon2 give the **best RAM/runtime with Groth16**. One benchmark cut proof
wait-time **~60%** swapping MiMC → Poseidon2. **gnark supports Poseidon2** (moved
to its permutation package) alongside MiMC.

**SPT-Txn implication.** Migrate MiMC → **Poseidon2** (not just Poseidon — it's
the current best) once we bump gnark. Expect a large proving speedup on all three
circuits with no security loss. The anchor unification (humanAnchor == ZK
commitment) carries over — just re-instantiate the hash. Keep MiMC as the
documented interim.

## 3. Post-quantum ZK (longer horizon, scoped honestly)

**State of the field.** **Groth16 is not post-quantum** (pairing/EC) and needs a
per-circuit trusted setup. PQ-secure options: **STARKs** (hash-based, transparent,
no trusted setup, PQ when instantiated with a suitable hash) and **lattice SNARKs**
(**LaBRADOR**, **Greyhound** — transparent, succinct, PQ; designated-verifier
lattice zkSNARKs ~16 KB for a 2^20 R1CS). A common production pattern: **prove in a
STARK** (transparent, PQ) then **wrap in Groth16** for cheap on-chain verification.

**SPT-Txn implication.** Because our proofs are *ephemeral*, PQ-ZK is a roadmap
item, not an emergency (§1). State the migration path honestly: Groth16/BN254 now
(with the BN254 ~100-bit vs BLS12-381 ~128-bit caveat) → transparent/PQ proving
(STARK or lattice) as the systems mature. This is a sharper, more credible line
than competitors' blanket "quantum-ready" claims.

## 4. zkDNS Layer 1 — decentralized name→key discovery

**Prior art.** **Handshake** replaces the ICANN root zone with a blockchain-
governed root and decentralized trust anchor (a CA/root alternative). **ENS**
resolves web3 names (does *not* replace DNS; bridges via a DNSSEC `_ens` record).
**Namecoin** (`.bit`) was first but slow/limited. ICANN's **OCTO-034** documents
the real hazards of alternative name systems (namespace collision, etc.) — cite it
to show awareness.

**SPT-Txn differentiator.** zkDNS L1 is *not* a general TLD play. It's a
**name → key/endpoint binding for VASP/agent discovery**: a committed membership
set with signed roots (the existing VASP-registry pattern), where a party
**proves in ZK that a counterparty name is registered without revealing the
namespace or which entry** — and which replaces TRP's Travel Address / TRISA's GDS
with a neutral, capture-resistant root (no ICANN/single-seizure dependency). One
line: *Handshake decentralizes the root, ENS resolves web3 names; zkDNS adds ZK
membership proofs over a compliance/VASP trust registry.* Complements DNSSEC, not
competes.

## 5. zkDNS Layer 2 — private resolution (query privacy)

**Prior art.** **ODoH** (Oblivious DNS-over-HTTPS, **RFC 9230**, 2022) splits
**proxy** (sees client IP, not query) from **target** (sees query, not client) so
no single server learns both — the standard for DNS *query* privacy. **Chainlink
DECO** (Cornell, acq. 2020) proves facts about TLS-held data in **zero-knowledge**
without revealing the data or exposing it to the oracle.

**SPT-Txn design.** Combine the two: ODoH-style proxy separation **+** a ZK proof
against the registry/oracle's **committed state** (DECO-style), so a VASP resolves
a counterparty `name → key` and checks live attributes (AML/sanctions) **without
revealing its query graph** or who it is screening. Anchor to **[RFC9230]** (ODoH)
and DECO; this is the "blind oracle query against committed state" already noted in
the architecture.

---

## Net for -02
- §11 PQ: hybrid, lifetime-triaged (CAT/registry/audit/escrow = priority; SPT-Txn
  token + proofs = low). Cite FIPS 203/204/205.
- Primitives: MiMC → **Poseidon2** (gnark-supported); BN254 caveat stated; PQ-ZK
  (STARK/lattice) as roadmap.
- zkDNS: L1 = ZK membership over a decentralized VASP/agent registry (vs
  Handshake/ENS); L2 = ODoH + DECO-style private resolution. Both anchored to real
  standards/protocols → consistent with the standards-mapping discipline.

## Citations
- NIST PQC FIPS 203/204/205 (2024-08-13); hybrid migration; JOSE/COSE PQC status.
- ZK-friendly hash benchmark (arXiv:2409.01976); gnark releases (Poseidon2).
- LaBRADOR / Greyhound lattice SNARKs; lattice designated-verifier zkSNARKs (Wu).
- Handshake; ENS; Namecoin; ICANN OCTO-034 (alt name systems).
- ODoH RFC 9230; Chainlink DECO (Cornell).
