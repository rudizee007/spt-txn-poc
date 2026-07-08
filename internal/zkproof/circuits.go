// Package zkproof provides the real Groth16 zero-knowledge circuits for the
// SPT-Txn privacy-preserving Travel Rule layer, validated on the OpenBSD host.
//
// Three predicates, each proving a compliance fact while revealing nothing
// about the underlying private data:
//
//   - Commitment: the holder knows the identity material behind a humanAnchor.
//   - Threshold:  a committed transfer amount is at/above the FATF reporting
//     threshold, without revealing the amount.
//   - VASP:       a counterparty is in the registered-VASP set, without
//     revealing which member.
//
// Poseidon2 is the ZK-friendly hash (gnark's native MerkleDamgard hasher and the
// in-circuit gadget are matched by construction); it replaced MiMC in v2 for a
// large proving speedup. This package depends on gnark but the M0-M2 services do
// not import it, so only the prover/verifier binaries pull in the proving backend.
//
// Domain separation (CR-1): each predicate hashes under a distinct domain tag,
// absorbed as the FIRST input — H(tag, a, b) — exactly mirroring the native
// helpers in internal/zkhash (HashAnchor/HashAmount/HashNode). The tag constants
// are imported from zkhash so the native and in-circuit absorption sequences can
// never drift apart. The Poseidon2 Merkle-Damgard hasher absorbs one field
// element per Write argument with initial state 0, so h.Write(tag, a, b) computes
// Compress(Compress(Compress(0, tag), a), b) — identical to the native side,
// which writes the same three 32-byte canonical blocks in the same order.
package zkproof

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	circuitposeidon2 "github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/rudizee007/spt-txn-poc/internal/zkhash"
)

// VASPTreeDepth fixes the registered-VASP Merkle tree depth (2^depth members).
const VASPTreeDepth = 8

// CommitmentCircuit constrains Anchor == Poseidon2(DomainAnchor, ID, Randomness).
type CommitmentCircuit struct {
	ID         frontend.Variable `gnark:",secret"`
	Randomness frontend.Variable `gnark:",secret"`
	Anchor     frontend.Variable `gnark:",public"`
}

func (c *CommitmentCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAnchor.
	h.Write(zkhash.DomainAnchor, c.ID, c.Randomness)
	api.AssertIsEqual(c.Anchor, h.Sum())
	return nil
}

// ThresholdCircuit constrains a committed amount to be >= a public threshold,
// with the amount range-checked to 64 bits to prevent field wraparound.
type ThresholdCircuit struct {
	Amount     frontend.Variable `gnark:",secret"`
	Blinding   frontend.Variable `gnark:",secret"`
	Commitment frontend.Variable `gnark:",public"`
	Threshold  frontend.Variable `gnark:",public"`
}

func (c *ThresholdCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAmount.
	h.Write(zkhash.DomainAmount, c.Amount, c.Blinding)
	api.AssertIsEqual(c.Commitment, h.Sum())

	// Range-check BOTH operands of the comparison to a shared 64-bit domain
	// (CR-4). Without constraining Threshold, the public input could be a field
	// element outside [0, 2^64) and AssertIsLessOrEqual would compare in the full
	// field, allowing a spurious "amount >= threshold" via modular wraparound.
	api.ToBinary(c.Amount, 64)
	api.ToBinary(c.Threshold, 64)
	api.AssertIsLessOrEqual(c.Threshold, c.Amount)
	return nil
}

// AddrThresholdCircuit is the Tier-1 (anti-replay) RWA attribute gate: it proves
// exactly what ThresholdCircuit proves — a committed amount is >= a public
// threshold, amount hidden — but adds the holder's on-chain address as a PUBLIC
// input so the proof is non-transferable.
//
// Why an appended public input is sufficient: in Groth16 EVERY public input is
// folded into the verifier's pairing check (vk_x = IC[0] + Σ inputᵢ·ICᵢ), so a
// proof generated for address A fails verification if a different address B is
// supplied. The RWA contract passes uint160(msg.sender) as HolderAddr, so a proof
// lifted from public calldata cannot be replayed by another caller. HolderAddr is
// range-checked to 160 bits both to guarantee it is materialised in the R1CS and
// to reject any non-address field element. This tier needs NO issuer — it stops
// replay but does not bind eligibility to a vetted identity (see EligibilityCircuit).
//
// Public-input order (mirrored by the generated Solidity verifier's uint256[3]):
//
//	input[0] = Commitment, input[1] = Threshold, input[2] = HolderAddr
type AddrThresholdCircuit struct {
	Amount     frontend.Variable `gnark:",secret"`
	Blinding   frontend.Variable `gnark:",secret"`
	Commitment frontend.Variable `gnark:",public"`
	Threshold  frontend.Variable `gnark:",public"`
	HolderAddr frontend.Variable `gnark:",public"`
}

func (c *AddrThresholdCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(zkhash.DomainAmount, c.Amount, c.Blinding)
	api.AssertIsEqual(c.Commitment, h.Sum())

	api.ToBinary(c.Amount, 64)
	api.ToBinary(c.Threshold, 64)
	api.AssertIsLessOrEqual(c.Threshold, c.Amount)

	// Bind the caller's address into the constraint system (also enforces it is a
	// well-formed 160-bit value). The value itself is unconstrained beyond width:
	// the legitimate holder proves with their own address, the contract verifies
	// with msg.sender, and any mismatch fails the pairing check → no replay.
	api.ToBinary(c.HolderAddr, 160)
	return nil
}

// EligibilityCircuit is the Tier-2 (production) RWA eligibility gate. It closes
// the replay boundary AND ties eligibility to a vetted identity: a holder becomes
// eligible only if a TRUSTED ISSUER has signed an attestation over THIS holder's
// address, and the holder proves an attribute predicate (amount >= threshold,
// amount hidden). No PII is revealed — only the address (which the contract
// already knows as msg.sender), the policy threshold, and the issuer's public key.
//
// The circuit enforces, in zero knowledge:
//  1. commitment = Poseidon2(DomainAmount, Amount, Blinding)  (amount hidden);
//  2. Amount >= Threshold, both range-checked to 64 bits;
//  3. HolderAddr is a 160-bit value (bound into the R1CS);
//  4. the issuer's Baby Jubjub EdDSA signature verifies IN-CIRCUIT over the
//     message m = Poseidon2(DomainHolder, HolderAddr, commitment), under the
//     public issuer key (IssuerX, IssuerY).
//
// (4) is what makes eligibility non-transferable and issuer-gated: only the
// trusted issuer can produce a signature over a given address, and the signed
// message is bound to the holder's address, so neither the holder nor an observer
// can move the eligibility to a different address. Same in-circuit EdDSA machinery
// as ChainCircuit (F1). The issuer key is PUBLIC so the RWA token pins its trusted
// claim issuer on-chain (the ERC-3643 "trusted issuer" analogue).
//
// Public-input order (mirrored by the generated Solidity verifier's uint256[4]):
//
//	input[0] = HolderAddr, input[1] = Threshold, input[2] = IssuerX, input[3] = IssuerY
type EligibilityCircuit struct {
	HolderAddr frontend.Variable `gnark:",public"`
	Threshold  frontend.Variable `gnark:",public"`
	IssuerX    frontend.Variable `gnark:",public"`
	IssuerY    frontend.Variable `gnark:",public"`

	Amount   frontend.Variable `gnark:",secret"`
	Blinding frontend.Variable `gnark:",secret"`
	Sig      eddsa.Signature   `gnark:",secret"`
}

func (c *EligibilityCircuit) Define(api frontend.API) error {
	// 1) amount commitment (amount stays hidden).
	hc, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	hc.Write(zkhash.DomainAmount, c.Amount, c.Blinding)
	commitment := hc.Sum()

	// 2) attribute predicate: amount >= threshold, both range-checked (CR-4).
	api.ToBinary(c.Amount, 64)
	api.ToBinary(c.Threshold, 64)
	api.AssertIsLessOrEqual(c.Threshold, c.Amount)

	// 3) bind the caller's address into the R1CS (160-bit well-formedness).
	api.ToBinary(c.HolderAddr, 160)

	// 4) reconstruct the issuer-signed message m = H(DomainHolder, addr, commitment)
	//    and verify the issuer's EdDSA signature over it, under the PUBLIC issuer key.
	hm, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	hm.Write(zkhash.DomainHolder, c.HolderAddr, commitment)
	msg := hm.Sum()

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	mh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	var pub eddsa.PublicKey
	pub.A.X = c.IssuerX
	pub.A.Y = c.IssuerY
	return eddsa.Verify(curve, c.Sig, msg, pub, &mh)
}

// VASPCircuit verifies a Merkle authentication path from a secret leaf to the
// public registered-VASP root.
type VASPCircuit struct {
	Leaf     frontend.Variable                `gnark:",secret"`
	Siblings [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	PathBits [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	Root     frontend.Variable                `gnark:",public"`
}

func (c *VASPCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	cur := c.Leaf
	for i := 0; i < VASPTreeDepth; i++ {
		api.AssertIsBoolean(c.PathBits[i])
		left := api.Select(c.PathBits[i], c.Siblings[i], cur)
		right := api.Select(c.PathBits[i], cur, c.Siblings[i])
		h.Reset()
		// Inner-node domain tag absorbed first; mirrors zkhash.HashNode and is
		// distinct from the commitment domains so a commitment value can never be
		// passed off as a Merkle node (or vice versa).
		h.Write(zkhash.DomainMerkleNode, left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}

// MaxHops bounds the delegation-chain length the agentic proof supports (root
// CAT + up to MaxHops-1 delegations). A fixed size keeps the circuit constant;
// shorter chains pad the inactive tail so its constraints hold trivially.
const MaxHops = 4

// ChainCircuit proves a delegation chain (CAT -> CT -> ... -> leaf) is valid
// WITHOUT revealing the intermediate scopes: each hop's ceiling only narrows,
// the currency is unchanged, the delegation depth decrements by one and never
// goes negative, and the whole chain is tied to one accountable human — while
// only commitments to the leaf scope and to the human-anchor are public.
//
//	Public:  H0    = Poseidon2(DomainAnchor, Anchor, Salt)            (human-anchor commitment)
//	         CLeaf = Poseidon2(DomainAmount, leafMaxAmt, leafCurrency) (leaf scope commitment)
//	         D     = root (maximum) delegation depth
//	Private: anchor preimage + salt, and per-hop (Active, MaxAmt, Currency, Depth).
//
// Signature/issuer-trust checks stay in the native eight-step engine; this
// circuit proves only the scope-attenuation + depth + human-anchor invariants,
// which keeps it small. DomainAmount is reused for the leaf-scope commitment (a
// 2-input Poseidon2 over (maxAmount, currency)) — it is a distinct public input
// in a distinct circuit, so no cross-predicate confusion arises.
type ChainCircuit struct {
	H0      frontend.Variable `gnark:",public"`
	CLeaf   frontend.Variable `gnark:",public"`
	D       frontend.Variable `gnark:",public"`
	RegRoot frontend.Variable `gnark:",public"` // registered-CT-issuer Merkle root (F1)

	Anchor   frontend.Variable          `gnark:",secret"`
	Salt     frontend.Variable          `gnark:",secret"`
	Active   [MaxHops]frontend.Variable `gnark:",secret"`
	MaxAmt   [MaxHops]frontend.Variable `gnark:",secret"`
	Currency [MaxHops]frontend.Variable `gnark:",secret"`
	Depth    [MaxHops]frontend.Variable `gnark:",secret"`

	// Per-hop issuer trust (F1, phase 2): for each ACTIVE hop, the hop's issuer
	// (a) signed this hop's scope commitment with its Baby Jubjub key (PubKey/Sig,
	// verified in-circuit via EdDSA), and (b) that public key is a member of the
	// registered-CT-issuer tree — its leaf H(DomainIssuer, A.X, A.Y) plus the
	// authentication path (IssuerSib/IssuerDir) must reconstruct the public
	// RegRoot. Inactive tail hops are unconstrained (the prover pads them).
	PubKey    [MaxHops]eddsa.PublicKey                  `gnark:",secret"`
	Sig       [MaxHops]eddsa.Signature                  `gnark:",secret"`
	IssuerSib [MaxHops][VASPTreeDepth]frontend.Variable `gnark:",secret"`
	IssuerDir [MaxHops][VASPTreeDepth]frontend.Variable `gnark:",secret"`
}

func (c *ChainCircuit) Define(api frontend.API) error {
	// 1) Human-anchor: prove knowledge of the preimage behind the public commitment.
	ha, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	ha.Write(zkhash.DomainAnchor, c.Anchor, c.Salt)
	api.AssertIsEqual(c.H0, ha.Sum())

	// 2) Root hop: active, at the full declared depth D, amount range-checked.
	api.AssertIsEqual(c.Active[0], 1)
	api.AssertIsEqual(c.Depth[0], c.D)
	api.ToBinary(c.MaxAmt[0], 64)
	api.ToBinary(c.Depth[0], 32)

	// 3) Each later hop attenuates. Inactive tail hops fall back to their parent
	//    so their constraints hold trivially (the active hops form a prefix).
	for i := 1; i < MaxHops; i++ {
		api.AssertIsBoolean(c.Active[i])
		// contiguous active prefix: no 0 -> 1 reactivation.
		api.AssertIsLessOrEqual(c.Active[i], c.Active[i-1])

		amtEff := api.Select(c.Active[i], c.MaxAmt[i], c.MaxAmt[i-1])
		curEff := api.Select(c.Active[i], c.Currency[i], c.Currency[i-1])
		depEff := api.Select(c.Active[i], c.Depth[i], api.Sub(c.Depth[i-1], 1))

		// attenuation: parent - child >= 0 (child also range-checked).
		api.ToBinary(c.MaxAmt[i], 64)
		api.ToBinary(api.Sub(c.MaxAmt[i-1], amtEff), 64)

		// currency unchanged along the chain.
		api.AssertIsEqual(curEff, c.Currency[i-1])

		// depth decrements by one; the active depth stays non-negative.
		api.AssertIsEqual(depEff, api.Sub(c.Depth[i-1], 1))
		api.ToBinary(api.Select(c.Active[i], c.Depth[i], 0), 32)
	}

	// 4) Leaf = last active hop: isLeaf[i] = Active[i] AND NOT Active[i+1].
	var leafAmt frontend.Variable = 0
	var leafCur frontend.Variable = 0
	for i := 0; i < MaxHops; i++ {
		var nextActive frontend.Variable = 0
		if i+1 < MaxHops {
			nextActive = c.Active[i+1]
		}
		isLeaf := api.Mul(c.Active[i], api.Sub(1, nextActive))
		leafAmt = api.Add(leafAmt, api.Mul(isLeaf, c.MaxAmt[i]))
		leafCur = api.Add(leafCur, api.Mul(isLeaf, c.Currency[i]))
	}

	// 5) The leaf scope commitment must match the public CLeaf.
	hs, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	hs.Write(zkhash.DomainAmount, leafAmt, leafCur)
	api.AssertIsEqual(c.CLeaf, hs.Sum())

	// 6) Per-hop issuer trust (F1, phase 2): for every ACTIVE hop, (a) the hop's
	//    issuer signed THIS hop's scope commitment H(DomainAmount, MaxAmt, Currency)
	//    with its Baby Jubjub key (EdDSA verified in-circuit), and (b) that public
	//    key is a member of the registered-CT-issuer tree (public RegRoot), via the
	//    leaf H(DomainIssuer, A.X, A.Y) and the Merkle path (orientation mirrors
	//    VASPCircuit). Together this proves each hidden hop carries a real signature
	//    from a registered issuer over its actual scope — closing F1. Inactive tail
	//    hops compare RegRoot to itself and gate the signature off, so the prover
	//    may pad them. The cleartext engine still verifies signatures too; ZK mode
	//    stays opt-in.
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	hp, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	hm, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	for i := 0; i < MaxHops; i++ {
		// (a) signature over this hop's scope commitment (same construction as CLeaf).
		hp.Reset()
		hp.Write(zkhash.DomainAmount, c.MaxAmt[i], c.Currency[i])
		scopeMsg := hp.Sum()
		mh, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		valid, err := eddsa.IsValid(curve, c.Sig[i], scopeMsg, c.PubKey[i], &mh)
		if err != nil {
			return err
		}
		// active hop ⇒ the signature must be valid; inactive hop ⇒ unconstrained.
		api.AssertIsEqual(api.Mul(c.Active[i], api.Sub(1, valid)), 0)

		// (b) the signing public key is a registered CT-issuer.
		hp.Reset()
		hp.Write(zkhash.DomainIssuer, c.PubKey[i].A.X, c.PubKey[i].A.Y)
		cur := hp.Sum()
		for j := 0; j < VASPTreeDepth; j++ {
			api.AssertIsBoolean(c.IssuerDir[i][j])
			left := api.Select(c.IssuerDir[i][j], c.IssuerSib[i][j], cur)
			right := api.Select(c.IssuerDir[i][j], cur, c.IssuerSib[i][j])
			hm.Reset()
			hm.Write(zkhash.DomainMerkleNode, left, right)
			cur = hm.Sum()
		}
		api.AssertIsEqual(api.Select(c.Active[i], cur, c.RegRoot), c.RegRoot)
	}

	return nil
}
