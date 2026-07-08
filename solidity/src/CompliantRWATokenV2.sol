// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// gnark-generated Groth16 verifiers REVERT on an invalid proof (they do not
/// return a bool). Arity = number of public inputs, in circuit declaration order:
///   - Tier 1 AddrThresholdCircuit: 3 = [ commitment, threshold, holderAddr ]
///   - Tier 2 EligibilityCircuit:   4 = [ holderAddr, threshold, issuerX, issuerY ]
interface IVerifier3 { function verifyProof(bytes calldata proof, uint256[3] calldata input) external view; }
interface IVerifier4 { function verifyProof(bytes calldata proof, uint256[4] calldata input) external view; }

/// @title CompliantRWATokenV2 — permissioned RWA token with msg.sender-bound
///        SPT-Txn zero-knowledge compliance proofs.
/// @notice V2 closes the honest boundary documented in CompliantRWAToken (V1):
///         the eligibility proof is now cryptographically bound to the caller, so
///         a valid proof lifted from public calldata CANNOT be replayed by another
///         address. Two configurable tiers:
///
///         Tier 1 (AddressBound) — the attribute proof (amount >= threshold,
///           amount hidden) carries the holder's address as a public input. The
///           contract verifies with msg.sender, so the proof only works for the
///           caller it was minted for. Anti-replay, no issuer required.
///
///         Tier 2 (IssuerBound) — eligibility additionally requires a TRUSTED
///           ISSUER's Baby Jubjub EdDSA signature over H(DomainHolder, holderAddr,
///           commitment), verified inside the circuit. The token pins the issuer's
///           public key (issuerX, issuerY) on-chain — the ERC-3643 "trusted claim
///           issuer" analogue — so only an address the issuer has vetted can become
///           eligible, and the attestation is non-transferable. No PII on-chain.
///
/// @dev ERC-3643 (T-REX) analogues, made privacy-preserving and replay-safe:
///        IdentityRegistry  → `eligible[addr]`, set by the caller PROVING compliance
///                            in ZK for their own address.
///        TrustedIssuer     → the pinned (issuerX, issuerY) Baby Jubjub key (Tier 2).
///        Compliance.canTransfer → `_transfer` requires both parties eligible.
///      The chain records only a boolean and the pinned issuer key — never identity.
contract CompliantRWATokenV2 {
    // ----- ERC-20 (minimal, self-contained) -----
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ----- compliance config -----
    enum Mode { AddressBound, IssuerBound } // Tier 1, Tier 2

    address public immutable admin;      // issuer / token agent
    address public immutable verifier;   // the gnark Groth16 verifier for `mode`
    Mode public immutable mode;
    uint256 public attributeThreshold;   // public policy threshold
    uint256 public issuerX;              // trusted issuer Baby Jubjub pubkey X (Tier 2)
    uint256 public issuerY;              // trusted issuer Baby Jubjub pubkey Y (Tier 2)

    mapping(address => bool) public eligible; // the ZK "identity registry" — flag only
    event Registered(address indexed holder, Mode mode);
    event ConfigUpdated(uint256 threshold, uint256 issuerX, uint256 issuerY);

    error NotEligible(address who);
    error OnlyAdmin();

    modifier onlyAdmin() { if (msg.sender != admin) revert OnlyAdmin(); _; }

    constructor(
        string memory _name,
        string memory _symbol,
        address _verifier,
        Mode _mode,
        uint256 _attributeThreshold,
        uint256 _issuerX,
        uint256 _issuerY
    ) {
        admin = msg.sender;
        name = _name;
        symbol = _symbol;
        verifier = _verifier;
        mode = _mode;
        attributeThreshold = _attributeThreshold;
        issuerX = _issuerX;
        issuerY = _issuerY;
    }

    /// @notice Establish eligibility by proving compliance in zero knowledge FOR
    ///         THE CALLER'S OWN ADDRESS. The proof is verified on-chain (the gnark
    ///         verifier reverts if invalid), and msg.sender is supplied as the
    ///         address public input — so the proof cannot be replayed by anyone else.
    /// @param proof The Groth16 proof bytes (from the RWA calldata tool).
    /// @param attributeCommitment The amount commitment (Tier 1 only; ignored in
    ///        Tier 2, where the commitment stays hidden inside the signed message).
    function register(bytes calldata proof, uint256 attributeCommitment) external {
        uint256 who = uint256(uint160(msg.sender));
        if (mode == Mode.AddressBound) {
            // Tier 1: [ commitment, threshold, holderAddr=msg.sender ]
            IVerifier3(verifier).verifyProof(proof, [attributeCommitment, attributeThreshold, who]);
        } else {
            // Tier 2: [ holderAddr=msg.sender, threshold, issuerX, issuerY ]
            IVerifier4(verifier).verifyProof(proof, [who, attributeThreshold, issuerX, issuerY]);
        }
        eligible[msg.sender] = true;
        emit Registered(msg.sender, mode);
    }

    /// @notice Issuer mints the RWA supply to an already-eligible holder.
    function mint(address to, uint256 amount) external onlyAdmin {
        if (!eligible[to]) revert NotEligible(to);
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // ----- ERC-20 transfers, gated on compliance -----
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _transfer(from, to, amount);
        return true;
    }

    /// @dev ERC-3643 canTransfer analogue: both counterparties must be eligible.
    function _transfer(address from, address to, uint256 amount) internal {
        if (!eligible[from]) revert NotEligible(from);
        if (!eligible[to]) revert NotEligible(to);
        require(balanceOf[from] >= amount, "balance");
        unchecked { balanceOf[from] -= amount; }
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    /// @notice Read-only compliance check, ERC-3643 style.
    function canTransfer(address from, address to) external view returns (bool) {
        return eligible[from] && eligible[to];
    }

    /// @notice Issuer governance: rotate the threshold / trusted-issuer key.
    function setConfig(uint256 _threshold, uint256 _issuerX, uint256 _issuerY) external onlyAdmin {
        attributeThreshold = _threshold;
        issuerX = _issuerX;
        issuerY = _issuerY;
        emit ConfigUpdated(_threshold, _issuerX, _issuerY);
    }
}
