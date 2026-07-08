// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// gnark-generated Groth16 verifiers REVERT on an invalid proof (they do not
/// return a bool). Arity differs per circuit:
///   - membership (VASPCircuit): 1 public input  = [ eligibleHoldersRoot ]
///   - attribute  (ThresholdCircuit): 2 public inputs = [ commitment, threshold ]
interface IVerifier1 { function verifyProof(bytes calldata proof, uint256[1] calldata input) external view; }
interface IVerifier2 { function verifyProof(bytes calldata proof, uint256[2] calldata input) external view; }

/// @title CompliantRWAToken — permissioned real-world-asset token, gated on
///        SPT-Txn zero-knowledge compliance proofs.
/// @notice A tokenised asset that can move ONLY between compliance-verified
///         holders. A holder becomes eligible by proving, in zero knowledge and
///         with NO personally-identifying data on-chain, that they are
///         (a) a member of the approved-holder set, and/or (b) satisfy an
///         attribute predicate (e.g. accredited / amount-over-threshold). Both
///         checks are configurable and enforced on-chain.
///
/// @dev ERC-3643 (T-REX) analogues, made privacy-preserving:
///        ERC-3643 IdentityRegistry (agent stores KYC'd identities)
///          → here `eligible[addr]`, set by the holder *proving* compliance in ZK.
///        ERC-3643 Compliance.canTransfer (module checks)
///          → here `_transfer` requires both parties eligible.
///      The chain records only a boolean flag and the anchored roots — never PII.
///      This is the differentiator over plain ERC-3643: eligibility is established
///      by a verifiable ZK proof, not by an operator custodying identity data.
///
/// @dev HONEST BOUNDARY (documented, not hidden): the membership/attribute proofs
///      prove that *a* valid holder/attribute exists in the set; they are NOT yet
///      cryptographically bound to `msg.sender`. A production deployment MUST bind
///      the proof to the registering address (e.g. include the address as a public
///      signal, or bind via the SPT-Txn humanAnchor) to prevent a valid proof from
///      being replayed by a different address. This PoC demonstrates the on-chain
///      gating mechanism; address-binding is the next circuit iteration.
contract CompliantRWAToken {
    // ----- ERC-20 (minimal, self-contained) -----
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ----- compliance config (ERC-3643-aligned) -----
    address public immutable admin;                 // issuer / token agent
    IVerifier1 public immutable membershipVerifier; // VASP circuit verifier
    IVerifier2 public immutable attributeVerifier;  // threshold circuit verifier
    uint256 public eligibleHoldersRoot;             // public Merkle root of approved holders
    uint256 public attributeThreshold;              // required attribute threshold
    bool public requireMembership;
    bool public requireAttribute;

    mapping(address => bool) public eligible;       // the ZK "identity registry" — flag only
    event Registered(address indexed holder, bool viaMembership, bool viaAttribute);
    event ConfigUpdated(uint256 root, uint256 threshold, bool reqMembership, bool reqAttribute);

    error NotEligible(address who);
    error NothingRequired();
    error OnlyAdmin();

    modifier onlyAdmin() { if (msg.sender != admin) revert OnlyAdmin(); _; }

    constructor(
        string memory _name,
        string memory _symbol,
        address _membershipVerifier,
        address _attributeVerifier,
        uint256 _eligibleHoldersRoot,
        uint256 _attributeThreshold,
        bool _requireMembership,
        bool _requireAttribute
    ) {
        if (!_requireMembership && !_requireAttribute) revert NothingRequired();
        admin = msg.sender;
        name = _name;
        symbol = _symbol;
        membershipVerifier = IVerifier1(_membershipVerifier);
        attributeVerifier = IVerifier2(_attributeVerifier);
        eligibleHoldersRoot = _eligibleHoldersRoot;
        attributeThreshold = _attributeThreshold;
        requireMembership = _requireMembership;
        requireAttribute = _requireAttribute;
    }

    /// @notice Establish eligibility by proving compliance in zero knowledge.
    ///         Supply whichever proofs the token requires. Each proof is verified
    ///         on-chain (the gnark verifier reverts if it is invalid), so a failed
    ///         proof reverts the whole call and no eligibility is granted.
    /// @param membershipProof Groth16 proof for VASPCircuit (ignored if membership not required).
    /// @param attributeProof  Groth16 proof for ThresholdCircuit (ignored if attribute not required).
    /// @param attributeCommitment The public commitment for the attribute proof (Poseidon2 of the hidden value).
    function register(
        bytes calldata membershipProof,
        bytes calldata attributeProof,
        uint256 attributeCommitment
    ) external {
        if (requireMembership) {
            membershipVerifier.verifyProof(membershipProof, [eligibleHoldersRoot]);
        }
        if (requireAttribute) {
            attributeVerifier.verifyProof(attributeProof, [attributeCommitment, attributeThreshold]);
        }
        eligible[msg.sender] = true;
        emit Registered(msg.sender, requireMembership, requireAttribute);
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

    /// @notice Issuer governance: update roots / thresholds / which checks apply.
    function setConfig(uint256 _root, uint256 _threshold, bool _reqMembership, bool _reqAttribute)
        external
        onlyAdmin
    {
        if (!_reqMembership && !_reqAttribute) revert NothingRequired();
        eligibleHoldersRoot = _root;
        attributeThreshold = _threshold;
        requireMembership = _reqMembership;
        requireAttribute = _reqAttribute;
        emit ConfigUpdated(_root, _threshold, _reqMembership, _reqAttribute);
    }
}
