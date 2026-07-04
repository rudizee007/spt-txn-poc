// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * PoC — MidasLzVaultComposerSync: minAmountLD is NOT reset to 0 before the OFT send
 *       (contrary to the NatSpec on _depositAndSend/_redeemAndSend), so LayerZero's
 *       dust-removal can trip the send-leg slippage check and revert an otherwise-valid
 *       cross-chain deposit (which is then refunded).
 *
 * Self-contained, dependency-free reproduction. It mirrors the EXACT vulnerable send-path
 * of MidasLzVaultComposerSync._depositAndSend (contracts/misc/layerzero/MidasLzVaultComposerSync.sol):
 *
 *   L316 (NatSpec):  "... minAmountLD is reset to 0 for the send operation"
 *   L329-336:        mTokenAmount = _deposit(address(this), amount, _sendParam.minAmountLD, ...)   // minAmountLD used as vault slippage
 *   L339:            _sendParam.amountLD = mTokenAmount;                                            // amountLD set...
 *   L341:            _sendOft(mTokenOft, _sendParam, _refundAddress);                               // ...but minAmountLD NOT reset -> passed into OFT.send
 *
 * MockOFT faithfully replicates LayerZero OFTCore._removeDust + _debitView:
 *   amountSentLD = (amountLD / decimalConversionRate) * decimalConversionRate;   // dust removed
 *   if (amountSentLD < minAmountLD) revert SlippageExceeded(...);
 * with decimalConversionRate = 10^(localDecimals - sharedDecimals).
 *
 * REAL DEPLOYED CONFIG (verified): MidasLzMintBurnOFTAdapter.sharedDecimals() == 9 (hardcoded pure override),
 * mToken == 18 decimals  =>  decimalConversionRate = 10^(18-9) = 1e9. Dust = any sub-1e9 remainder (1e-9 mToken).
 *
 * Run:  forge test --match-contract MinAmountLDNotReset -vvv
 */

import "forge-std/Test.sol";

/// @dev Minimal LayerZero SendParam mirror (field names/order per @layerzerolabs/oft-evm IOFT.sol)
struct SendParam {
    uint32 dstEid;
    bytes32 to;
    uint256 amountLD;
    uint256 minAmountLD;
    bytes extraOptions;
    bytes composeMsg;
    bytes oftCmd;
}

struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

/// @dev Faithful mock of a LayerZero OFT's send()/_debitView() dust-removal + slippage behaviour.
contract MockOFT {
    error SlippageExceeded(uint256 amountLD, uint256 minAmountLD);

    uint256 public immutable decimalConversionRate; // 10^(localDecimals - sharedDecimals)

    constructor(uint8 localDecimals, uint8 sharedDecimals) {
        decimalConversionRate = 10 ** (localDecimals - sharedDecimals);
    }

    function _removeDust(uint256 amountLD) public view returns (uint256) {
        return (amountLD / decimalConversionRate) * decimalConversionRate;
    }

    /// @dev Mirrors OFTCore._debitView(): dust removed, then slippage checked against minAmountLD.
    function send(SendParam calldata p, MessagingFee calldata, address)
        external
        payable
        returns (uint256 amountSentLD)
    {
        amountSentLD = _removeDust(p.amountLD);
        if (amountSentLD < p.minAmountLD) revert SlippageExceeded(amountSentLD, p.minAmountLD);
        // (cross-chain delivery omitted; the revert vs success is the whole point)
    }
}

/// @dev Reproduces MidasLzVaultComposerSync._depositAndSend send-leg (L329-341) exactly.
contract ComposerSendPath {
    MockOFT public immutable mTokenOft;

    constructor(MockOFT _oft) {
        mTokenOft = _oft;
    }

    /**
     * @param mintedAmount   the mToken amount minted by the vault (== balance diff in _deposit, L424)
     * @param userSendParam  the SendParam the user supplied in the compose message
     * @param applyFix       if true, apply the missing reset the NatSpec promises (minAmountLD = 0)
     */
    function depositAndSend(uint256 mintedAmount, SendParam memory userSendParam, bool applyFix) external {
        // L339: amountLD updated to actual minted amount
        userSendParam.amountLD = mintedAmount;

        // L316 NatSpec claims minAmountLD is reset to 0 here. The real contract does NOT do it.
        if (applyFix) {
            userSendParam.minAmountLD = 0; // <-- the one missing line
        }

        // L341: _sendOft -> IOFT.send(sendParam, fee, refund)
        mTokenOft.send{value: 0}(userSendParam, MessagingFee(0, 0), address(this));
    }
}

contract MinAmountLDNotReset is Test {
    MockOFT oft;
    ComposerSendPath composer;

    function setUp() public {
        // REAL config: mToken 18 decimals, MidasLzMintBurnOFTAdapter.sharedDecimals() == 9
        // => decimalConversionRate = 10^(18-9) = 1e9
        oft = new MockOFT(18, 9);
        composer = new ComposerSendPath(oft);
    }

    /// The vault mints `mintedAmount` (>= the user's minAmountLD, so the *deposit* slippage passes),
    /// but the amount carries sub-1e12 "dust". Because minAmountLD is NOT reset, the OFT send reverts.
    function test_currentBehavior_dustTripsSendSlippage_andReverts() public {
        // A minted amount that is NOT a multiple of 1e9 (has sub-1e9 dust): 1.0000000005 mToken
        uint256 mintedAmount = 1e18 + 5e8;

        // User set tight slippage equal to their expected mToken (the vault guarantees minted >= this).
        SendParam memory sp;
        sp.dstEid = 30110; // arbitrary remote eid (!= local)
        sp.to = bytes32(uint256(uint160(address(0xBEEF))));
        sp.minAmountLD = 1e18 + 5e8; // == mintedAmount; vault deposit succeeds since minted >= min

        // Sanity: dust removal (rate 1e9) drops the 5e8 remainder, landing below the user's min
        assertEq(oft._removeDust(mintedAmount), 1e18, "dust removed to 1e18");
        assertLt(oft._removeDust(mintedAmount), sp.minAmountLD, "removed < min");

        // CURRENT (buggy) behavior: minAmountLD NOT reset -> send reverts -> whole compose reverts -> refund path.
        vm.expectRevert(
            abi.encodeWithSelector(MockOFT.SlippageExceeded.selector, uint256(1e18), uint256(1e18 + 5e8))
        );
        composer.depositAndSend(mintedAmount, sp, false);
    }

    /// With the documented-but-missing fix (minAmountLD = 0 on the send leg), the same deposit succeeds.
    function test_fixedBehavior_resetMinAmountLD_succeeds() public {
        uint256 mintedAmount = 1e18 + 5e8;
        SendParam memory sp;
        sp.dstEid = 30110;
        sp.to = bytes32(uint256(uint160(address(0xBEEF))));
        sp.minAmountLD = 1e18 + 5e8;

        // applyFix = true resets minAmountLD to 0 (what L316/L364 NatSpec says should happen)
        composer.depositAndSend(mintedAmount, sp, true); // does NOT revert
    }
}
