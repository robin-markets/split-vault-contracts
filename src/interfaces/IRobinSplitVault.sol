// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.31;

import { IERC4626 } from '@openzeppelin/contracts/interfaces/IERC4626.sol';

/// @title IRobinSplitVault
/// @notice ERC-4626 yield source that deploys USDC.e into fully-hedged Polymarket positions.
///         Deposits are split into equal YES+NO conditional tokens on a single manager-selected
///         market that pays daily holder rewards; withdrawals merge pairs back to USDC.e at par.
interface IRobinSplitVault is IERC4626 {
    // ============ Events ============

    /// @notice Emitted when the active market changes (bytes32(0) = no market / wind-down).
    event MarketUpdated(bytes32 indexed oldConditionId, bytes32 indexed newConditionId);

    /// @notice Emitted on `compound()`. `recognized` is the newly folded-in yield; `deployed` the
    ///         idle USDC.e split into the market; the `vesting*` fields are the schedule as stored
    ///         after the call (a no-op compound repeats the unchanged schedule, so `vestingStart`
    ///         can predate the event).
    event Compounded(uint256 recognized, uint256 deployed, uint256 vestingAmount, uint64 vestingStart, uint64 vestingEnd);

    /// @notice `compound()`'s best-effort unwrap failed: the PolyUSD waits and the compound
    ///         continues. Monitor this; `eth_call` `unwrapRewards(0)` for the exact reason.
    event UnwrapFailed();

    /// @notice The last funded holder left and the books closed: the residual accounting
    ///         is dropped, returning any leftover backing to undetected yield for the next
    ///         holder's `compound()`.
    event BooksClosed(uint256 trackedAssets, uint256 vestingAmount);

    /// @notice `compound()` found yield but skipped recognition. No funded shares exist or the
    ///         supply is below the recognition floor (irtual shares would capture the
    ///         yield); `pending` stays as undetected backing until a compound that qualifies.
    event YieldPending(uint256 pending);

    /// @notice Emitted when the base vesting duration changes.
    event BaseVestingDurationUpdated(uint64 oldDuration, uint64 newDuration);

    /// @notice Emitted when the Polymarket CollateralOfframp address changes.
    event OfframpUpdated(address oldOfframp, address newOfframp);

    // ============ Errors ============

    error ZeroAddress();
    error ZeroShares();
    /// @notice The condition does not exist on the CTF or is not a binary market.
    error InvalidMarket(bytes32 conditionId);
    /// @notice Withdrawal needs more USDC.e than idle + mergeable pairs while no market is set.
    error NoActiveMarket();
    /// @notice ERC-1155 tokens pushed by a contract other than the ConditionalTokens.
    error UnsolicitedTransfer(address token);
    /// @notice Base vesting duration must be in [MIN_BASE_VESTING_DURATION, MAX_BASE_VESTING_DURATION].
    error BaseVestingDurationOutOfRange(uint64 duration);
    /// @notice `amount` exceeds the vault's PolyUSD balance.
    error InvalidUnwrapAmount(uint256 amount, uint256 balance);
    /// @notice The offramp address has no code (EOA, undeployed, or wrong chain).
    error InvalidOfframp(address offramp);

    // ============ External Functions ============

    /// @notice The daily keeper call. Unwraps PolyUSD (best effort — failures are reported via
    ///         `UnwrapFailed` and skipped, never fatal), deploys idle USDC.e into the market, and
    ///         folds all backing above `trackedAssets` into the vesting schedule. New yield enters
    ///         over the period it accrued (clamped to [base, MAX]), so it drips out at roughly the
    ///         rate it was earned. Permissionless.
    /// @return unwrapped False if PolyUSD was present and could not be unwrapped.
    /// @return recognized Yield newly folded into the vesting schedule.
    function compound() external returns (bool unwrapped, uint256 recognized);

    /// @notice Unwraps `amount` PolyUSD into USDC.e via the offramp (0 = entire balance).
    ///         Partial amounts let keepers drain a backlog a thin offramp reserve cannot cover in
    ///         one go; failures revert loudly. Recognized as yield by the next `compound()`.
    ///         Permissionless.
    function unwrapRewards(uint256 amount) external;

    /// @notice Exits the current market (merging all pairs to USDC.e) and enters `newConditionId`,
    ///         splitting all idle USDC.e into it. Pass bytes32(0) to exit into idle USDC.e.
    function setMarket(bytes32 newConditionId) external;

    /// @notice Sets the base vesting duration: the minimum duration a new tranche enters the
    ///         schedule with, however fast it accrued. Applies to future compounds.
    function setBaseVestingDuration(uint64 newDuration) external;

    /// @notice Updates the Polymarket CollateralOfframp used to unwrap PolyUSD rewards. Must be a
    ///         deployed contract.
    function setOfframp(address newOfframp) external;

    // ============ View Functions ============

    /// @notice The active market and its cached position IDs (all zero when no market is set).
    function activeMarket() external view returns (bytes32 conditionId, uint256 yesPositionId, uint256 noPositionId);

    /// @notice USDC.e value locked in YES+NO pairs of the active market (min of both balances).
    function pairedAssets() external view returns (uint256);

    /// @notice Accounted backing: net deposits plus all recognized yield. `totalAssets` is this
    ///         minus the unvested remainder; backing above it is yield awaiting the next compound.
    function trackedAssets() external view returns (uint256);

    /// @notice Recognized yield not yet reflected in totalAssets (the still-vesting remainder).
    function unvestedProfit() external view returns (uint256);

    /// @notice Current vesting schedule: `amount` vests linearly between `start` and `end` (the
    ///         blended schedule length is `end - start`); `baseDuration` is the configured minimum
    ///         duration a new tranche enters the blend with.
    function vestingInfo() external view returns (uint256 amount, uint64 start, uint64 end, uint64 baseDuration);

    /// @notice Last moment the vault was verified caught up (initialization, or a `compound()`
    ///         whose unwrap succeeded). The next tranche's accrual period is measured from here.
    function lastRecognitionAt() external view returns (uint64);

    /// @notice Yield not yet recognized: all backing (PolyUSD at par, idle USDC.e, pairs) above
    ///         `trackedAssets`, whatever token it arrived in.
    function pendingYield() external view returns (uint256);
}
