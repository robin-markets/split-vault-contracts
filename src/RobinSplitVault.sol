// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.31;

import { Initializable } from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import { UUPSUpgradeable } from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import { AccessControlUpgradeable } from '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol';
import { ERC4626Upgradeable } from '@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol';
import { ReentrancyGuardTransient } from '@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol';
import { IERC20 } from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import { SafeERC20 } from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import { Math } from '@openzeppelin/contracts/utils/math/Math.sol';
import { IERC1155Receiver } from '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import { IConditionalTokens } from './interfaces/external/IConditionalTokens.sol';
import { ICollateralOfframp } from './interfaces/external/ICollateralOfframp.sol';
import { IRobinSplitVault } from './interfaces/IRobinSplitVault.sol';
import { IERC4626 } from '@openzeppelin/contracts/interfaces/IERC4626.sol';

/// @title RobinSplitVault
/// @notice Deposited USDC.e is split into equal YES+NO conditional tokens on a manager-selected Polymarket market
///         that pays daily holder rewards. A YES+NO pair always merges back to exactly 1 USDC.e, before and after
///         resolution, so withdrawals merge pairs on demand and are always instant and at par.
///
///         Rewards: on markets enrolled in its holding-rewards program (~3.25% APR), Polymarket
///         computes rewards off-chain, pro-rata to on-chain balances of the market's canonical
///         outcome tokens. Both sides earn, so a YES+NO pair earns fully hedged. Polymarket pushes
///         them roughly every 24h directly to the holding address, normally as PolyUSD.
///         The program is entirely off-chain and at Polymarket's discretion (rate,
///         cadence, eligibility), which is why rewards are treated as untrusted inbound transfers
///         and the manager can rotate markets when one stops paying.
///
///         Yield is whatever the vault holds above `trackedAssets` (net deposits + recognized
///         yield), regardless of the token it arrived in. It stays invisible to `totalAssets`
///         until the permissionless `compound()` unwraps PolyUSD (best effort), deploys idle
///         USDC.e, and folds the surplus into a linear vesting schedule. Each batch enters over
///         the period it accrued (min `baseVestingDuration`); the schedule is the amount-weighted
///         average of its batches' durations. The share price never jumps and drips at ≈ the earn
///         rate, so neither the daily payout nor a compound backlog can be sniped.
///
///         The drip pacing assumes a stable holder set: exiting mid-vest forfeits the exiter's
///         unvested slice, which stays on the running schedule and drips faster onto the
///         remaining shares. Forfeited yield is ownerless by design. Whoever holds shares while
///         it drips picks it up, first come first served, same as any residue left after a full
///         exit.
contract RobinSplitVault is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardTransient, ERC4626Upgradeable, IRobinSplitVault {
    using SafeERC20 for IERC20;

    // ============ Roles ============

    bytes32 public constant DEFAULT_MANAGER_ROLE = keccak256('DEFAULT_MANAGER_ROLE');
    bytes32 public constant TIMELOCKED_ROLE = keccak256('TIMELOCKED_ROLE');

    // ============ Constants ============

    /// @notice Floor on the base vesting duration — the anti-sniping guarantee proper. The accrual
    ///         clock is publicly resettable (any caught-up `compound()`), so only this floor bounds
    ///         how fast a payout can drip.
    uint64 public constant MIN_BASE_VESTING_DURATION = 8 hours;

    /// @notice Cap on the base duration and on any tranche's accrual period, so neither a
    ///         misconfiguration nor a long backlog can withhold profit indefinitely.
    uint64 public constant MAX_BASE_VESTING_DURATION = 30 days;

    /// @notice Supply floor for yield recognition: 1e12 shares = 1 USDC.e at the genesis price;
    ///         below it yield stays pending, deferred and never wiped, until real supply exists or the books close.
    uint256 public constant MIN_RECOGNITION_SUPPLY = 1e12;

    // CTF encoding for a binary market: top-level positions (no parent collection) and the
    // one-hot index sets for the two outcome slots.
    bytes32 private constant PARENT_COLLECTION_ID = bytes32(0);
    uint256 private constant YES_INDEX_SET = 1;
    uint256 private constant NO_INDEX_SET = 2;

    // ============ Storage ============

    /// @custom:storage-location erc7201:robin.storage.SplitVault
    struct SplitVaultStorage {
        // Immutable-after-init external contracts
        IConditionalTokens ctf;
        IERC20 polyUsd;
        // Offramp used to unwrap PolyUSD rewards (Polymarket may redeploy it; timelock-settable)
        ICollateralOfframp offramp;
        // Active market (bytes32(0) = none; deposits stay idle, withdrawals served from idle)
        bytes32 conditionId;
        uint256 yesPositionId;
        uint256 noPositionId;
        // Accounted backing: net deposits plus every yield tranche folded in by `compound()`.
        // Real backing (idle USDC.e + paired collateral) above this is undetected yield,
        // invisible to `totalAssets` until the next `compound()`.
        uint256 trackedAssets;
        // Linear vesting: `vestingAmount` is recognized between `vestingStart` and `vestingEnd`.
        // The schedule is the amount-weighted average of its tranches' durations, each entering
        // over its accrual period and never less than `baseVestingDuration`.
        uint256 vestingAmount;
        uint64 vestingStart;
        uint64 vestingEnd;
        uint64 baseVestingDuration; //This is usually kept at 24 hours unless Polymarket's schedule changes.
        // Last moment the vault was verified caught up (initialization, or a `compound()` whose
        // unwrap succeeded). Tranches measure their accrual period from here, so dead time can
        // only stretch a tranche, never compress a backlog; a daily keeper bounds the stretch.
        uint64 lastRecognitionTime;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("robin.storage.SplitVault")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SPLIT_VAULT_STORAGE_LOCATION = 0xa8d15d08edd024ada635151278c2127cbd3933a91aae39618ece4d0baf731d00;

    function _getSplitVaultStorage() private pure returns (SplitVaultStorage storage $) {
        assembly {
            $.slot := SPLIT_VAULT_STORAGE_LOCATION
        }
    }

    // ============ Constructor ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /// @notice Initialize the Robin Split Vault
    /// @param initialOwner Receives DEFAULT_ADMIN_ROLE and DEFAULT_MANAGER_ROLE
    /// @param timelockController Receives the self-administered TIMELOCKED_ROLE (upgrades, offramp)
    /// @param ctf Polymarket ConditionalTokens
    /// @param usdc USDC.e, the ERC-4626 asset and CTF collateral
    /// @param polyUsd PolyUSD, the token Polymarket pays daily rewards in
    /// @param offramp Polymarket CollateralOfframp (PolyUSD → USDC.e)
    /// @param baseVestingDuration_ Minimum period a yield tranche vests over, in [MIN_BASE_VESTING_DURATION, MAX_BASE_VESTING_DURATION]
    function initialize(
        address initialOwner,
        address timelockController,
        address ctf,
        address usdc,
        address polyUsd,
        address offramp,
        uint64 baseVestingDuration_
    ) external initializer {
        if (initialOwner == address(0) || timelockController == address(0)) revert ZeroAddress();
        if (ctf == address(0) || usdc == address(0) || polyUsd == address(0)) revert ZeroAddress();
        if (offramp.code.length == 0) revert InvalidOfframp(offramp);
        if (baseVestingDuration_ < MIN_BASE_VESTING_DURATION || baseVestingDuration_ > MAX_BASE_VESTING_DURATION) {
            revert BaseVestingDurationOutOfRange(baseVestingDuration_);
        }

        __ERC20_init('Robin Split Vault', 'rsvUSDC');
        __ERC4626_init(IERC20(usdc));
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(DEFAULT_MANAGER_ROLE, initialOwner);
        _grantRole(TIMELOCKED_ROLE, timelockController);
        // Make TIMELOCKED_ROLE self-administered
        _setRoleAdmin(TIMELOCKED_ROLE, TIMELOCKED_ROLE);

        SplitVaultStorage storage $ = _getSplitVaultStorage();
        $.ctf = IConditionalTokens(ctf);
        $.polyUsd = IERC20(polyUsd);
        $.offramp = ICollateralOfframp(offramp);
        $.baseVestingDuration = baseVestingDuration_;
        $.lastRecognitionTime = uint64(block.timestamp);

        // One-time max approval: the CTF pulls collateral on every splitPosition and it's non-upgradable
        IERC20(usdc).forceApprove(ctf, type(uint256).max);
    }

    // ============ ERC-4626 Overrides ============

    /// @notice Accounted backing minus the still-vesting remainder.
    /// @dev Deliberately reads no live balances: undetected yield stays excluded until
    ///      `compound()`, so the share price can never jump on an inflow.
    function totalAssets() public view override(ERC4626Upgradeable, IERC4626) returns (uint256) {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        return $.trackedAssets - _unvestedProfit($);
    }

    /// @dev Track the principal, then split it into pairs (stays idle when no market is set).
    ///      `nonReentrant` lives on this hook: `deposit` and `mint` both funnel here, and
    ///      everything OZ runs before it is pure storage reads.
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override nonReentrant {
        if (shares == 0) revert ZeroShares();
        super._deposit(caller, receiver, assets, shares);
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        $.trackedAssets += assets;
        if ($.conditionId != bytes32(0)) _split($, assets);
    }

    /// @dev Merge exactly the missing pairs, drop the principal from `trackedAssets`, pay out.
    ///      `assets <= totalAssets <= trackedAssets`. The
    ///      `NoActiveMarket` branch is unreachable under consistent accounting — kept as an
    ///      invariant check. NonReentrant guarded here for the same reason as `_deposit`.
    function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal override nonReentrant {
        if (shares == 0) revert ZeroShares();
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        uint256 idle = IERC20(asset()).balanceOf(address(this));
        if (idle < assets) {
            if ($.conditionId == bytes32(0)) revert NoActiveMarket();
            _merge($, assets - idle);
        }
        $.trackedAssets -= assets;
        super._withdraw(caller, receiver, owner, assets, shares);

        // Last holder out closes the books: the residual (still-vesting remainder, later rewards)
        // returns to "undetected" state for the next holder's compound — otherwise it would sit
        // in `trackedAssets` with no holder, unreachable forever. "Empty" is when the remaining shares
        // collectively redeem to 0 assets.
        if (convertToAssets(totalSupply()) == 0) {
            emit BooksClosed($.trackedAssets, $.vestingAmount);
            $.trackedAssets = 0;
            $.vestingAmount = 0;
            $.vestingStart = uint64(block.timestamp);
            $.vestingEnd = uint64(block.timestamp);
        }
    }

    /// @notice Virtual-share offset applied to every share<>asset conversion.
    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }

    // ============ External Functions ============

    /// @inheritdoc IRobinSplitVault
    /// @dev (1) Unwrap PolyUSD via `unwrapRewards(0)` — best effort, a failure is reported and
    ///      skipped; (2) deploy idle USDC.e into the market; (3) recognize all backing above
    ///      `trackedAssets` and fold it into the schedule: the tranche enters over its accrual
    ///      period (`now - lastRecognitionTime`, clamped to [base, MAX]), blended with the
    ///      in-flight remainder by amount. Yield drips at ≈ its earn rate; a backlog stretches
    ///      the schedule; dust compounds cannot materially move the schedule.
    function compound() external nonReentrant returns (bool unwrapped, uint256 recognized) {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        IERC20 usdc = IERC20(asset());

        // (1) Best-effort unwrap. External self-call so a revert anywhere in the PolyUSD leg
        //     (token or offramp) is caught and fully rolled back. No third-party state may block
        //     recognition of yield that is already USDC.e or pairs.
        try this.unwrapRewards(0) {
            unwrapped = true;
        } catch {
            emit UnwrapFailed();
        }

        // (2) Deploy all idle USDC.e into the active market.
        uint256 deployed = 0;
        if ($.conditionId != bytes32(0)) {
            deployed = usdc.balanceOf(address(this));
            _split($, deployed);
        }

        // (3) Fold all backing above `trackedAssets` into the schedule, only while the live shares
        //     are worth something (see `_withdraw`) AND the supply clears the recognition floor,
        //     else the yield would be stranded on the virtual shares; it stays pending instead.
        uint64 nowStamp = uint64(block.timestamp);
        uint256 backing = usdc.balanceOf(address(this)) + _pairedAssets($);
        recognized = backing - $.trackedAssets; // >= 0: backing always covers accounted assets
        if (recognized > 0 && convertToAssets(totalSupply()) > 0 && totalSupply() >= MIN_RECOGNITION_SUPPLY) {
            // The new tranche vests over its accrual period, clamped to [base, max].
            uint256 duration = nowStamp - $.lastRecognitionTime;
            if (duration < $.baseVestingDuration) duration = $.baseVestingDuration;
            if (duration > MAX_BASE_VESTING_DURATION) duration = MAX_BASE_VESTING_DURATION;

            // Amount-weighted blend of the remainder's remaining time and the new tranche's
            // duration. `remaining > 0` whenever `remainder > 0`, and the blend is >= 1s.
            // Rounding goes toward `remaining` so dust can neither shave a stretched schedule nor stall a running one.
            uint256 remainder = _unvestedProfit($);
            uint256 remaining = remainder > 0 ? $.vestingEnd - nowStamp : 0;
            uint256 numerator = remainder * remaining + recognized * duration;
            uint256 denominator = remainder + recognized;
            uint256 blended = duration < remaining ? Math.ceilDiv(numerator, denominator) : numerator / denominator;

            $.trackedAssets = backing;
            $.vestingAmount = remainder + recognized;
            $.vestingStart = nowStamp;
            // Cast is safe: blended <= max(remaining, duration) <= MAX_BASE_VESTING_DURATION.
            // forge-lint: disable-next-line(unsafe-typecast)
            $.vestingEnd = nowStamp + uint64(blended);
        } else {
            if (recognized > 0) emit YieldPending(recognized);
            recognized = 0;
        }

        // The clock advances only when the vault is verified caught up (unwrap succeeded),
        // recognition or not. It stays frozen while PolyUSD is stuck behind a failing offramp.
        // Otherwise a multi-day backlog would later measure a near-zero period, be clamped up to
        // just baseVestingDuration, and drip at many times its earn rate. Accepted trade-off: concurrent USDC.e/pair yield is then
        // measured against the growing period and vests slower (capped at MAX) — delayed. Recovery is in Polymarket's
        // hands, not the vault's: the leg heals only when they fix the offramp or authorize a replacement
        // (`setOfframp`).
        if (unwrapped) $.lastRecognitionTime = nowStamp;

        emit Compounded(recognized, deployed, $.vestingAmount, $.vestingStart, $.vestingEnd);
    }

    /// @inheritdoc IRobinSplitVault
    /// @dev Single unwrap path: `compound()` self-calls it for the full balance under try/catch.
    ///      Unwrapped USDC.e stays outside `totalAssets` until recognized, so unwraps never move the share price.
    ///      Deliberately not `nonReentrant`: writes no vault state and must be callable from
    ///      inside `compound()`'s guard.
    function unwrapRewards(uint256 amount) public {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        uint256 balance = $.polyUsd.balanceOf(address(this));
        if (amount > balance) revert InvalidUnwrapAmount(amount, balance);
        if (balance == 0) return;
        if (amount == 0) amount = balance;

        ICollateralOfframp offramp = $.offramp;
        $.polyUsd.forceApprove(address(offramp), amount);
        offramp.unwrap(asset(), address(this), amount);
        $.polyUsd.forceApprove(address(offramp), 0);
    }

    // ============ Admin Functions ============

    /// @inheritdoc IRobinSplitVault
    /// @dev Value-neutral rotation: merge all pairs, re-split into the new market. A one-sided
    ///      donated surplus of the old market stays behind as dust `totalAssets` never counted.
    function setMarket(bytes32 newConditionId) external onlyRole(DEFAULT_MANAGER_ROLE) nonReentrant {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        bytes32 oldConditionId = $.conditionId;

        if (oldConditionId != bytes32(0)) {
            _merge($, _pairedAssets($));
        }

        if (newConditionId != bytes32(0)) {
            IConditionalTokens ctf = $.ctf;
            if (ctf.getOutcomeSlotCount(newConditionId) != 2) revert InvalidMarket(newConditionId);
            bytes32 yesCollectionId = ctf.getCollectionId(PARENT_COLLECTION_ID, newConditionId, YES_INDEX_SET);
            bytes32 noCollectionId = ctf.getCollectionId(PARENT_COLLECTION_ID, newConditionId, NO_INDEX_SET);
            $.conditionId = newConditionId;
            $.yesPositionId = ctf.getPositionId(asset(), yesCollectionId);
            $.noPositionId = ctf.getPositionId(asset(), noCollectionId);
            _split($, IERC20(asset()).balanceOf(address(this)));
        } else {
            $.conditionId = bytes32(0);
            $.yesPositionId = 0;
            $.noPositionId = 0;
        }

        emit MarketUpdated(oldConditionId, newConditionId);
    }

    /// @inheritdoc IRobinSplitVault
    /// @dev Applies to future tranches; the in-flight schedule keeps its end. Bounded to
    ///      [MIN, MAX] so the manager can track the payout cadence but never remove the floor.
    function setBaseVestingDuration(uint64 newDuration) external onlyRole(DEFAULT_MANAGER_ROLE) {
        if (newDuration < MIN_BASE_VESTING_DURATION || newDuration > MAX_BASE_VESTING_DURATION) revert BaseVestingDurationOutOfRange(newDuration);
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        uint64 oldDuration = $.baseVestingDuration;
        $.baseVestingDuration = newDuration;
        emit BaseVestingDurationUpdated(oldDuration, newDuration);
    }

    /// @inheritdoc IRobinSplitVault
    /// @dev Timelocked: the offramp receives PolyUSD approvals during `compound()`. Must have
    ///      code but so a code-less offramp is rejected loudly at set-time instead of silently
    ///      failing every unwrap until rotated again.
    function setOfframp(address newOfframp) external onlyRole(TIMELOCKED_ROLE) {
        if (newOfframp.code.length == 0) revert InvalidOfframp(newOfframp);
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        address oldOfframp = address($.offramp);
        $.offramp = ICollateralOfframp(newOfframp);
        emit OfframpUpdated(oldOfframp, newOfframp);
    }

    // ============ View Functions ============

    /// @inheritdoc IRobinSplitVault
    function activeMarket() external view returns (bytes32 conditionId, uint256 yesPositionId, uint256 noPositionId) {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        return ($.conditionId, $.yesPositionId, $.noPositionId);
    }

    /// @inheritdoc IRobinSplitVault
    function pairedAssets() external view returns (uint256) {
        return _pairedAssets(_getSplitVaultStorage());
    }

    /// @inheritdoc IRobinSplitVault
    function trackedAssets() external view returns (uint256) {
        return _getSplitVaultStorage().trackedAssets;
    }

    /// @inheritdoc IRobinSplitVault
    function unvestedProfit() external view returns (uint256) {
        return _unvestedProfit(_getSplitVaultStorage());
    }

    /// @inheritdoc IRobinSplitVault
    function vestingInfo() external view returns (uint256 amount, uint64 start, uint64 end, uint64 baseDuration) {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        return ($.vestingAmount, $.vestingStart, $.vestingEnd, $.baseVestingDuration);
    }

    /// @inheritdoc IRobinSplitVault
    function lastRecognitionAt() external view returns (uint64) {
        return _getSplitVaultStorage().lastRecognitionTime;
    }

    /// @inheritdoc IRobinSplitVault
    /// @dev PolyUSD is counted at par (the offramp's rate); `compound()` measures the actual
    ///      unwrap, so this is a preview of what the next compound will recognize.
    function pendingYield() external view returns (uint256) {
        SplitVaultStorage storage $ = _getSplitVaultStorage();
        uint256 backing = $.polyUsd.balanceOf(address(this)) + IERC20(asset()).balanceOf(address(this)) + _pairedAssets($);
        return backing - $.trackedAssets;
    }

    // ============ ERC-1155 Receiver ============

    /// @notice Accept CTF mints from splitPosition (the CTF is msg.sender for all its transfers).
    ///         Third-party position donations only increase balances and are harmless.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external view returns (bytes4) {
        if (msg.sender != address(_getSplitVaultStorage().ctf)) revert UnsolicitedTransfer(msg.sender);
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external view returns (bytes4) {
        if (msg.sender != address(_getSplitVaultStorage().ctf)) revert UnsolicitedTransfer(msg.sender);
        return this.onERC1155BatchReceived.selector;
    }

    /// @inheritdoc AccessControlUpgradeable
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || super.supportsInterface(interfaceId);
    }

    // ============ Internal Functions ============

    /// @notice Authorize a UUPS upgrade to a new implementation
    /// @dev Restricted to TIMELOCKED_ROLE to enforce governance delay on upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(TIMELOCKED_ROLE) { }

    /// @dev Complete YES+NO pairs of the active market, from live CTF balances. No counter that
    ///      could drift, and donated pairs are picked up.
    function _pairedAssets(SplitVaultStorage storage $) private view returns (uint256) {
        if ($.conditionId == bytes32(0)) return 0;
        uint256 yesBalance = $.ctf.balanceOf(address(this), $.yesPositionId);
        uint256 noBalance = $.ctf.balanceOf(address(this), $.noPositionId);
        return yesBalance < noBalance ? yesBalance : noBalance;
    }

    function _unvestedProfit(SplitVaultStorage storage $) private view returns (uint256) {
        uint256 end = $.vestingEnd;
        // Timestamp drift (~seconds) is immaterial against a >= 8h vesting schedule.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp >= end) return 0;
        uint256 start = $.vestingStart;
        return $.vestingAmount * (end - block.timestamp) / (end - start);
    }

    /// @dev Split `amount` USDC.e into `amount` YES + `amount` NO of the active market.
    function _split(SplitVaultStorage storage $, uint256 amount) private {
        if (amount == 0) return;
        $.ctf.splitPosition(asset(), PARENT_COLLECTION_ID, $.conditionId, _partition(), amount);
    }

    /// @dev Merge `amount` YES+NO pairs of the active market back into `amount` USDC.e.
    function _merge(SplitVaultStorage storage $, uint256 amount) private {
        if (amount == 0) return;
        $.ctf.mergePositions(asset(), PARENT_COLLECTION_ID, $.conditionId, _partition(), amount);
    }

    function _partition() private pure returns (uint256[] memory partition) {
        partition = new uint256[](2);
        partition[0] = YES_INDEX_SET;
        partition[1] = NO_INDEX_SET;
    }
}
