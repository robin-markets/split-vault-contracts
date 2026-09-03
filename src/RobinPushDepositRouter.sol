// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.31;

import { IERC20 } from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import { SafeERC20 } from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import { IERC4626 } from '@openzeppelin/contracts/interfaces/IERC4626.sol';

/// @title RobinPushDepositRouter
/// @notice Stateless periphery so approve-blocked contract wallets (e.g. Polymarket
///         DepositWallets) can enter ERC-4626 vaults: the wallet atomically batches
///         `asset.transfer(router, assets)` + `depositFor(vault, assets, wallet)`; the router
///         approves the vault from its own balance and mints the shares to the wallet.
///
///         Transfer + `depositFor` MUST be one atomic batch. The router is stateless
///         and unowned. Assets parked here between transactions belong to nobody: claimable by
///         anyone via `depositFor` or `rescue`.
contract RobinPushDepositRouter {
    using SafeERC20 for IERC20;

    event PushDeposited(address indexed vault, address indexed receiver, address indexed caller, uint256 assets, uint256 shares);
    event Rescued(address indexed token, address indexed to, uint256 amount);

    error ZeroAmount();
    error ZeroShares();

    /// @notice Deposits `assets` of `vault.asset()` held by this router into `vault`, minting the
    ///         shares to `receiver`. `type(uint256).max` = the router's entire asset balance
    ///         (avoids dust mismatches with the preceding transfer).
    /// @dev Must be batched atomically after the transfer that funds the router. Assumes an
    ///      EIP-4626-compliant vault that pulls exactly `assets`; against one that under-pulls,
    ///      the remainder stays claimable by anyone — such integrators should append
    ///      `rescue(asset)` to the same batch.
    function depositFor(IERC4626 vault, uint256 assets, address receiver) external returns (uint256 shares) {
        IERC20 asset = IERC20(vault.asset());
        if (assets == type(uint256).max) assets = asset.balanceOf(address(this));
        if (assets == 0) revert ZeroAmount();

        asset.forceApprove(address(vault), assets);
        shares = vault.deposit(assets, receiver);
        asset.forceApprove(address(vault), 0);

        if (shares == 0) revert ZeroShares();
        emit PushDeposited(address(vault), receiver, msg.sender, assets, shares);
    }

    /// @notice Transfers the router's entire balance of `token` to the caller. Strays only exist
    ///         when the atomicity rule was broken and are claimable by anyone regardless (via
    ///         `depositFor` with a crafted vault). Paying the caller just gives the legitimate
    ///         owner the easiest recovery path.
    function rescue(IERC20 token) external {
        uint256 balance = token.balanceOf(address(this));
        if (balance == 0) revert ZeroAmount();
        token.safeTransfer(msg.sender, balance);
        emit Rescued(address(token), msg.sender, balance);
    }
}
