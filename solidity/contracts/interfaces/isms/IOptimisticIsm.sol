// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

/**
 * @title IOptimisticIsm
 * @notice Interface for the Optimistic Interchain Security Module
 */
interface IOptimisticIsm is IInterchainSecurityModule {
    // ============ Events ============

    event MessagePreVerified(bytes32 indexed messageId);
    event MessageVerified(bytes32 indexed messageId);
    event FraudReported(address indexed watcher, bytes32 indexed messageId);
    event SubmoduleSet(address indexed newSubmodule);
    event WatcherAdded(address indexed watcher);
    event WatcherRemoved(address indexed watcher);
    event RequiredWatchersSet(uint256 newRequiredWatchers);

    /**
     * @notice Pre-verifies a message using the submodule
     * @param _metadata Metadata needed for verification
     * @param _message The message to verify
     * @return True if the message was successfully pre-verified
     */
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool);

    /**
     * @notice Allows a watcher to mark a submodule as fraudulent
     * @param messageId The ID of the message to mark as fraudulent
     */
    function markFraudulent(bytes32 messageId) external;

    /**
     * @notice Returns the current submodule
     * @return The address of the current submodule
     */
    function submodule() external view returns (IInterchainSecurityModule);
}
