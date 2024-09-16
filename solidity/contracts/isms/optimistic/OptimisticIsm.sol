// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {Message} from "../../libs/Message.sol";
import {TypeCasts} from "../../libs/TypeCasts.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title OptimisticIsm
 * @notice Implements the optimistic verification security model for Hyperlane
 */
contract OptimisticIsm is IOptimisticIsm, Ownable {
    using Message for bytes;
    using TypeCasts for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    // ============ Constants ============

    uint256 public constant FRAUD_WINDOW = 30 minutes;

    // ============ Structs ============

    struct VerificationData {
        uint256 timestamp;
        bool isVerified;
        uint256 fraudReports;
    }

    // ============ Public Storage ============

    mapping(bytes32 => VerificationData) public verifications;
    IInterchainSecurityModule public submodule;
    EnumerableSet.AddressSet private watchers;
    uint256 public requiredWatchers;

    // ============ Constructor ============

    constructor(address _submodule, uint256 _requiredWatchers) {
        _setSubmodule(_submodule);
        _setRequiredWatchers(_requiredWatchers);
    }

    // ============ External Functions ============

    /**
     * @notice Pre-verifies a message using the submodule
     * @param _metadata Metadata needed for verification
     * @param _message The message to verify
     * @return True if the message was successfully pre-verified
     */
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external override returns (bool) {
        bytes32 messageId = _message.id();
        require(
            verifications[messageId].timestamp == 0,
            "Message already pre-verified"
        );

        bool verified = submodule.verify(_metadata, _message);
        if (verified) {
            verifications[messageId] = VerificationData({
                timestamp: block.timestamp,
                isVerified: true,
                fraudReports: 0
            });
            emit MessagePreVerified(messageId);
        }
        return verified;
    }

    /**
     * @notice Verifies a message after the fraud window has passed
     * @param _metadata Metadata needed for verification
     * @param _message The message to verify
     * @return True if the message is verified
     */
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external override returns (bool) {
        bytes32 messageId = _message.id();
        VerificationData storage data = verifications[messageId];

        require(data.isVerified, "Message not pre-verified");
        require(
            block.timestamp >= data.timestamp + FRAUD_WINDOW,
            "Fraud window not elapsed"
        );
        require(
            data.fraudReports < requiredWatchers,
            "Fraud threshold reached"
        );

        emit MessageVerified(messageId);
        return true;
    }

    /**
     * @notice Allows a watcher to report fraud for a specific message
     * @param messageId The ID of the message to mark as fraudulent
     */
    function markFraudulent(bytes32 messageId) external override {
        require(watchers.contains(msg.sender), "Not authorized");

        VerificationData storage data = verifications[messageId];
        require(data.isVerified, "Message not pre-verified");

        data.fraudReports++;
        emit FraudReported(msg.sender, messageId);
    }

    // ============ Watcher Management ============

    /**
     * @notice Adds a new watcher
     * @param _watcher The address of the watcher to add
     */
    function addWatcher(address _watcher) external onlyOwner {
        require(watchers.add(_watcher), "Watcher already exists");
        emit WatcherAdded(_watcher);
    }

    /**
     * @notice Removes a watcher
     * @param _watcher The address of the watcher to remove
     */
    function removeWatcher(address _watcher) external onlyOwner {
        require(watchers.remove(_watcher), "Watcher does not exist");
        uint256 totalWatchers = watchers.length();

        if (requiredWatchers > totalWatchers) {
            _setRequiredWatchers(totalWatchers);
        }

        emit WatcherRemoved(_watcher);
    }

    /**
     * @notice Returns the list of current watchers
     * @return The list of watcher addresses
     */
    function getWatchers() external view returns (address[] memory) {
        return watchers.values();
    }

    // ============ Submodule Management ============

    /**
     * @notice Sets a new submodule
     * @param _newSubmodule The address of the new submodule
     */
    function setSubmodule(address _newSubmodule) external onlyOwner {
        _setSubmodule(_newSubmodule);
    }

    /**
     * @notice Sets the number of watchers required to mark a message as fraudulent
     * @param _newRequiredWatchers The new number of required watchers
     */
    function setRequiredWatchers(
        uint256 _newRequiredWatchers
    ) external onlyOwner {
        _setRequiredWatchers(_newRequiredWatchers);
    }

    // ============ Internal Functions ============

    /**
     * @notice Internal function to set the submodule
     * @param _newSubmodule The address of the new submodule
     */
    function _setSubmodule(address _newSubmodule) internal {
        require(_newSubmodule != address(0), "Invalid submodule address");
        submodule = IInterchainSecurityModule(_newSubmodule);
        emit SubmoduleSet(_newSubmodule);
    }

    /**
     * @notice Internal function to set the required number of watchers
     * @param _newRequiredWatchers The new number of required watchers
     */
    function _setRequiredWatchers(uint256 _newRequiredWatchers) internal {
        require(_newRequiredWatchers > 0, "Required watchers must be > 0");
        require(
            _newRequiredWatchers <= watchers.length(),
            "Required watchers must be <= total watchers"
        );
        requiredWatchers = _newRequiredWatchers;

        emit RequiredWatchersSet(_newRequiredWatchers);
    }

    // ============ Override ============

    /**
     * @notice Returns the module type
     * @return The module type as a uint8
     */
    function moduleType() external pure override returns (uint8) {
        return uint8(IInterchainSecurityModule.Types.OPTIMISTIC);
    }
}
