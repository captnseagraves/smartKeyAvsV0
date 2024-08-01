// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IKeyStoreServiceManager {
    // EVENTS
    event NewIsOwnerAddressRequest(uint32 indexed taskIndex, Task task);

    event IsOwnerAddressResponse(uint32 indexed taskIndex, Task task, bool isOwner, address operator, bytes signature);

    // STRUCTS
    struct Task {
        address smartWalletAddress;
        address ownerAddress;
        uint32 taskCreatedBlock;
    }

    // FUNCTIONS
    /// @notice Checks if a public key is an owner of a smart wallet.
    /// @dev This function creates a new isOwnerPublicKey task and assigns it a taskId
    /// @param smartWalletAddress The address of the smart wallet.
    /// @param ownerAddress The address of the owner to check.
    function isOwnerAddressRequest(
        address smartWalletAddress,
        address ownerAddress    
    ) external;

    /// @notice Responds to a isOwnerPublicKey task.
    /// @dev This function is called by operators to respond to a task.
    /// @param task The task to respond to.
    /// @param isOwner The result of the task.
    /// @param referenceTaskIndex The index of the task to respond to.
    /// @param signature The signature of the operator.
    function isOwnerAddressResponse(
        Task calldata task,
        bool isOwner,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external;
}