// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IHelloWorldServiceManager {
    // EVENTS
    event NewGetOwnerRequest(uint32 indexed taskIndex, Task task);

    event GetOwnerResponse(uint32 indexed taskIndex, Task task, address smartWalletOwner, address operator);

    // STRUCTS
    struct Task {
        string smartWalletAddress;
        uint32 taskCreatedBlock;
    }

    // FUNCTIONS
    // NOTE: this function creates new task.
    function getOwner(
        address memory smartWalletAddress
    ) external;

    // NOTE: this function is called by operators to respond to a task.
    function getOwnerResponse(
        Task calldata task,
        address smartWalletOwner,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external;
}