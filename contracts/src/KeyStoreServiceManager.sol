// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@eigenlayer/contracts/libraries/BytesLib.sol";
import "@eigenlayer/contracts/core/DelegationManager.sol";
import "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import {IRegistryCoordinator} from "@eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import "./IKeyStoreServiceManager.sol";

///TODO: Purpose: the purpose of this service is to provide an interface between the coinbase smart wallet and an external ownership system.
///     In this case we are adding an Eigenlayer KeyStore AVS between the smart wallet and multiOwner contracts. In a future project we will deploy a full AVS that makes external calls. 

/**
 * @title KeyStore oracle for smart wallet contracts
 * @author captnseagraves
 */
contract KeyStoreServiceManager is 
    ECDSAServiceManagerBase,
    IKeyStoreServiceManager,
    Pausable
{
    using BytesLib for bytes;
    using ECDSAUpgradeable for bytes32;

    /* STORAGE */
    // The latest task index
    uint32 public latestTaskNum;

    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes;

    // mapping of task indices to hash of abi.encode(taskResponse, taskResponseMetadata)
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;

    /* MODIFIERS */
    /// @notice Modifier to ensure only operators can call a function.
    /// @dev Checks if the caller is registered as an operator in the stake registry.
    modifier onlyOperator() {
        require(
            ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender) 
            == 
            true, 
            "Operator must be the caller"
        );
        _;
    }

    /// @notice Constructor for the KeyStoreServiceManager contract.
    /// @param _avsDirectory The address of the AVS directory.
    /// @param _stakeRegistry The address of the stake registry.
    /// @param _delegationManager The address of the delegation manager.
    constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _delegationManager
    )
        ECDSAServiceManagerBase(
            _avsDirectory,
            _stakeRegistry,
            address(0), // keyStore doesn't need to deal with payments
            _delegationManager
        )
    {}


    /* FUNCTIONS */
    /// @notice Checks if a public key is an owner of a smart wallet.
    /// @dev This function creates a new isOwnerPublicKey task and assigns it a taskId
    /// @param smartWalletAddress The address of the smart wallet.
    /// @param ownerAddress The address of the owner to check.
    function isOwnerAddressRequest(
        address smartWalletAddress,
        address ownerAddress
    ) external {
        // create a new task struct
        Task memory newTask;
        // set smartWalletAddress   
        newTask.smartWalletAddress = smartWalletAddress;
        // set ownerAddress
        newTask.ownerAddress = ownerAddress;
        // set taskCreatedBlock
        newTask.taskCreatedBlock = uint32(block.number);

        // store hash of task onchain, emit event, and increase taskNum
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));

        // emit event
        ///@dev operators will use this event to find tasks to respond to
        emit NewIsOwnerAddressRequest(latestTaskNum, newTask);

        // increment taskNum
        latestTaskNum = latestTaskNum + 1;
    }

    /// @notice Responds to a getOwner task with the owner's address and a signature.
    /// @dev This function checks if the task is valid, hasn't been responded to yet, and is being responded to in time.
    ///      It also verifies that the signature corresponds to the task and was signed by the operator.
    /// @param task The task structure containing details about the getOwner request.
    /// @param isOwner The result of the task.
    /// @param referenceTaskIndex The index of the task being responded to.
    /// @param signature The digital signature proving the operator's response is valid.
    function isOwnerAddressResponse(
        Task calldata task,
        bool isOwner,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external onlyOperator {
        // check that the operator has the minimum weight
        require(
            operatorHasMinimumWeight(msg.sender),
            "Operator does not have the weight requirements"
        );

        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            keccak256(abi.encode(task)) ==
                allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );

        // check that the operator has not already responded to the task
        require(
            allTaskResponses[msg.sender][referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // hash the task and smartWalletOwner
        bytes32 isOwnerHash = keccak256(abi.encode(task, isOwner));
        // convert to eth signed message hash   
        bytes32 ethSignedWalletHash = isOwnerHash.toEthSignedMessageHash();

        // Recover the signer address from the signature
        address signer = ethSignedWalletHash.recover(signature);

        // check that the signer is the operator
        require(signer == msg.sender, "Message signer is not operator");

        // updating the storage with task responses
        allTaskResponses[msg.sender][referenceTaskIndex] = signature;

        // emitting event
        emit IsOwnerAddressResponse(referenceTaskIndex, task, isOwner, msg.sender, signature);
    }

    // HELPER

    function operatorHasMinimumWeight(address operator) public view returns (bool) {
        return ECDSAStakeRegistry(stakeRegistry).getOperatorWeight(operator) >= ECDSAStakeRegistry(stakeRegistry).minimumWeight();
    }
}