// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@eigenlayer/contracts/libraries/BytesLib.sol";
import "@eigenlayer/contracts/core/DelegationManager.sol";
import "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import {IRegistryCoordinator} from "@eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import "./IHelloWorldServiceManager.sol";

///TODO: Purpose: the purpose of this service is to provide an interface between the coinbase smart wallet and an external ownership system.
///     In this case we are adding an Eigenlayer KeyStore AVS between the smart wallet and multiOwner contracts. In a future project we will deploy a full AVS that makes external calls. 

/**
 * @title KeyStore oracle for smart wallet contracts
 * @author captnseagraves
 */
contract KeyStoreServiceManager is 
    ECDSAServiceManagerBase,
    IHelloWorldServiceManager,
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
    modifier onlyOperator() {
        require(
            ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender) 
            == 
            true, 
            "Operator must be the caller"
        );
        _;
    }

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
    // NOTE: this function creates a new getOwner task and assigns it a taskId
    function getOwner(
        address memory smartWalletAddress
    ) external {
        // create a new task struct
        Task memory newTask;
        newTask.smartWalletAddress = smartWalletAddress;
        newTask.taskCreatedBlock = uint32(block.number);

        // store hash of task onchain, emit event, and increase taskNum
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewGetOwnerRequest(latestTaskNum, newTask);
        latestTaskNum = latestTaskNum + 1;
    }

    // NOTE: this function responds to existing tasks.
    function getOwnerResponse(
        Task calldata task,
        address smartWalletOwner,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external onlyOperator returns(address smartWalletOwnerResponse){
        require(
            operatorHasMinimumWeight(msg.sender),
            "Operator does not have match the weight requirements"
        );
        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            keccak256(abi.encode(task)) ==
                allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        // some logical checks
        require(
            allTaskResponses[msg.sender][referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // The message that was signed
        bytes32 smartWalletOwnerHash = keccak256(abi.encodePacked(task, smartWalletOwner));
        bytes32 ethSignedWalletHash = smartWalletOwnerHash.toEthSignedMessageHash();

        // Recover the signer address from the signature
        address signer = ethSignedWalletHash.recover(signature);

        require(signer == msg.sender, "Message signer is not operator");

        // updating the storage with task responses
        allTaskResponses[msg.sender][referenceTaskIndex] = signature;

        // emitting event
        emit GetOwnerResponse(referenceTaskIndex, task, smartWalletOwner, msg.sender);
    }

    // HELPER

    function operatorHasMinimumWeight(address operator) public view returns (bool) {
        return ECDSAStakeRegistry(stakeRegistry).getOperatorWeight(operator) >= ECDSAStakeRegistry(stakeRegistry).minimumWeight();
    }
}