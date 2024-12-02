// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShare {
    mapping(bytes32 => bool) public fileOwnershipProofs;

    event FileUploaded(bytes32 indexed proof, string ipfsHash, address indexed owner);
    event FileAccessed(bytes32 indexed proof, uint256 timestamp);
    event UnauthorizedAccess(bytes32 indexed proof, string attemptedBy, uint256 timestamp);

    function uploadFile(string memory _ipfsHash, address user) public {
        bytes32 proof = keccak256(abi.encode(_ipfsHash, user));
        require(!fileOwnershipProofs[proof], "File already uploaded by this user.");
        fileOwnershipProofs[proof] = true;
        emit FileUploaded(proof, _ipfsHash, user);
    }

    function verifyOwnership(string memory _ipfsHash, address user) public view returns (bool) {
        bytes32 proof = keccak256(abi.encode(_ipfsHash, user));
        return fileOwnershipProofs[proof];
    }

    function logAccess(string memory _ipfsHash, address user) public {
        bytes32 proof = keccak256(abi.encode(_ipfsHash, user));
        require(fileOwnershipProofs[proof], "You are not the owner of this file.");
        emit FileAccessed(proof, block.timestamp);
    }

    function logUnauthorizedAccess(string memory _ipfsHash, string memory attemptedBy) public {
        bytes32 proof = keccak256(abi.encode(_ipfsHash, attemptedBy));
        emit UnauthorizedAccess(proof, attemptedBy, block.timestamp);
    }
}