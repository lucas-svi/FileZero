// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShare {
    mapping(bytes32 => bool) public fileOwnershipProofs;

    event FileUploaded(bytes32 indexed proof, string ipfsHash, address indexed owner);
    event FileAccessed(bytes32 indexed proof, address accessedBy, uint256 timestamp);

    function uploadFile(string memory _ipfsHash) public {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash, msg.sender));
        fileOwnershipProofs[proof] = true;
        emit FileUploaded(proof, _ipfsHash, msg.sender);
    }

    function verifyOwnership(string memory _ipfsHash) public view returns (bool) {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash, msg.sender));
        return fileOwnershipProofs[proof];
    }

    function logAccess(string memory _ipfsHash) public {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash, msg.sender));
        require(fileOwnershipProofs[proof], "You are not the owner of this file.");
        emit FileAccessed(proof, msg.sender, block.timestamp);
    }
}