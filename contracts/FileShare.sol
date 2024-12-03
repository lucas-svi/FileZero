// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShare {
    mapping(bytes32 => bool) public fileOwnershipProofs;

    event FileUploaded(bytes32 indexed proof, string ipfsHash, address indexed owner);
    event FileAccessed(bytes32 indexed proof, address indexed accessedBy, uint256 timestamp);
    event UnauthorizedAccess(bytes32 indexed proof, address indexed attemptedBy, string ipAddress, uint256 timestamp);

    function uploadFile(string memory _ipfsHash, address user) public {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash, user));
        require(!fileOwnershipProofs[proof], "File already uploaded by this user.");
        fileOwnershipProofs[proof] = true;
        emit FileUploaded(proof, _ipfsHash, user);
    }

    function verifyOwnership(string memory _ipfsHash, address user) public view returns (bool) {
        return fileOwnershipProofs[keccak256(abi.encodePacked(_ipfsHash, user))];
    }

    function logAccess(string memory _ipfsHash, address user) public {
        emit FileAccessed(keccak256(abi.encodePacked(_ipfsHash, user)), user, block.timestamp);
    }

    function logUnauthorizedAccess(string memory _ipfsHash, address user, string memory ipAddress) public {
        emit UnauthorizedAccess(keccak256(abi.encodePacked(_ipfsHash, user)), user, ipAddress, block.timestamp);
    }

    function computeProof(string memory _ipfsHash, address user) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_ipfsHash, user));
    }
}