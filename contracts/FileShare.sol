// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShare {
    struct File {
        address owner;
        address[] authorizedUsers;
        string ipfsHash;
    }

    mapping(bytes32 => File) private files;

    event FileUploaded(bytes32 indexed fileId, string ipfsHash, address indexed owner, address[] authorizedUsers);
    event AccessGranted(bytes32 indexed fileId, address indexed grantedTo);
    event AccessRevoked(bytes32 indexed fileId, address indexed revokedFrom);
    event FileAccessed(bytes32 indexed fileId, address indexed accessedBy, uint256 timestamp);
    event UnauthorizedAccess(bytes32 indexed fileId, address indexed attemptedBy, string ipAddress, uint256 timestamp);

    modifier onlyOwner(bytes32 fileId) {
        require(files[fileId].owner == msg.sender, "Only the file owner can perform this action.");
        _;
    }

    function uploadFile(
        string memory ipfsHash,
        address[] memory authorizedUsers,
        address owner
    ) public {
        bytes32 fileId = keccak256(abi.encodePacked(ipfsHash));
        require(files[fileId].owner == address(0), "File already exists.");

        if (owner == address(0) && authorizedUsers.length > 0) {
            owner = authorizedUsers[0];
        }

        files[fileId] = File({
            owner: owner,
            authorizedUsers: authorizedUsers,
            ipfsHash: ipfsHash
        });

        emit FileUploaded(fileId, ipfsHash, owner, authorizedUsers);
    }

    function grantAccess(bytes32 fileId, address user) public onlyOwner(fileId) {
        require(user != address(0), "Invalid address.");
        File storage file = files[fileId];

        for (uint256 i = 0; i < file.authorizedUsers.length; i++) {
            require(file.authorizedUsers[i] != user, "User already authorized.");
        }

        file.authorizedUsers.push(user);
        emit AccessGranted(fileId, user);
    }

    function revokeAccess(bytes32 fileId, address user) public onlyOwner(fileId) {
        File storage file = files[fileId];
        bool found = false;

        for (uint256 i = 0; i < file.authorizedUsers.length; i++) {
            if (file.authorizedUsers[i] == user) {
                file.authorizedUsers[i] = file.authorizedUsers[file.authorizedUsers.length - 1];
                file.authorizedUsers.pop();
                found = true;
                emit AccessRevoked(fileId, user);
                break;
            }
        }

        require(found, "User not found.");
    }

    function isAuthorized(bytes32 fileId, address user) public view returns (bool) {
        File storage file = files[fileId];
        if (file.owner == user) {
            return true;
        }
        for (uint256 i = 0; i < file.authorizedUsers.length; i++) {
            if (file.authorizedUsers[i] == user) {
                return true;
            }
        }
        return false;
    }

    function logFileAccess(bytes32 fileId, address user) public {
        require(isAuthorized(fileId, user), "User is not authorized.");
        emit FileAccessed(fileId, user, block.timestamp);
    }

    function logUnauthorizedAccess(bytes32 fileId, address user, string memory ipAddress) public {
        emit UnauthorizedAccess(fileId, user, ipAddress, block.timestamp);
    }

    function getOwner(bytes32 fileId) public view returns (address) {
        return files[fileId].owner;
    }

    function getAuthorizedUsers(bytes32 fileId) public view returns (address[] memory) {
        return files[fileId].authorizedUsers;
    }
}