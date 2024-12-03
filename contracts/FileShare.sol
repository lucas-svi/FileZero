// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShare {
    struct File {
        address owner;
        address[] authorized;
        string ipfsHash;
    }

    mapping(bytes32 => File) private files;
    address public serverAddress;

    event FileUploaded(bytes32 indexed proof, string ipfsHash, address indexed owner);
    event FileAccessed(bytes32 indexed proof, address indexed accessedBy, string ipfsHash, uint256 timestamp);
    event UnauthorizedAccess(bytes32 indexed proof, address indexed attemptedBy, string ipfsHash, string ipAddress, uint256 timestamp);
    event AddressAuthorized(bytes32 indexed proof, address indexed authorizedAddress);
    event AddressRevoked(bytes32 indexed proof, address indexed revokedAddress);

    constructor() {
        serverAddress = msg.sender; // Server deploys the contract
    }

    modifier onlyOwnerOrServer(bytes32 proof) {
        require(files[proof].owner == msg.sender || msg.sender == serverAddress, "Not authorized.");
        _;
    }

    function uploadFile(string memory _ipfsHash, address[] memory initialAuthorized, address owner) public {
        require(msg.sender == serverAddress, "Only server can call this function.");
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        require(files[proof].owner == address(0), "File already uploaded.");

        File storage newFile = files[proof];
        newFile.owner = owner;
        newFile.ipfsHash = _ipfsHash;

        for (uint256 i = 0; i < initialAuthorized.length; i++) {
            address addr = initialAuthorized[i];
            require(addr != address(0), "Invalid address.");
            newFile.authorized.push(addr);
            emit AddressAuthorized(proof, addr);
        }

        emit FileUploaded(proof, _ipfsHash, owner);
    }

    function isAuthorized(string memory _ipfsHash, address user) public view returns (bool) {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        if (files[proof].owner == user) {
            return true;
        }
        for (uint256 i = 0; i < files[proof].authorized.length; i++) {
            if (files[proof].authorized[i] == user) {
                return true;
            }
        }
        return false;
    }

    function authorizeAddress(string memory _ipfsHash, address newAuthorized) public onlyOwnerOrServer(keccak256(abi.encodePacked(_ipfsHash))) {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        require(newAuthorized != address(0), "Invalid address.");

        for (uint256 i = 0; i < files[proof].authorized.length; i++) {
            require(files[proof].authorized[i] != newAuthorized, "Address already authorized.");
        }

        files[proof].authorized.push(newAuthorized);
        emit AddressAuthorized(proof, newAuthorized);
    }

    function revokeAddress(string memory _ipfsHash, address toRevoke) public onlyOwnerOrServer(keccak256(abi.encodePacked(_ipfsHash))) {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        address[] storage authorized = files[proof].authorized;
        bool found = false;

        for (uint256 i = 0; i < authorized.length; i++) {
            if (authorized[i] == toRevoke) {
                authorized[i] = authorized[authorized.length - 1];
                authorized.pop();
                found = true;
                emit AddressRevoked(proof, toRevoke);
                break;
            }
        }

        require(found, "Address not found.");
    }

    function logAccess(string memory _ipfsHash, address user) public {
        require(isAuthorized(_ipfsHash, user), "User not authorized.");
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        emit FileAccessed(proof, user, _ipfsHash, block.timestamp);
    }

    function logUnauthorizedAccess(string memory _ipfsHash, address user, string memory ipAddress) public {
        bytes32 proof = keccak256(abi.encodePacked(_ipfsHash));
        emit UnauthorizedAccess(proof, user, _ipfsHash, ipAddress, block.timestamp);
    }
}