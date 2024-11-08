// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.0;

contract FileShare {
    struct File {
        string ipfsHash;
        address owner;
    }

    mapping(uint256 => File) public files;
    uint256 public fileCount;

    event FileUploaded(uint256 fileId, string ipfsHash, address owner);

    function uploadFile(string memory _ipfsHash) public {
        fileCount++;
        files[fileCount] = File(_ipfsHash, msg.sender);

        emit FileUploaded(fileCount, _ipfsHash, msg.sender);
    }

    function getFile(uint256 _fileId) public view returns (string memory) {
        require(files[_fileId].owner == msg.sender, "You are not the owner of this file.");
        return files[_fileId].ipfsHash;
    }
}