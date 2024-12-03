const { ethers } = require('ethers');
require('dotenv').config();

(async () => {
    const provider = new ethers.JsonRpcProvider(`https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`);
    const privateKey = process.env.PRIVATE_KEY;
    const wallet = new ethers.Wallet(privateKey, provider);
    const contractABI = require('./artifacts/contracts/FileShare.sol/FileShare.json').abi;
    const contractAddress = process.env.CONTRACT_ADDRESS;
    const fileShareContract = new ethers.Contract(contractAddress, contractABI, wallet);

    const testIpfsHash = 'bafkreidrds7rlk6xt75m26afz2rvne3jugitodphkoagzgtmkar6b4i4cm';
    const testUserAddress = '0xdedd09aa2bad89f3131da7c98fcec486322d3bcb';
    const formattedTestUserAddress = ethers.getAddress(testUserAddress);

    try {
        const solidityProof = await fileShareContract.computeProof(testIpfsHash, formattedTestUserAddress);
        console.log('Solidity Proof:', solidityProof);

        const jsProof = ethers.keccak256(
            ethers.solidityPacked(['string', 'address'], [testIpfsHash, formattedTestUserAddress])
        );
        console.log('JavaScript Proof:', jsProof);

        console.log('Proofs match:', solidityProof === jsProof);
    } catch (error) {
        console.error('Error:', error);
    }
})();
