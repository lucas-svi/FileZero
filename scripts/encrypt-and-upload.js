const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const { ethers } = require('ethers');
const readline = require('readline');
const path = require('path');
require('dotenv').config();

const pinataApiKey = process.env.PINATA_API_KEY;
const pinataSecretApiKey = process.env.PINATA_SECRET_API_KEY;
const pinata = new pinataSDK(pinataApiKey, pinataSecretApiKey);

const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545');
const privateKey = process.env.PRIVATE_KEY;
const wallet = new ethers.Wallet(privateKey, provider);
const contractAddress = process.env.CONTRACT_ADDRESS;
const contractABI = require('../artifacts/contracts/FileShare.sol/FileShare.json').abi;
const contract = new ethers.Contract(contractAddress, contractABI, wallet);

function encryptFile(fileBuffer, password, originalFileName) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex'),
        originalFileName: originalFileName
    };
}

async function uploadToPinata(encryptedFile) {
    const options = {
        pinataMetadata: {
            name: 'Encrypted File',
            keyvalues: {
                customKey: 'customValue'
            }
        },
        pinataOptions: {
            cidVersion: 1
        }
    };
    try {
        const tempFilePath = './encrypted_file.json';
        fs.writeFileSync(tempFilePath, JSON.stringify(encryptedFile));
        const readableStreamForFile = fs.createReadStream(tempFilePath);
        const result = await pinata.pinFileToIPFS(readableStreamForFile, options);
        console.log('File uploaded to IPFS. IPFS Hash:', result.IpfsHash);
        fs.unlinkSync(tempFilePath);
        return result.IpfsHash;
    } catch (error) {
        console.error('Error uploading file to IPFS:', error);
        throw error;
    }
}

async function storeHashOnBlockchain(ipfsHash) {
    try {
        const tx = await contract.uploadFile(ipfsHash);
        await tx.wait();
        console.log(`IPFS hash stored on blockchain. Transaction hash: ${tx.hash}`);
    } catch (error) {
        console.error('Error storing hash on blockchain:', error);
    }
}

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('Enter the file path (e.g., ./test.txt): ', (filePath) => {
        rl.question('Enter a password to encrypt the file: ', async (password) => {
            try {
                const fileBuffer = fs.readFileSync(filePath);
                const originalFileName = path.basename(filePath);
                const encryptedFile = encryptFile(fileBuffer, password, originalFileName);
                const ipfsHash = await uploadToPinata(encryptedFile);
                await storeHashOnBlockchain(ipfsHash);
                console.log('File successfully uploaded to IPFS and IPFS hash stored on blockchain.');
            } catch (error) {
                console.error('Error:', error);
            } finally {
                rl.close();
            }
        });
    });
}

main();