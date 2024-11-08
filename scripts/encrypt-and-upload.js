const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const readline = require('readline');
require('dotenv').config();

const pinataApiKey = process.env.PINATA_API_KEY;
const pinataSecretApiKey = process.env.PINATA_SECRET_API_KEY;
const pinata = new pinataSDK(pinataApiKey, pinataSecretApiKey);

function encryptFile(fileBuffer, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
    return { iv: iv.toString('hex'), content: encrypted.toString('hex') };
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
        console.log('File uploaded to IPFS via Pinata. IPFS Hash:', result.IpfsHash);
        fs.unlinkSync(tempFilePath);
        return result.IpfsHash;
    } catch (error) {
        console.error('Error uploading file to Pinata:', error);
        throw error;
    }
}

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('Enter the file path (e.g., ./test.txt): ', async (filePath) => {
        rl.question('Enter a password to encrypt the file: ', async (password) => {
            try {
                const fileBuffer = fs.readFileSync(filePath);
                const encryptedFile = encryptFile(fileBuffer, password);
                const ipfsHash = await uploadToPinata(encryptedFile);
                console.log('Successfully uploaded encrypted file to IPFS via Pinata. Hash:', ipfsHash);
            } catch (error) {
                console.error('Error:', error);
            } finally {
                rl.close();
            }
        });
    });
}

main();