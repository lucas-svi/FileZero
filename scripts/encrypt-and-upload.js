const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');

const pinata = new pinataSDK('27da191fcf548524c42e', '9ebc471b5e1fb98d8d849741304e82064551a7232d7e78d88991d94242655714');

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
    const filePath = './test.txt'
    const password = 'your-encryption-password';
    try {
        const fileBuffer = fs.readFileSync(filePath);
        const encryptedFile = encryptFile(fileBuffer, password);
        const ipfsHash = await uploadToPinata(encryptedFile);
        console.log('Successfully uploaded encrypted file to IPFS via Pinata. Hash:', ipfsHash);
    } catch (error) {
        console.error('Error:', error);
    }
}
main();