const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const { ethers } = require('ethers');
const { decryptFile } = require('./scripts/decrypt-and-download');

require('dotenv').config();

const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

const app = express();
app.use(bodyParser.json());
app.use(express.static('views'));

const upload = multer({ dest: 'uploads/' });

const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545');
const privateKey = process.env.PRIVATE_KEY;
const wallet = new ethers.Wallet(privateKey, provider);
const contractABI = require('./artifacts/contracts/FileShare.sol/FileShare.json').abi;
const contractAddress = process.env.CONTRACT_ADDRESS;
const fileShareContract = new ethers.Contract(contractAddress, contractABI, wallet);

app.post('/upload', upload.single('file'), async (req, res) => {
    const password = req.body.password;
    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
    const encryptedFile = {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex'),
        originalFileName: req.file.originalname,
    };

    const tempFilePath = 'encrypted_file.json';
    fs.writeFileSync(tempFilePath, JSON.stringify(encryptedFile));

    const stream = fs.createReadStream(tempFilePath);
    const options = { pinataMetadata: { name: req.file.originalname }, pinataOptions: { cidVersion: 1 } };
    const result = await pinata.pinFileToIPFS(stream, options);
    const ipfsHash = result.IpfsHash;

    fs.unlinkSync(filePath);
    fs.unlinkSync(tempFilePath);

    const tx = await fileShareContract.uploadFile(ipfsHash);
    await tx.wait();

    res.json({ ipfsHash });
});

app.post('/download', async (req, res) => {
    const { ipfsHash, password } = req.body;

    try {
        const isOwner = await fileShareContract.verifyOwnership(ipfsHash);

        if (!isOwner) {
            throw new Error('Access denied: You do not own this file.');
        }

        const url = `https://ipfs.io/ipfs/${ipfsHash}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error('Failed to retrieve file from IPFS');
        }

        const encryptedFile = await response.json();
        const originalFileName = encryptedFile.originalFileName || 'decrypted_file';

        const iv = Buffer.from(encryptedFile.iv, 'hex');
        const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);

        const logTx = await fileShareContract.logAccess(ipfsHash);
        await logTx.wait();

        res.json({ success: true, fileContent: decrypted, originalFileName });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/logs', async (req, res) => {
    try {
        const filter = fileShareContract.filters.FileAccessed();
        const events = await fileShareContract.queryFilter(filter);
        const logs = events.map(event => ({
            proof: event.args.proof,
            accessedBy: event.args.accessedBy,
            timestamp: new Date(event.args.timestamp.toNumber() * 1000).toLocaleString()
        }));

        res.json({ success: true, logs });
    } catch (error) {
        console.error('Error retrieving access logs:', error);
        res.json({ success: false, error: 'Error retrieving access logs.' });
    }
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));