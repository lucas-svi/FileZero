require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const requestIp = require('request-ip');
const { ethers } = require('ethers');
const path = require('path');
const fetch = require('node-fetch');

const salt = process.env.SALT || 'secure-salt';
const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

const app = express();
app.set('trust proxy', true);
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'views')));

const upload = multer({ dest: 'uploads/' });

const provider = new ethers.JsonRpcProvider(`https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`);
const privateKey = process.env.PRIVATE_KEY;
const wallet = new ethers.Wallet(privateKey, provider);

const contractABI = require('./artifacts/contracts/FileShare.sol/FileShare.json').abi;
const contractAddress = process.env.CONTRACT_ADDRESS;
const fileShareContract = new ethers.Contract(contractAddress, contractABI, wallet);

async function downloadFromIPFS(ipfsHash) {
    const url = `https://gateway.pinata.cloud/ipfs/${ipfsHash}`;
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error('Failed to fetch file from IPFS.');
    }
    return await response.json();
}

const sanitizeFilename = (filename) => {
    return filename.replace(/[^a-zA-Z0-9-_\.]/g, '_').replace(/"/g, '');
};

function normalizeIp(ip) {
    if (ip === '::1') {
        return '127.0.0.1';
    }
    
    if (ip.includes('::ffff:')) {
        return ip.split('::ffff:')[1];
    }

    return ip;
}

app.post('/upload', upload.single('file'), async (req, res) => {
    const { password, authorizeSelf } = req.body;
    try {
        const uploaderAddress = ethers.getAddress(req.body.walletAddress);
        const authorizedAddressesInput = req.body.authorizedAddresses;
        const filePath = req.file.path;
        const fileBuffer = fs.readFileSync(filePath);
        console.log("Upload Wallet Address:", uploaderAddress);
        let authorizedList = [];

        if (authorizedAddressesInput) {
            authorizedList = authorizedAddressesInput
                .split(',')
                .map(addr => addr.trim())
                .filter(addr => ethers.isAddress(addr))
                .map(addr => ethers.getAddress(addr));
        }
        
        if (authorizeSelf === 'true') {
            if (!authorizedList.includes(uploaderAddress)) {
                authorizedList.push(uploaderAddress);
            }
        }

        console.log("Authorized Addresses:", authorizedList);
        let ownerAddress = authorizedList.length > 0 ? authorizedList[0] : uploaderAddress;
        console.log("Owner Address:", ownerAddress);
        const encryptionKey = crypto.createHash('sha256').update(password + ownerAddress + salt).digest();
        console.log("Encryption Key:", encryptionKey);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);

        const encryptedFile = {
            iv: iv.toString('hex'),
            content: encrypted.toString('hex'),
            originalFileName: req.file.originalname
        };

        const tempFilePath = 'encrypted_file.json';
        fs.writeFileSync(tempFilePath, JSON.stringify(encryptedFile));

        const stream = fs.createReadStream(tempFilePath);
        const options = {
            pinataMetadata: {
                name: req.file.originalname,
            },
            pinataOptions: {
                cidVersion: 1
            }
        };
        const result = await pinata.pinFileToIPFS(stream, options);

        fs.unlinkSync(filePath);
        fs.unlinkSync(tempFilePath);

        const ipfsHash = result.IpfsHash;
        console.log("Uploaded IPFS Hash:", ipfsHash);
        const tx = await fileShareContract.uploadFile(
            ipfsHash,
            authorizedList,
            ownerAddress
        );
        await tx.wait();

        res.json({ success: true, ipfsHash });
    } catch (error) {
        console.error('Upload Error:', error);
        res.status(500).json({ success: false, error: 'Failed to upload file.' });
    }
});

app.post('/download', async (req, res) => {
    try {
        const { ipfsHash, password } = req.body;
        const walletAddress = ethers.getAddress(req.body.walletAddress);
        console.log("Download Wallet Address:", walletAddress);
        const fileId = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));
        
        const isAuthorized = await fileShareContract.isAuthorized(fileId, walletAddress);
        if (!isAuthorized) {
            const tx = await fileShareContract.logUnauthorizedAccess(fileId, walletAddress, normalizeIp(requestIp.getClientIp(req)));
            await tx.wait();
            return res.status(403).json({ success: false, error: 'You are not authorized to access this file. Your unauthorized attempt has been publicly logged.' });
        }

        const ownerAddress = await fileShareContract.getOwner(fileId); //this should already be standardized via ethers.getAddress, right?
        console.log("Download Owner Address:", ownerAddress);
        const encryptedFile = await downloadFromIPFS(ipfsHash);

        const encryptionKey = crypto.createHash('sha256').update(password + ownerAddress + salt).digest();
        console.log("Decrypted Key:", encryptionKey);
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, Buffer.from(encryptedFile.iv, 'hex'));
        const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);

        const tx = await fileShareContract.logFileAccess(fileId, walletAddress);
        await tx.wait();

        const filename = encryptedFile.originalFileName
            ? sanitizeFilename(encryptedFile.originalFileName)
            : 'decrypted_file';
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(decrypted);
    } catch (error) {
        console.error('Download Error:', error);
        res.status(500).json({ success: false, error: 'Failed to download file.' });
    }
});

app.get('/logs', async (req, res) => {
    const { ipfsHash, userAddress } = req.query;

    if (!ipfsHash || !userAddress) {
        return res.status(400).json({ success: false, error: 'IPFS hash and user address are required.' });
    }

    try {
        const fileId = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));

        const accessEvents = await fileShareContract.queryFilter(fileShareContract.filters.FileAccessed(fileId));
        const unauthorizedEvents = await fileShareContract.queryFilter(fileShareContract.filters.UnauthorizedAccess(fileId));

        const accessLogs = accessEvents.map(event => ({
            accessedBy: event.args.accessedBy,
            timestamp: new Date(Number(event.args.timestamp) * 1000).toLocaleString(),
        }));
        console.log("Access Logs:", accessLogs);
        const unauthorizedLogs = unauthorizedEvents.map(event => ({
            attemptedBy: event.args.attemptedBy,
            ipAddress: event.args.ipAddress,
            timestamp: new Date(Number(event.args.timestamp) * 1000).toLocaleString(),
        }));
        console.log("Unauthorized Logs:", unauthorizedLogs);
        res.json({ success: true, accessLogs, unauthorizedLogs });
    } catch (error) {
        console.error('Logs Error:', error);
        res.status(500).json({ success: false, error: 'Failed to retrieve logs.' });
    }
});

app.post('/authorize', async (req, res) => {
    const { ipfsHash, newAddress, walletAddress, password } = req.body;
    try {
        walletAddress = ethers.getAddress(walletAddress);
        const fileId = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));
        console.log("File ID:", fileId);
        console.log("Authorize Wallet Address:", walletAddress);
        const ownerAddress = await fileShareContract.getOwner(fileId);
        console.log("Authorize Owner Address:", ownerAddress);
        if (walletAddress !== ownerAddress) {
            return res.status(403).json({ success: false, error: 'Only the owner can authorize users.' });
        }

        const encryptionKey = crypto.createHash('sha256').update(password + ownerAddress + salt).digest();
        const encryptedFile = await downloadFromIPFS(ipfsHash);
        const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, Buffer.from(encryptedFile.iv, 'hex'));

        try {
            Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);
        } catch {
            return res.status(401).json({ success: false, error: 'Invalid password.' });
        }

        const tx = await fileShareContract.grantAccess(fileId, newAddress);
        await tx.wait();

        res.json({ success: true, message: 'Access granted successfully.' });
    } catch (error) {
        console.error('Authorization Error:', error);
        res.status(500).json({ success: false, error: 'Failed to authorize user.' });
    }
});

app.post('/revoke', async (req, res) => {
    const { ipfsHash, revokedAddress, walletAddress, password } = req.body;
    try {
        walletAddress = ethers.getAddress(walletAddress);
        const fileId = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));

        const ownerAddress = await fileShareContract.getOwner(fileId);
        if (walletAddress !== ownerAddress) {
            return res.status(403).json({ success: false, error: 'Only the owner can revoke access.' });
        }

        const encryptionKey = crypto.createHash('sha256').update(password + ownerAddress + salt).digest();
        const encryptedFile = await downloadFromIPFS(ipfsHash);
        const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, Buffer.from(encryptedFile.iv, 'hex'));

        try {
            Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);
        } catch {
            return res.status(401).json({ success: false, error: 'Invalid password.' });
        }

        const tx = await fileShareContract.revokeAccess(fileId, revokedAddress);
        await tx.wait();

        res.json({ success: true, message: 'Access revoked successfully.' });
    } catch (error) {
        console.error('Revocation Error:', error);
        res.status(500).json({ success: false, error: 'Failed to revoke access.' });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});