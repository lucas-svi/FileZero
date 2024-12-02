const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const { ethers } = require('ethers');
const { downloadFromIPFS } = require('./scripts/decrypt-and-download');
const salt = process.env.SALT || 'secure-salt';

require('dotenv').config();

const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

const app = express();
app.use(bodyParser.json());
app.use(express.static('views'));

const upload = multer({ dest: 'uploads/' });

const provider = new ethers.JsonRpcProvider(`https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`);
const privateKey = process.env.PRIVATE_KEY;
const wallet = new ethers.Wallet(privateKey, provider);
const contractABI = require('./artifacts/contracts/FileShare.sol/FileShare.json').abi;
const contractAddress = process.env.CONTRACT_ADDRESS;
const fileShareContract = new ethers.Contract(contractAddress, contractABI, wallet);

app.post('/upload', upload.single('file'), async (req, res) => {
    const { file, password, originalFileName, walletAddress} = req.body;
    try {
        const filePath = req.file.path;
        const fileBuffer = fs.readFileSync(filePath);

        const iv = crypto.randomBytes(16);
        const key = crypto.createHash('sha256').update(password + walletAddress + salt).digest();
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);

        const encryptedFile = {
            iv: iv.toString('hex'),
            content: encrypted.toString('hex'),
            originalFileName: originalFileName
        };

        const tempFilePath = 'encrypted_file.json';
        fs.writeFileSync(tempFilePath, JSON.stringify(encryptedFile));

        const stream = fs.createReadStream(tempFilePath);
        const options = {
            pinataMetadata: {
                name: originalFileName,
            },
            pinataOptions: {
                cidVersion: 1
            }
        };        
        const result = await pinata.pinFileToIPFS(stream, options);
        fs.unlinkSync(filePath);
        fs.unlinkSync(tempFilePath);
        
        const tx = await fileShareContract.uploadFile(result.IpfsHash, walletAddress);
        await tx.wait();
        res.json({ ipfsHash: result.IpfsHash });
    } catch (error) {
        console.error('Upload Error:', error);
        res.status(500).json({ error: 'Failed to upload file.' });
    }
});



app.post('/download', async (req, res) => {
    const { ipfsHash, password, walletAddress: userAddress } = req.body;
    
    const isOwner = await fileShareContract.verifyOwnership(ipfsHash, userAddress);
    if (!isOwner) {
        return res.status(403).json({ success: false, error: 'Access denied. You do not own this file.' });
    }
    const encryptedFile = await downloadFromIPFS(ipfsHash);
    const derivedKey = crypto.createHash('sha256')
        .update(password + userAddress + salt)
        .digest();
    //implement try catch to stop server from crashing!!!
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, Buffer.from(encryptedFile.iv, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);

    res.setHeader('Content-Disposition', `attachment; filename="${encryptedFile.originalFileName}"`);
    res.send(decrypted);
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