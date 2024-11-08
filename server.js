const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const { decryptFile } = require('./scripts/decrypt-and-download');

require('dotenv').config();

const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

const app = express();
app.use(bodyParser.json());
app.use(express.static('views'));

const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), async (req, res) => {
    const password = req.body.password;
    const originalFileName = req.body.originalFileName;

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);

    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
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
    const options = { pinataMetadata: { name: originalFileName }, pinataOptions: { cidVersion: 1 } };
    const result = await pinata.pinFileToIPFS(stream, options);

    fs.unlinkSync(filePath);
    fs.unlinkSync(tempFilePath);

    res.json({ ipfsHash: result.IpfsHash });
});

app.post('/download', async (req, res) => {
    const { ipfsHash, password } = req.body;

    try {
        const url = `https://ipfs.io/ipfs/${ipfsHash}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error('Failed to retrieve file from IPFS');
        }

        const encryptedFile = await response.json();
        const originalFileName = encryptedFile.originalFileName || 'decrypted_file';

        const decryptedFile = decryptFile(encryptedFile, password);

        res.json({ success: true, fileContent: decryptedFile, originalFileName: originalFileName });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));