const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');
const readline = require('readline');

function decryptFile(encryptedFile, password) {
    const key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        key,
        Buffer.from(encryptedFile.iv, 'hex')
    );

    try {
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(encryptedFile.content, 'hex')),
            decipher.final()
        ]);
        return decrypted;
    } catch (error) {
        throw new Error("Decryption failed. Possible incorrect password or corrupted file.");
    }
}

module.exports = { decryptFile };

async function downloadFromIPFS(ipfsHash) {
    try {
        const url = `https://ipfs.io/ipfs/${ipfsHash}`;
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        const fileData = Buffer.from(response.data).toString();

        let encryptedFile;
        try {
            encryptedFile = JSON.parse(fileData);
        } catch (error) {
            throw new Error("Downloaded data is not in the expected format. Decryption failed.");
        }

        return encryptedFile;
    } catch (error) {
        console.error('Error downloading file from IPFS:', error);
        throw error;
    }
}

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('Enter the IPFS hash: ', (ipfsHash) => {
        rl.question('Enter the password to decrypt the file: ', async (password) => {
            try {
                const encryptedFile = await downloadFromIPFS(ipfsHash);
                const originalFileName = encryptedFile.originalFileName || 'decrypted_file';
                const decryptedFile = decryptFile(encryptedFile, password);
                fs.writeFileSync(`./${originalFileName}`, decryptedFile);
                console.log(`Decrypted file saved as ${originalFileName}`);
            } catch (error) {
                console.error('Error:', error.message);
            } finally {
                rl.close();
            }
        });
    });
}

//main();