const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');
const readline = require('readline');

function decryptFile(encryptedFile, password) {
    const key = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(encryptedFile.iv, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedFile.content, 'hex')), decipher.final()]);
    return decrypted;
}

async function downloadFromIPFS(ipfsHash) {
    try {
        const url = `https://ipfs.io/ipfs/${ipfsHash}`;
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        return JSON.parse(Buffer.from(response.data).toString());
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

    rl.question('Enter the IPFS hash: ', async (ipfsHash) => {
        rl.question('Enter the password to decrypt the file: ', async (password) => {
            try {
                const encryptedFile = await downloadFromIPFS(ipfsHash);
                const decryptedFile = decryptFile(encryptedFile, password);
                fs.writeFileSync('./decrypted_file.txt', decryptedFile);
                console.log('Decrypted file saved as decrypted_file.txt');
            } catch (error) {
                console.error('Error:', error);
            }
        });
    });
}
main();
