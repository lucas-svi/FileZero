const axios = require('axios');

async function downloadFromIPFS(ipfsHash) {
    try {
        if (!ipfsHash) {
            throw new Error('IPFS hash is required');
        }

        console.log('IPFS Hash:', ipfsHash);
        
        // Choose an alternative gateway
        const gateway = 'https://gateway.pinata.cloud';
        const url = `${gateway}/ipfs/${ipfsHash}`;
        
        console.log('Fetching file from:', url);
        
        const response = await axios.get(url, { responseType: 'text' });
        const fileData = response.data;
        console.log('Downloaded File Data:', fileData);
        
        let encryptedFile;
        try {
            encryptedFile = JSON.parse(fileData);
        } catch (error) {
            throw new Error("Downloaded data is not in the expected JSON format. Decryption failed.");
        }

        return encryptedFile;
    } catch (error) {
        console.error('Error downloading file from IPFS:', error.message);
        throw error; // Re-throw the error to be handled by the caller
    }
}

// Example usage
async function main() {
    try {
        const ipfsHash = 'bafkreihpalqshkefxzlfjwkegkmco55kk3l7blswo5fulmjitmatf7ecg4'; // Replace with your actual IPFS hash
        const data = await downloadFromIPFS(ipfsHash);
        console.log('Encrypted File:', data);
    } catch (error) {
        console.error('Failed to download from IPFS:', error.message);
    }
}

main();
