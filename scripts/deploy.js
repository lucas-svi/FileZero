const hre = require("hardhat");

async function main() {
    const FileShare = await hre.ethers.getContractFactory("FileShare");
    const fileShare = await FileShare.deploy();

    await fileShare.deployed();

    console.log("FileShare deployed to:", fileShare.address);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });