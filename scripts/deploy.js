const { ethers } = require("hardhat");
async function main() {
    const [deployer] = await ethers.getSigners();
    
    console.log("Deploying contract with the account:", deployer.address);
  
    const MyContract = await ethers.getContractFactory("MyContract");
    const myContract = await MyContract.deploy("Hello, Hardhat!");
  
    console.log("Contract deployed to:", myContract.address);
  }
  
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });  