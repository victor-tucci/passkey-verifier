const hre = require("hardhat");

async function main() {
  // Deploy the EntryPoint contract
  // const EntryPoint = await hre.ethers.deployContract("EntryPoint");
  // await EntryPoint.waitForDeployment();
 
  // const AccountFactory = await hre.ethers.deployContract("AccountFactory",["0xb87a472325C42BfC137499539C1A966Bce9ce10A"]);
  // await AccountFactory.waitForDeployment();

  const PasskeyRegistry = await hre.ethers.deployContract("PasskeyRegistryModule");
  await PasskeyRegistry.waitForDeployment();
    
  // const Paymaster = await hre.ethers.deployContract("Paymaster");
  // await Paymaster.waitForDeployment();

  // Log the deployed contract address
  // console.log("Deployed EntryPoint to:", EntryPoint.target);
  // console.log("Deployed AccountFactory to:", AccountFactory.target);
  console.log("Deployed PasskeyRegistry to:", PasskeyRegistry.target);
}

// Run the main function and catch any errors
main().catch((error) => {
  console.error(error);
  process.exit(1);
});
