require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  // defaultNetwork: "localhost",
  defaultNetwork: "amoy",
  networks: {
    amoy: {
      url: process.env.RPC_URL,
      accounts: [process.env.PRIVATE_KEY],
    },
  },
  solidity: {
    version: "0.8.23",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
  etherscan: {
    apiKey:process.env.API_KEY
  },
};
