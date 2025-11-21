#!/usr/bin/env tsx

import { execSync } from "child_process";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { ethers } from "ethers";
import {
  DEPLOYER_PRIVATE_KEY,
  SIGNER_ONE_ADDRESS,
  SIGNER_TWO_ADDRESS,
  SIGNER_THREE_ADDRESS,
  SIGNER_TWO_PRIVATE_KEY,
  SIGNER_THREE_PRIVATE_KEY,
} from "./config";

interface ChainConfig {
  name: string;
  rpc: string;
  htlcs: string[];
  fundAmount: string;
}

interface Config {
  chains: ChainConfig[];
}

interface DeployedContracts {
  chain: string;
  multiSigSigner: string;
  gardenSolver: string;
  signer1Address: string;
  signer2Address: string;
  signer3Address: string;
  signer1KeyHash: string;
  signer2KeyHash: string;
  signer3KeyHash: string;
  multisigKeyHash: string;
  deployedAt: string;
}

interface DeploymentSummary {
  total: number;
  successful: number;
  failed: number;
  deployedAt: string;
}

interface DeploymentResults {
  deployments: Record<string, DeployedContracts>;
  summary: DeploymentSummary;
}

function deriveDeployerAddress(privateKey: string): string {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

/**
 * Get chain ID from RPC provider
 */
async function getChainId(rpcUrl: string): Promise<number> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  return Number(network.chainId);
}

/**
 * Parse contract addresses from forge broadcast artifacts
 */
function parseBroadcastArtifacts(
  chainId: number,
  scriptName: string
): {
  multiSigSigner: string;
  gardenSolver: string;
} {
  const broadcastPath = join(
    __dirname,
    `../broadcast/${scriptName}/${chainId}/run-latest.json`
  );

  if (!existsSync(broadcastPath)) {
    throw new Error(
      `Broadcast artifact not found: ${broadcastPath}\n` +
        `Make sure the deployment completed successfully.`
    );
  }

  const broadcast = JSON.parse(readFileSync(broadcastPath, "utf-8"));

  const contracts: Record<string, string> = {};

  // Extract contract addresses from transactions
  for (const tx of broadcast.transactions || []) {
    if (tx.transactionType === "CREATE" && tx.contractName) {
      contracts[tx.contractName] = tx.contractAddress;
    }
  }

  // Also check receipts as fallback
  for (const receipt of broadcast.receipts || []) {
    if (receipt.contractAddress) {
      // Find matching transaction to get contract name
      const matchingTx = broadcast.transactions?.find(
        (tx: any) => tx.hash === receipt.transactionHash
      );
      if (matchingTx?.contractName) {
        contracts[matchingTx.contractName] = receipt.contractAddress;
      }
    }
  }

  const multiSigSigner = contracts["MultiSigSigner"];
  const gardenSolver = contracts["GardenSolver"];

  if (!multiSigSigner) {
    throw new Error(
      `Could not find MultiSigSigner address in broadcast artifacts`
    );
  }

  if (!gardenSolver) {
    throw new Error(
      `Could not find GardenSolver address in broadcast artifacts`
    );
  }

  return { multiSigSigner, gardenSolver };
}

function parseKeyHash(output: string, keyName: string): string {
  // Try multiple patterns to find key hash
  const patterns = [
    new RegExp(`${keyName}.*?KeyHash.*?:\\s+(0x[a-fA-F0-9]{64})`, "i"),
    new RegExp(`${keyName}.*?:\\s+(0x[a-fA-F0-9]{64})`, "i"),
  ];

  for (const regex of patterns) {
    const match = output.match(regex);
    if (match && match[1]) {
      return match[1];
    }
  }

  // If not found, try to find any 64-char hex after the key name
  const lines = output.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toLowerCase().includes(keyName.toLowerCase())) {
      const hashMatch = lines[i].match(/(0x[a-fA-F0-9]{64})/);
      if (hashMatch) {
        return hashMatch[1];
      }
    }
  }

  throw new Error(`Could not find ${keyName} key hash in forge output`);
}

async function deployContracts(chain: ChainConfig): Promise<DeployedContracts> {
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Deploying contracts to ${chain.name}`);
  console.log(`RPC: ${chain.rpc}`);
  console.log(`${"=".repeat(50)}\n`);

  if (!DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY is required for deployment");
  }

  // Always use SIGNER_ADDRESS (hardware wallet) as signer1 - required
  const SIGNER_ADDRESS = process.env.SIGNER_ADDRESS || SIGNER_ONE_ADDRESS;
  if (!SIGNER_ADDRESS) {
    throw new Error(
      "SIGNER_ADDRESS (or SIGNER_ONE_ADDRESS) is required for deployment. This will be used as Signer 1 (hardware wallet address)."
    );
  }

  const signer1Address = ethers.getAddress(SIGNER_ADDRESS);
  console.log(
    `ℹ️  Using SIGNER_ADDRESS (hardware wallet) as Signer 1: ${signer1Address}`
  );

  let signer2Address: string;
  let signer3Address: string;

  // Get remaining signers
  if (SIGNER_TWO_ADDRESS && SIGNER_THREE_ADDRESS) {
    signer2Address = ethers.getAddress(SIGNER_TWO_ADDRESS);
    signer3Address = ethers.getAddress(SIGNER_THREE_ADDRESS);
  } else if (SIGNER_TWO_PRIVATE_KEY && SIGNER_THREE_PRIVATE_KEY) {
    signer2Address = deriveDeployerAddress(SIGNER_TWO_PRIVATE_KEY);
    signer3Address = deriveDeployerAddress(SIGNER_THREE_PRIVATE_KEY);
  } else {
    throw new Error(
      "SIGNER_TWO_ADDRESS and SIGNER_THREE_ADDRESS (or their private keys) are required for deployment."
    );
  }

  const deployerAddress = deriveDeployerAddress(DEPLOYER_PRIVATE_KEY);

  console.log("📋 Deployment Configuration:");
  console.log(`   Deployer: ${deployerAddress}`);
  console.log(`   Signer 1: ${signer1Address}`);
  console.log(`   Signer 2: ${signer2Address}`);
  console.log(`   Signer 3: ${signer3Address}`);
  console.log("");

  const fundAmountEth = chain.fundAmount;
  const fundAmountWei = ethers.parseEther(fundAmountEth).toString();

  const env = {
    ...process.env,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
    SIGNER1_ADDRESS: signer1Address,
    SIGNER2_ADDRESS: signer2Address,
    SIGNER3_ADDRESS: signer3Address,
    FUND_AMOUNT_WEI: fundAmountWei, //@dev Amount in wei (Solidity expects uint256)
    MULTISIG_THRESHOLD: "1", // 2-of-3
  };

  console.log(
    `💰 Funding GardenSolver with: ${fundAmountEth} ETH (${fundAmountWei} wei)`
  );

  // Build forge command
  const scriptPath = join(__dirname, "../script/main/DeployContracts.s.sol");
  const command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("🚀 Executing deployment...");
  console.log(`   Command: ${command}\n`);

  try {
    // Capture both stdout and stderr
    const output = execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large outputs
    });

    const chainId = await getChainId(chain.rpc);
    console.log(`   Chain ID: ${chainId}`);

    // Parse contract addresses from broadcast artifacts
    const scriptName = "DeployContracts.s.sol";
    const { multiSigSigner, gardenSolver } = parseBroadcastArtifacts(
      chainId,
      scriptName
    );

    // need to parse key hashes from console.log output (not available in broadcast artifacts)
    const signer1KeyHash = parseKeyHash(output, "Signer1 KeyHash");
    const signer2KeyHash = parseKeyHash(output, "Signer2 KeyHash");
    const signer3KeyHash = parseKeyHash(output, "Signer3 KeyHash");
    const multisigKeyHash = parseKeyHash(output, "Multisig KeyHash");

    console.log("✅ Deployment successful!");
    console.log(`   MultiSigSigner: ${multiSigSigner}`);
    console.log(`   GardenSolver: ${gardenSolver}`);
    console.log("");

    return {
      chain: chain.name,
      multiSigSigner,
      gardenSolver,
      signer1Address,
      signer2Address,
      signer3Address,
      signer1KeyHash,
      signer2KeyHash,
      signer3KeyHash,
      multisigKeyHash,
      deployedAt: new Date().toISOString(),
    };
  } catch (error: any) {
    console.error("❌ Deployment failed:");
    const errorMessage = error.message || "Unknown error";
    const stdout = error.stdout || "";
    const stderr = error.stderr || "";

    // Show the actual error output
    if (stdout) {
      console.error("\n--- Forge Output (STDOUT) ---");
      console.error(stdout);
    }
    if (stderr) {
      console.error("\n--- Forge Output (STDERR) ---");
      console.error(stderr);
    }

    // Create a more informative error
    const fullError = new Error(
      `Deployment failed: ${errorMessage}\n${
        stdout ? `\nOutput:\n${stdout}` : ""
      }${stderr ? `\nErrors:\n${stderr}` : ""}`
    );
    throw fullError;
  }
}

async function main() {
  const configPath = join(__dirname, "config.json");
  const config: Config = JSON.parse(readFileSync(configPath, "utf-8"));

  if (config.chains.length === 0) {
    throw new Error("No chains configured in config.json");
  }

  console.log(`\n${"=".repeat(50)}`);
  console.log(`Starting deployment to ${config.chains.length} chain(s)`);
  console.log(`${"=".repeat(50)}\n`);

  const results: DeploymentResults = {
    deployments: {},
    summary: {
      total: config.chains.length,
      successful: 0,
      failed: 0,
      deployedAt: new Date().toISOString(),
    },
  };

  // Deploy to all chains
  for (let i = 0; i < config.chains.length; i++) {
    const chain = config.chains[i];
    const chainNumber = i + 1;

    console.log(
      `\n[${chainNumber}/${config.chains.length}] Processing chain: ${chain.name}`
    );

    try {
      const deployed = await deployContracts(chain);
      results.deployments[chain.name] = deployed;
      results.summary.successful++;
    } catch (error: any) {
      console.error(`\n❌ Failed to deploy to ${chain.name}:`);
      const errorMsg = error.message || error.toString() || "Unknown error";
      // Truncate very long error messages
      const displayMsg =
        errorMsg.length > 500 ? errorMsg.substring(0, 500) + "..." : errorMsg;
      console.error(`   ${displayMsg}`);
      results.summary.failed++;

      // Continue with next chain instead of stopping
      console.log(`\n⚠️  Continuing with remaining chains...\n`);
    }
  }

  // Write deployed.json
  const deployedPath = join(__dirname, "deployed.json");
  writeFileSync(deployedPath, JSON.stringify(results, null, 2));

  // Print summary
  console.log(`\n${"=".repeat(50)}`);
  console.log("📊 Deployment Summary");
  console.log(`${"=".repeat(50)}`);
  console.log(`Total chains: ${results.summary.total}`);
  console.log(`✅ Successful: ${results.summary.successful}`);
  console.log(`❌ Failed: ${results.summary.failed}`);
  console.log("");

  if (results.summary.successful > 0) {
    console.log("Successfully deployed chains:");
    for (const [chainName, deployment] of Object.entries(results.deployments)) {
      console.log(`\n  ${chainName}:`);
      console.log(`    MultiSigSigner: ${deployment.multiSigSigner}`);
      console.log(`    GardenSolver: ${deployment.gardenSolver}`);
    }
  }

  console.log(`\n💾 Deployment info saved to: ${deployedPath}`);
  console.log(`${"=".repeat(50)}\n`);

  // Exit with error code if any deployments failed
  if (results.summary.failed > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
