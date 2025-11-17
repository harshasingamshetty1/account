#!/usr/bin/env tsx

import { execSync } from "child_process";
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { ethers } from "ethers";
import {
  DEPLOYER_PRIVATE_KEY,
  SIGNER_ONE_PRIVATE_KEY,
  SIGNER_TWO_PRIVATE_KEY,
  SIGNER_THREE_PRIVATE_KEY,
} from "./config";

interface ChainConfig {
  name: string;
  rpc: string;
  htlcs: string[];
  fundAmount?: string; // Optional: ETH amount to fund GardenSolver (default: 10)
}

interface Config {
  chains: ChainConfig[];
}

interface DeployedContracts {
  chain: string;
  orchestrator: string;
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

function deriveAddress(privateKey: string): string {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

function parseForgeOutput(output: string, contractName: string): string {
  // Try multiple patterns to find contract address
  const patterns = [
    new RegExp(`${contractName}:\\s+(0x[a-fA-F0-9]{40})`, "i"),
    new RegExp(
      `${contractName}\\s+deployed\\s+to:\\s+(0x[a-fA-F0-9]{40})`,
      "i"
    ),
    new RegExp(
      `Deployed\\s+${contractName}\\s+to:\\s+(0x[a-fA-F0-9]{40})`,
      "i"
    ),
  ];

  for (const regex of patterns) {
    const match = output.match(regex);
    if (match && match[1]) {
      return match[1];
    }
  }

  // If not found, try to find any address after the contract name
  const lines = output.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toLowerCase().includes(contractName.toLowerCase())) {
      // Look for address in the same line or next few lines
      for (let j = i; j < Math.min(i + 3, lines.length); j++) {
        const addrMatch = lines[j].match(/(0x[a-fA-F0-9]{40})/);
        if (addrMatch) {
          return addrMatch[1];
        }
      }
    }
  }

  throw new Error(`Could not find ${contractName} address in forge output`);
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

  // Derive addresses from private keys
  const deployerAddress = deriveAddress(DEPLOYER_PRIVATE_KEY);
  const signer1Address = deriveAddress(SIGNER_ONE_PRIVATE_KEY);
  const signer2Address = deriveAddress(SIGNER_TWO_PRIVATE_KEY);
  const signer3Address = deriveAddress(SIGNER_THREE_PRIVATE_KEY);

  console.log("📋 Deployment Configuration:");
  console.log(`   Deployer: ${deployerAddress}`);
  console.log(`   Signer 1: ${signer1Address}`);
  console.log(`   Signer 2: ${signer2Address}`);
  console.log(`   Signer 3: ${signer3Address}`);
  console.log("");

  const fundAmountEth = chain.fundAmount!;
  const fundAmountWei = ethers.parseEther(fundAmountEth).toString();

  const env = {
    ...process.env,
    DEPLOYER: deployerAddress,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
    SIGNER1_ADDRESS: signer1Address,
    SIGNER2_ADDRESS: signer2Address,
    SIGNER3_ADDRESS: signer3Address,
    FUND_AMOUNT_WEI: fundAmountWei, // Amount in wei (Solidity expects uint256)
    MULTISIG_THRESHOLD: "2", // 2-of-3
  };

  console.log(
    `💰 Funding GardenSolver with: ${fundAmountEth} ETH (${fundAmountWei} wei)`
  );

  // Build forge command
  const scriptPath = join(__dirname, "../main/DeployContracts.s.sol");
  const command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("🚀 Executing deployment...");
  console.log(`   Command: ${command}\n`);

  try {
    const output = execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "pipe",
    });

    // Parse contract addresses from output
    const orchestrator = parseForgeOutput(output, "Orchestrator");
    const multiSigSigner = parseForgeOutput(output, "MultiSigSigner");
    const gardenSolver = parseForgeOutput(output, "GardenSolver");

    // Parse key hashes
    const signer1KeyHash = parseKeyHash(output, "Signer1 KeyHash");
    const signer2KeyHash = parseKeyHash(output, "Signer2 KeyHash");
    const signer3KeyHash = parseKeyHash(output, "Signer3 KeyHash");
    const multisigKeyHash = parseKeyHash(output, "Multisig KeyHash");

    console.log("✅ Deployment successful!");
    console.log(`   Orchestrator: ${orchestrator}`);
    console.log(`   MultiSigSigner: ${multiSigSigner}`);
    console.log(`   GardenSolver: ${gardenSolver}`);
    console.log("");

    return {
      chain: chain.name,
      orchestrator,
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
    if (error.stdout) {
      console.error("STDOUT:", error.stdout);
    }
    if (error.stderr) {
      console.error("STDERR:", error.stderr);
    }
    throw error;
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
      console.error(`   ${error.message || "Unknown error"}`);
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
      console.log(`    Orchestrator: ${deployment.orchestrator}`);
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
