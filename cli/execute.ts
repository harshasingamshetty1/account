#!/usr/bin/env tsx

import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import {
  DEPLOYER_PRIVATE_KEY,
  SIGNER_ONE_PRIVATE_KEY,
  SIGNER_TWO_PRIVATE_KEY,
  PERMISSION_ADDRESS,
} from "./config";

// Validate required env vars for execution
if (
  !DEPLOYER_PRIVATE_KEY ||
  !SIGNER_ONE_PRIVATE_KEY ||
  !SIGNER_TWO_PRIVATE_KEY ||
  !PERMISSION_ADDRESS
) {
  throw new Error(
    "Missing required configuration for execution. Please set DEPLOYER_PRIVATE_KEY, SIGNER_ONE_PRIVATE_KEY, SIGNER_TWO_PRIVATE_KEY, and PERMISSION_ADDRESS in .env file."
  );
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

interface ChainConfig {
  name: string;
  rpc: string;
  htlcs: string[];
  fundAmount?: string; // Optional: ETH amount to fund GardenSolver
}

interface Config {
  chains: ChainConfig[];
}

async function executeApproveTokens(
  chain: ChainConfig,
  deployed: DeployedContracts
): Promise<void> {
  console.log("\n========================================");
  console.log("Step 1: Approve Tokens to HTLC (Multisig)");
  console.log("========================================\n");

  const env = {
    ...process.env,
    GARDEN_SOLVER: deployed.gardenSolver,
    MULTISIG_SIGNER: deployed.multiSigSigner,
    HTLC_ADDRESSES: chain.htlcs.join(","),
    SIGNER1_PRIVATE_KEY: SIGNER_ONE_PRIVATE_KEY,
    SIGNER2_PRIVATE_KEY: SIGNER_TWO_PRIVATE_KEY,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  };

  const scriptPath = join(__dirname, "../script/main/ApproveHTLCToken.s.sol");
  const command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("Executing token approval...");
  try {
    execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log("\n[OK] Tokens approved successfully!\n");
  } catch (error: any) {
    console.error("Token approval failed:", error.message);
    throw error;
  }
}

async function executeGrantPermissions(
  chain: ChainConfig,
  deployed: DeployedContracts
): Promise<void> {
  console.log("\n========================================");
  console.log("Step 2: Grant HTLC Permissions (Multisig)");
  console.log("========================================");
  console.log(`Granting permissions to: ${PERMISSION_ADDRESS}`);
  console.log("========================================\n");

  const env = {
    ...process.env,
    GARDEN_SOLVER: deployed.gardenSolver,
    MULTISIG_SIGNER: deployed.multiSigSigner,
    HTLC_ADDRESSES: chain.htlcs.join(","),
    SIGNER_ADDRESS: PERMISSION_ADDRESS,
    SIGNER1_PRIVATE_KEY: SIGNER_ONE_PRIVATE_KEY,
    SIGNER2_PRIVATE_KEY: SIGNER_TWO_PRIVATE_KEY,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  };

  const scriptPath = join(
    __dirname,
    "../script/main/GrantHTLCPermissions.s.sol"
  );
  const command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("Executing permission grant...");
  try {
    execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log("\n[OK] Permissions granted successfully!\n");
  } catch (error: any) {
    console.error("Permission grant failed:", error.message);
    throw error;
  }
}

// test function
async function executeInitiateHTLC(
  chain: ChainConfig,
  deployed: DeployedContracts,
  redeemerAddress: string,
  timelock: number,
  amount: string,
  secretHash: string
): Promise<void> {
  console.log("\n========================================");
  console.log("Step 3: Initiate HTLC Order");
  console.log("========================================\n");

  const env = {
    ...process.env,
    GARDEN_SOLVER: deployed.gardenSolver,
    HTLC_ADDRESS: chain.htlcs[0], // Use first HTLC
    REDEEMER_ADDRESS: redeemerAddress,
    TIMELOCK: timelock.toString(),
    AMOUNT: amount,
    SECRET_HASH: secretHash,
    SIGNER_PRIVATE_KEY: SIGNER_ONE_PRIVATE_KEY,
  };

  const scriptPath = join(__dirname, "../script/main/InitiateHTLC.s.sol");
  const command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("Executing HTLC initiation...");
  try {
    execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log("\n[OK] HTLC order initiated successfully!\n");
  } catch (error: any) {
    console.error("HTLC initiation failed:", error.message);
    throw error;
  }
}

async function main() {
  const deployedPath = join(__dirname, "deployed.json");
  if (!existsSync(deployedPath)) {
    throw new Error(
      "deployed.json not found. Please run deploy.ts first to deploy contracts."
    );
  }

  // Load deployed contracts (new structure with deployments object)
  const deploymentResults: {
    deployments: Record<string, DeployedContracts>;
    summary: any;
  } = JSON.parse(readFileSync(deployedPath, "utf-8"));

  // Load config
  const configPath = join(__dirname, "config.json");
  const config: Config = JSON.parse(readFileSync(configPath, "utf-8"));

  // only specific chain granting else all
  const chainNameArg = process.argv[2];
  const processAllChains = chainNameArg === "all" || !chainNameArg;

  if (processAllChains) {
    // Process all deployed chains
    const deployedChains = Object.keys(deploymentResults.deployments);
    if (deployedChains.length === 0) {
      throw new Error("No deployed chains found in deployed.json");
    }

    console.log("\n========================================");
    console.log("Executing Multisig Operations for ALL Chains");
    console.log("========================================");
    console.log(`Permission Address: ${PERMISSION_ADDRESS}`);
    console.log(`Total chains: ${deployedChains.length}`);
    console.log("========================================\n");

    for (let i = 0; i < deployedChains.length; i++) {
      const chainName = deployedChains[i];
      const deployed = deploymentResults.deployments[chainName];
      const chain = config.chains.find((c) => c.name === chainName);

      if (!chain) {
        console.warn(
          `⚠️  Chain ${chainName} not found in config.json, skipping...`
        );
        continue;
      }

      console.log(
        `\n[${i + 1}/${deployedChains.length}] Processing chain: ${chainName}`
      );
      console.log(`GardenSolver: ${deployed.gardenSolver}`);
      console.log(`HTLC Addresses: ${chain.htlcs.join(", ")}`);

      try {
        await executeApproveTokens(chain, deployed);
        await executeGrantPermissions(chain, deployed);
        console.log(`✅ Successfully processed ${chainName}\n`);
      } catch (error: any) {
        console.error(`❌ Failed to process ${chainName}: ${error.message}\n`);
        // Continue with next chain
      }
    }

    console.log("\n========================================");
    console.log("All Chains Processing Completed!");
    console.log("========================================\n");
    return;
  }

  // Process single chain
  const chainName = chainNameArg;
  const deployed = deploymentResults.deployments[chainName];
  if (!deployed) {
    throw new Error(
      `Chain ${chainName} not found in deployed.json. Available chains: ${Object.keys(
        deploymentResults.deployments
      ).join(", ")}`
    );
  }

  // Find matching chain in config
  const chain = config.chains.find((c) => c.name === chainName);
  if (!chain) {
    throw new Error(`Chain ${chainName} not found in config.json`);
  }

  console.log("\n========================================");
  console.log("Executing Multisig Operations");
  console.log("========================================");
  console.log(`Chain: ${chain.name}`);
  console.log(`GardenSolver: ${deployed.gardenSolver}`);
  console.log(`Permission Address: ${PERMISSION_ADDRESS}`);
  console.log(`HTLC Addresses: ${chain.htlcs.join(", ")}`);
  console.log("========================================\n");

  await executeApproveTokens(chain, deployed);
  await executeGrantPermissions(chain, deployed);

  // Step 3: Initiate HTLC (testing)
  /*
  const redeemerAddress = "0x9596ce01462aa3b46ae5aa8a0d550095de10fcfa"; // Address that can redeem the HTLC
  const timelock = 1000000; // Block number timelock
  const amount = "500"; // wbtc tested in testnet sepolia w/ decimals 8
  const secretHash =
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // keccak256 hash of the secret

  await executeInitiateHTLC(
    chain,
    deployed,
    redeemerAddress,
    timelock,
    amount,
    secretHash
  );
   */

  console.log("\n========================================");
  console.log("All Operations Completed Successfully!");
  console.log("========================================");
  console.log("✓ Tokens approved to HTLC contracts");
  console.log(`✓ HTLC permissions granted to ${PERMISSION_ADDRESS}`);
  console.log("========================================\n");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
