#!/usr/bin/env tsx

import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import {
  DEPLOYER_PRIVATE_KEY,
  SIGNER_ONE_ADDRESS,
  SIGNER_TWO_ADDRESS,
  SIGNER_TWO_PRIVATE_KEY,
  PERMISSION_ADDRESS,
} from "./config";

// Validate required env vars for execution
if (!DEPLOYER_PRIVATE_KEY) {
  throw new Error(
    "Missing required configuration for execution. Please set DEPLOYER_PRIVATE_KEY in .env file."
  );
}

if (!PERMISSION_ADDRESS) {
  throw new Error(
    "Missing required configuration for execution. Please set PERMISSION_ADDRESS in .env file."
  );
}

// SIGNER_ONE (hardware) and SIGNER_TWO (software) are required
const HARDWARE_SIGNER_ADDRESS =
  process.env.SIGNER_ADDRESS || SIGNER_ONE_ADDRESS;
if (!HARDWARE_SIGNER_ADDRESS) {
  throw new Error(
    "Missing required configuration. Please set SIGNER_ONE_ADDRESS (or SIGNER_ADDRESS) in .env file for hardware wallet signing."
  );
}

// if (!SIGNER_TWO_ADDRESS) {
//   throw new Error(
//     "Missing required configuration. Please set SIGNER_TWO_ADDRESS in .env file."
//   );
// }

// if (!SIGNER_TWO_PRIVATE_KEY) {
//   throw new Error(
//     "Missing required configuration. Please set SIGNER_TWO_PRIVATE_KEY in .env file."
//   );
// }

interface DeployedContracts {
  chain: string;
  multiSigSigner: string;
  gardenSolver: string;
  signer1Address: string;
  // signer2Address: string;
  // signer3Address: string;
  signer1KeyHash: string;
  // signer2KeyHash: string;
  // signer3KeyHash: string;
  multisigKeyHash: string;
  deployedAt: string;
}

interface ChainConfig {
  name: string;
  rpc: string;
  htlcs: string[]; // Non-native token HTLCs (require token approval)
  nativeHtlcs?: string[]; // Native token HTLCs (no token approval needed)
  fundAmount?: string; // Optional: ETH amount to fund GardenSolver
}

interface Config {
  chains: ChainConfig[];
}

async function executeApproveTokens(
  chain: ChainConfig,
  deployed: DeployedContracts
): Promise<void> {
  delete process.env.SIGNATURE;

  // Only approve tokens for non-native HTLCs
  if (!chain.htlcs || chain.htlcs.length === 0) {
    console.log("\n⏭️  Skipping token approval (no non-native HTLCs)\n");
    return;
  }

  console.log("\n========================================");
  console.log("Step 1: Approve Tokens to HTLC (Hardware Wallet)");
  console.log("========================================\n");

  const env = {
    ...process.env,
    GARDEN_SOLVER: deployed.gardenSolver,
    HTLC_ADDRESSES: chain.htlcs.join(","),
    SIGNER_ADDRESS: HARDWARE_SIGNER_ADDRESS,
    SIGNER_ONE_ADDRESS: HARDWARE_SIGNER_ADDRESS,
    // SIGNER_TWO_ADDRESS: SIGNER_TWO_ADDRESS,
    // SIGNER_TWO_PRIVATE_KEY: SIGNER_TWO_PRIVATE_KEY,
    MULTISIG_SIGNER: deployed.multiSigSigner,
    MULTISIG_KEY_HASH: deployed.multisigKeyHash,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  };

  const scriptPath = join(__dirname, "../script/main/ApproveHTLCToken.s.sol");

  // First run: get digest (no broadcast)
  let command = `forge script ${scriptPath} --rpc-url ${chain.rpc} -vvv`;

  console.log("Step 1a: Getting digest to sign...");
  let forgeOutput = "";
  try {
    forgeOutput = execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "pipe",
    }).toString();
    console.log(forgeOutput);
  } catch (error: any) {
    forgeOutput = error.stdout?.toString() || "";
    console.log(forgeOutput);
    // Continue even if there's an error - we just need the digest
  }

  // Extract digest from output
  const digestMatch = forgeOutput.match(
    /Digest to sign:\s+(0x[a-fA-F0-9]{64})/i
  );
  if (!digestMatch) {
    // If SIGNATURE is already set, skip signing and go straight to broadcast
    if (process.env.SIGNATURE) {
      console.log("SIGNATURE already set, proceeding to broadcast...\n");
    } else {
      console.log(
        "\n⚠️  Could not extract digest from output. Please check the logs above.\n"
      );
      return;
    }
  } else {
    const digest = digestMatch[1];
    console.log(`\n🔐 Signing digest with hardware wallet: ${digest}`);
    console.log("Please approve on your hardware wallet...\n");

    // Execute cast wallet sign --ledger
    try {
      const signCommand = `cast wallet sign --ledger ${digest}`;
      const signatureOutput = execSync(signCommand, {
        encoding: "utf-8",
        stdio: "pipe",
      })
        .toString()
        .trim();

      // Parse signature from output (cast outputs just the signature)
      const signature = signatureOutput.trim();
      if (!signature || !signature.startsWith("0x")) {
        throw new Error("Failed to get signature from cast command");
      }

      console.log(`✅ Signature obtained: ${signature.substring(0, 20)}...`);
      (env as any).SIGNATURE = signature;
      process.env.SIGNATURE = signature;
    } catch (error: any) {
      console.error("\n❌ Failed to sign with hardware wallet:", error.message);
      console.error("Make sure your Ledger is connected and unlocked.");
      throw error;
    }
  }

  // Second run: broadcast with signature
  command = `forge script ${scriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("\nStep 1b: Broadcasting transaction with signature...");
  try {
    execSync(command, {
      env,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log("\n[OK] Tokens approved successfully!\n");
    delete process.env.SIGNATURE;
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
  console.log("Step 2: Grant HTLC Permissions (Hardware Wallet)");
  console.log("========================================");
  console.log(`Granting permissions to: ${PERMISSION_ADDRESS}`);
  console.log("========================================\n");
  // Combine both htlcs and nativeHtlcs for permissions
  const allHtlcs = [...(chain.htlcs || []), ...(chain.nativeHtlcs || [])];

  if (allHtlcs.length === 0) {
    throw new Error(
      "No HTLC addresses found in config (neither htlcs nor nativeHtlcs)"
    );
  }

  delete process.env.SIGNATURE_AUTH;
  delete process.env.SIGNATURE_PERM;

  const baseEnv = {
    ...process.env,
    GARDEN_SOLVER: deployed.gardenSolver,
    HTLC_ADDRESSES: allHtlcs.join(","),
    PERMISSION_ADDRESS: PERMISSION_ADDRESS,
    SIGNER_ADDRESS: HARDWARE_SIGNER_ADDRESS,
    SIGNER_ONE_ADDRESS: HARDWARE_SIGNER_ADDRESS,
    // SIGNER_TWO_ADDRESS: SIGNER_TWO_ADDRESS,
    // SIGNER_TWO_PRIVATE_KEY: SIGNER_TWO_PRIVATE_KEY,
    MULTISIG_SIGNER: deployed.multiSigSigner,
    MULTISIG_KEY_HASH: deployed.multisigKeyHash,
    DEPLOYER_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  };

  const authScriptPath = join(
    __dirname,
    "../script/main/AuthorizeExecutor.s.sol"
  );
  const permScriptPath = join(
    __dirname,
    "../script/main/GrantHTLCPermissions.s.sol"
  );

  // Step 2a: Get authorization digest
  const env2a = { ...baseEnv };
  delete (env2a as any).SIGNATURE_AUTH;

  let command = `forge script ${authScriptPath} --rpc-url ${chain.rpc} -vvv`;

  console.log("Step 2a: Getting authorization digest to sign...");
  let forgeOutput = "";
  try {
    const result = execSync(command, {
      env: env2a,
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
    });
    forgeOutput = result.toString();
    console.log(forgeOutput);
  } catch (error: any) {
    forgeOutput =
      (error.stdout?.toString() || "") + (error.stderr?.toString() || "");
    console.log(forgeOutput);
  }

  // Extract authorization digest
  const authDigestMatch = forgeOutput.match(
    /AUTHORIZATION - SIGNING INFORMATION[\s\S]*?Digest to sign:\s+(0x[a-fA-F0-9]{64})/i
  );

  if (!authDigestMatch) {
    console.log(
      "\n⚠️  Could not extract authorization digest from output. Please check the logs above.\n"
    );
    // Debug: show a snippet of the output to help diagnose
    if (forgeOutput.length > 0) {
      const lines = forgeOutput.split("\n");
      const relevantLines = lines.filter(
        (line) =>
          line.toLowerCase().includes("digest") ||
          line.toLowerCase().includes("authorization") ||
          line.toLowerCase().includes("step 1")
      );
      if (relevantLines.length > 0) {
        console.log("Relevant output lines:");
        relevantLines.slice(0, 10).forEach((line) => console.log(`  ${line}`));
      }
    }
    return;
  }

  // Now we have the digest, sign it if not already signed
  if (!process.env.SIGNATURE_AUTH) {
    if (!authDigestMatch) {
      throw new Error("Authorization digest not found");
    }
    const authDigest = authDigestMatch[1];
    console.log(
      `\n🔐 Signing authorization digest with hardware wallet: ${authDigest}`
    );
    console.log("Please approve on your hardware wallet...\n");

    try {
      const signCommand = `cast wallet sign --ledger ${authDigest}`;
      const signatureOutput = execSync(signCommand, {
        encoding: "utf-8",
        stdio: "pipe",
      })
        .toString()
        .trim();

      const signature = signatureOutput.trim();
      if (!signature || !signature.startsWith("0x")) {
        throw new Error("Failed to get signature from cast command");
      }

      console.log(
        `✅ Authorization signature obtained: ${signature.substring(0, 20)}...`
      );
      process.env.SIGNATURE_AUTH = signature;
    } catch (error: any) {
      console.error("\n❌ Failed to sign with hardware wallet:", error.message);
      console.error("Make sure your Ledger is connected and unlocked.");
      throw error;
    }
  } else {
    console.log("SIGNATURE_AUTH already set, using existing signature...\n");
  }

  // Step 2b: Execute authorization (with broadcast)
  const env2b = { ...baseEnv };
  // Ensure SIGNATURE_AUTH is included from process.env
  if (process.env.SIGNATURE_AUTH) {
    (env2b as any).SIGNATURE_AUTH = process.env.SIGNATURE_AUTH;
  }
  command = `forge script ${authScriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("\nStep 2b: Executing authorization (broadcasting)...");
  try {
    execSync(command, {
      env: env2b,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log("\n[OK] Authorization executed successfully!\n");
    delete process.env.SIGNATURE_AUTH;
  } catch (error: any) {
    console.error("Authorization execution failed:", error.message);
    throw error;
  }

  // Step 2c: Get permissions digest (nonce is now updated after Step 2b)
  const env2c = { ...baseEnv };
  delete (env2c as any).SIGNATURE_PERM; // Clear this to ensure script prints permissions digest

  command = `forge script ${permScriptPath} --rpc-url ${chain.rpc} -vvv`;

  console.log("\nStep 2c: Getting permissions digest to sign...");
  forgeOutput = "";
  try {
    const result = execSync(command, {
      env: env2c,
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
    });
    forgeOutput = result.toString();
    console.log(forgeOutput);
  } catch (error: any) {
    forgeOutput =
      (error.stdout?.toString() || "") + (error.stderr?.toString() || "");
    console.log(forgeOutput);
  }

  // Extract permissions digest
  const permDigestMatch = forgeOutput.match(
    /PERMISSIONS - SIGNING INFORMATION[\s\S]*?Digest to sign:\s+(0x[a-fA-F0-9]{64})/i
  );

  if (!permDigestMatch) {
    console.log(
      "\n⚠️  Could not extract permissions digest from output. Please check the logs above.\n"
    );
    // Debug: show a snippet of the output to help diagnose
    if (forgeOutput.length > 0) {
      const lines = forgeOutput.split("\n");
      const relevantLines = lines.filter(
        (line) =>
          line.toLowerCase().includes("digest") ||
          line.toLowerCase().includes("permissions") ||
          line.toLowerCase().includes("step 2")
      );
      if (relevantLines.length > 0) {
        console.log("Relevant output lines:");
        relevantLines.slice(0, 10).forEach((line) => console.log(`  ${line}`));
      }
    }
    return;
  }

  // Now we have the digest, sign it if not already signed
  if (!process.env.SIGNATURE_PERM) {
    if (!permDigestMatch) {
      throw new Error("Permissions digest not found");
    }
    const permDigest = permDigestMatch[1];
    console.log(
      `\n🔐 Signing permissions digest with hardware wallet: ${permDigest}`
    );
    console.log("Please approve on your hardware wallet...\n");

    try {
      const signCommand = `cast wallet sign --ledger ${permDigest}`;
      const signatureOutput = execSync(signCommand, {
        encoding: "utf-8",
        stdio: "pipe",
      })
        .toString()
        .trim();

      const signature = signatureOutput.trim();
      if (!signature || !signature.startsWith("0x")) {
        throw new Error("Failed to get signature from cast command");
      }

      console.log(
        `✅ Permissions signature obtained: ${signature.substring(0, 20)}...`
      );
      process.env.SIGNATURE_PERM = signature;
    } catch (error: any) {
      console.error("\n❌ Failed to sign with hardware wallet:", error.message);
      console.error("Make sure your Ledger is connected and unlocked.");
      throw error;
    }
  } else {
    console.log("SIGNATURE_PERM already set, using existing signature...\n");
  }

  // Step 2d: Final broadcast with permissions signature
  const env2d = { ...baseEnv };
  // Ensure SIGNATURE_PERM is included from process.env
  if (process.env.SIGNATURE_PERM) {
    (env2d as any).SIGNATURE_PERM = process.env.SIGNATURE_PERM;
  }

  command = `forge script ${permScriptPath} --rpc-url ${chain.rpc} --broadcast -vvv`;

  console.log("\nStep 2d: Broadcasting permissions grant...");
  try {
    execSync(command, {
      env: env2d,
      encoding: "utf-8",
      stdio: "inherit",
    });
    console.log(
      "\n[OK] Authorize executor and grant permissions successfully!\n"
    );
    delete process.env.SIGNATURE_PERM;
  } catch (error: any) {
    console.error(
      "Authorize executor and grant permissions failed:",
      error.message
    );
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
    SIGNER_ADDRESS: HARDWARE_SIGNER_ADDRESS,
    SIGNER_ONE_ADDRESS: HARDWARE_SIGNER_ADDRESS,
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
      const allHtlcs = [...(chain.htlcs || []), ...(chain.nativeHtlcs || [])];
      console.log(`HTLC Addresses: ${allHtlcs.join(", ")}`);
      if (chain.nativeHtlcs && chain.nativeHtlcs.length > 0) {
        console.log(`Native HTLC Addresses: ${chain.nativeHtlcs.join(", ")}`);
      }

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
  const allHtlcs = [...(chain.htlcs || []), ...(chain.nativeHtlcs || [])];
  console.log(`HTLC Addresses: ${allHtlcs.join(", ")}`);
  if (chain.nativeHtlcs && chain.nativeHtlcs.length > 0) {
    console.log(`Native HTLC Addresses: ${chain.nativeHtlcs.join(", ")}`);
  }
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
  if (chain.htlcs && chain.htlcs.length > 0) {
    console.log("✓ Tokens approved to non-native HTLC contracts");
  }
  if (chain.nativeHtlcs && chain.nativeHtlcs.length > 0) {
    console.log("✓ Native HTLCs configured (no token approval needed)");
  }
  console.log(`✓ HTLC permissions granted to ${PERMISSION_ADDRESS}`);

  console.log("========================================\n");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
