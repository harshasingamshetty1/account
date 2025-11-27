#!/usr/bin/env tsx
import { existsSync } from "fs";
import path from "path";
import { readJson } from "./helpers";
import { Config, DeploymentResults } from "./types";
import { executeApproveTokens, executeGrantPermissions } from "./flows";

async function main() {
  const deployedPath = path.join(__dirname, "deployed.json");
  if (!existsSync(deployedPath)) {
    throw new Error("deployed.json is missing, run deploy.ts first.");
  }

  const deployments = readJson<DeploymentResults>("deployed.json");
  const config: Config = readJson<Config>("config.json");

  const chainNameArg = process.argv[2];
  const targetChains =
    chainNameArg && chainNameArg !== "all"
      ? [chainNameArg]
      : Object.keys(deployments.deployments);

  if (!targetChains.length) {
    throw new Error("No chains found in deployment data");
  }

  for (const chainName of targetChains) {
    const chain = config.chains.find((c) => c.name === chainName);
    const deployed = deployments.deployments[chainName];
    if (!chain || !deployed) {
      console.warn(`Skipping ${chainName}: missing config or deployment data.`);
      continue;
    }

    console.log(`\n>> Processing ${chainName}`);
    await executeApproveTokens(chain, deployed);
    await executeGrantPermissions(chain, deployed);
  }

  console.log("\nAll operations completed.");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
