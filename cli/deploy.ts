#!/usr/bin/env tsx
import { readJson, writeJson } from "./helpers/file";
import { Config, DeploymentResults } from "./types";
import { deployContracts, executeWhitelist } from "./flows";

async function main() {
  const config: Config = readJson<Config>("config.json");
  if (!config.chains.length) {
    throw new Error("No chains configured in config.json");
  }

  if (!config.whitelistAddress) {
    throw new Error("whitelistAddress is required in config.json");
  }

  const results: DeploymentResults = {
    deployments: {},
    summary: {
      total: config.chains.length,
      successful: 0,
      failed: 0,
      deployedAt: new Date().toISOString(),
    },
  };

  for (const chain of config.chains) {
    try {
      const deployed = await deployContracts(chain);
      results.deployments[chain.name] = deployed;
      results.summary.successful++;

      // Whitelist address after deployment
      console.log(`[${chain.name}] Whitelisting address after deployment...`);
      await executeWhitelist(chain, deployed, {
        recipient: config.whitelistAddress,
      });
    } catch (error: any) {
      console.error(`Failed to deploy ${chain.name}: ${error.message}`);
      results.summary.failed++;
    }
  }

  writeJson("deployed.json", results);
  console.log("Deployment data saved to deployed.json");
  if (results.summary.failed > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
