#!/usr/bin/env tsx
import { loadDeploymentData } from "./helpers/cli";
import { executeWhitelist, WhitelistOptions } from "./flows";

async function main() {
  const chainNameArg = process.argv[2];
  const recipientArg = process.argv[3];

  if (!chainNameArg || !recipientArg) {
    throw new Error("Usage: whitelist.ts <chainName> <recipient>");
  }

  const { chain, deployed } = loadDeploymentData(chainNameArg);

  const options: WhitelistOptions = {
    recipient: recipientArg,
  };

  console.log(`\n>> Whitelisting address on ${chainNameArg}`);
  console.log(`   Recipient: ${options.recipient}`);

  await executeWhitelist(chain, deployed, options);

  console.log("\nWhitelisting completed successfully.");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
