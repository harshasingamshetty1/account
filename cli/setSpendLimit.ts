#!/usr/bin/env tsx
import {
  loadDeploymentData,
  sanitizeNumber,
  isNativeToken,
} from "./helpers/cli";
import { executeSetSpendLimit, SetSpendLimitOptions } from "./flows";

async function main() {
  const chainNameArg = process.argv[2];
  const spendLimitArg = process.argv[3];
  const tokenArg = process.argv[4]; // Optional if not given native

  if (!chainNameArg || !spendLimitArg) {
    throw new Error(
      "Usage: setSpendLimit.ts <chainName> <spendLimitInWei> [tokenAddress]",
    );
  }

  const { chain, deployed } = loadDeploymentData(chainNameArg);
  const sanitizedSpendLimit = sanitizeNumber(spendLimitArg, "spend limit");

  const options: SetSpendLimitOptions = {
    spendLimit: sanitizedSpendLimit,
    token: tokenArg, // undefined if not provided (defaults to native)
  };

  console.log(`\n>> Setting spend limit on ${chainNameArg}`);
  console.log(`   Spend Limit: ${options.spendLimit} wei`);
  console.log(
    `   Token: ${isNativeToken(options.token) ? "native" : options.token}`,
  );

  await executeSetSpendLimit(chain, deployed, options);

  console.log("\nSpend limit set successfully.");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
