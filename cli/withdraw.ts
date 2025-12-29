#!/usr/bin/env tsx
import {
  loadDeploymentData,
  sanitizeNumber,
  isNativeToken,
} from "./helpers/cli";
import { executeWithdraw, WithdrawOptions } from "./flows";

async function main() {
  const chainNameArg = process.argv[2];
  const recipientArg = process.argv[3];
  const amountArg = process.argv[4];
  const tokenArg = process.argv[5]; // Optional if not given native

  if (!chainNameArg || !recipientArg || !amountArg) {
    throw new Error(
      "Usage: withdraw.ts <chainName> <recipient> <amount> [tokenAddress]",
    );
  }

  const { chain, deployed } = loadDeploymentData(chainNameArg);
  const sanitizedAmount = sanitizeNumber(amountArg, "amount");

  const options: WithdrawOptions = {
    recipient: recipientArg,
    amount: sanitizedAmount,
    token: tokenArg, // if not provided then we will do native
  };

  console.log(`\n>> Withdrawing from ${chainNameArg}`);
  console.log(`   Recipient: ${options.recipient}`);
  console.log(`   Amount: ${options.amount}`);
  console.log(
    `   Token: ${isNativeToken(options.token) ? "native" : options.token}`,
  );

  await executeWithdraw(chain, deployed, options);

  console.log("\nWithdrawal completed successfully.");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
