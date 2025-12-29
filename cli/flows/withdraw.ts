import { ChainConfig, DeployedContracts } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, executeWithSignature } from "./common";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";
import { executeChangeCooldown } from "./changeCooldown";
import { isNativeToken, NATIVE_TOKEN_ADDRESS } from "../helpers/cli";

export interface WithdrawOptions {
  token?: string; // Token address (undefined or "0x0" for native)
  recipient: string;
  amount: string;
}

export async function executeWithdraw(
  chain: ChainConfig,
  deployed: DeployedContracts,
  options: WithdrawOptions,
): Promise<void> {
  const isNative = isNativeToken(options.token);
  const scriptPath = isNative
    ? SCRIPT_PATHS.withdrawNative
    : SCRIPT_PATHS.withdraw;

  const baseEnv = buildBaseEnv(
    deployed,
    [], // No HTLCs needed for withdrawal
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
    {
      TOKEN_ADDRESS: isNative ? NATIVE_TOKEN_ADDRESS : options.token,
      RECIPIENT_ADDRESS: options.recipient,
      AMOUNT: options.amount,
    },
  );

  const signature = await collectSignature({
    scriptPath,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.withdrawal,
    label: "withdrawal",
    signatureKey: "SIGNATURE",
    context: chain.name,
  });

  if (!signature) {
    throw new Error(`[${chain.name}] WithdrawDigest missing`);
  }

  executeWithSignature({
    scriptPath,
    rpc: chain.rpc,
    baseEnv,
    digestPattern: DIGEST_PATTERNS.withdrawal,
    digestLabel: "withdrawal",
    context: chain.name,
    successMessage: `Withdrawal ${isNative ? "(native)" : "(token)"} broadcast successfully.`,
  });

  console.log(
    `[${chain.name}] Resetting cooldown period to 1 day (86400 seconds)...`,
  );
  await executeChangeCooldown(chain, deployed, { cooldownPeriod: "86400" });
  console.log(`[${chain.name}] Cooldown period reset to 1 day.`);
}
