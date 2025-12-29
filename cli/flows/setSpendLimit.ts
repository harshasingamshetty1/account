import { ChainConfig, DeployedContracts } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, executeWithSignature } from "./common";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";
import { isNativeToken, NATIVE_TOKEN_ADDRESS } from "../helpers/cli";

export interface SetSpendLimitOptions {
  spendLimit: string; // in wei
  token?: string; // Token address (undefined or "0x0" for native)
}

export async function executeSetSpendLimit(
  chain: ChainConfig,
  deployed: DeployedContracts,
  options: SetSpendLimitOptions,
): Promise<void> {
  const scriptPath = SCRIPT_PATHS.setSpendLimit;
  const isNative = isNativeToken(options.token);
  const tokenAddress = isNative ? NATIVE_TOKEN_ADDRESS : options.token!;

  const baseEnv = buildBaseEnv(
    deployed,
    [], // No HTLCs needed for setting spend limit
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
    {
      SPEND_LIMIT: options.spendLimit,
      TOKEN_ADDRESS: tokenAddress,
    },
  );

  const signature = await collectSignature({
    scriptPath,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.setSpendLimit,
    label: "set spend limit",
    signatureKey: "SIGNATURE",
    context: chain.name,
  });

  if (!signature) {
    throw new Error(`[${chain.name}] SetSpendLimitDigest missing`);
  }

  executeWithSignature({
    scriptPath,
    rpc: chain.rpc,
    baseEnv,
    digestPattern: DIGEST_PATTERNS.setSpendLimit,
    digestLabel: "set spend limit",
    context: chain.name,
    successMessage: `Spend limit set to ${options.spendLimit} wei for ${isNative ? "native token" : `token ${tokenAddress}`}.`,
  });
}
