import { ChainConfig, DeployedContracts } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, executeWithSignature } from "./common";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";

export interface ChangeCooldownOptions {
  cooldownPeriod: string; // in seconds
}

export async function executeChangeCooldown(
  chain: ChainConfig,
  deployed: DeployedContracts,
  options: ChangeCooldownOptions,
): Promise<void> {
  const scriptPath = SCRIPT_PATHS.changeCooldown;

  const baseEnv = buildBaseEnv(
    deployed,
    [],
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
    {
      COOLDOWN_PERIOD: options.cooldownPeriod,
    },
  );

  const signature = await collectSignature({
    scriptPath,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.cooldown,
    label: "cooldown",
    signatureKey: "SIGNATURE",
    context: chain.name,
  });

  if (!signature) {
    throw new Error(`[${chain.name}] CooldownDigest missing`);
  }

  executeWithSignature({
    scriptPath,
    rpc: chain.rpc,
    baseEnv,
    digestPattern: DIGEST_PATTERNS.cooldown,
    digestLabel: "cooldown",
    context: chain.name,
    successMessage: `Cooldown period changed to ${options.cooldownPeriod} seconds.`,
  });
}
