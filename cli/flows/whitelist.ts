import { ChainConfig, DeployedContracts } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, executeWithSignature } from "./common";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";
import { executeChangeCooldown } from "./changeCooldown";

export interface WhitelistOptions {
  recipient: string;
}

export async function executeWhitelist(
  chain: ChainConfig,
  deployed: DeployedContracts,
  options: WhitelistOptions,
): Promise<void> {
  console.log(`[${chain.name}] Changing cooldown period to 10 seconds...`);
  await executeChangeCooldown(chain, deployed, { cooldownPeriod: "10" });

  console.log(`[${chain.name}] Whitelisting address...`);
  const scriptPath = SCRIPT_PATHS.whitelist;

  const baseEnv = buildBaseEnv(
    deployed,
    [], // No HTLCs needed for whitelisting
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
    {
      RECIPIENT_ADDRESS: options.recipient,
    },
  );

  const signature = await collectSignature({
    scriptPath,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.whitelist,
    label: "whitelist",
    signatureKey: "SIGNATURE",
    context: chain.name,
  });

  if (!signature) {
    throw new Error(`[${chain.name}] WhitelistDigest missing`);
  }

  executeWithSignature({
    scriptPath,
    rpc: chain.rpc,
    baseEnv,
    digestPattern: DIGEST_PATTERNS.whitelist,
    digestLabel: "whitelist",
    context: chain.name,
    successMessage: `Address whitelisted: ${options.recipient}`,
  });

  console.log(
    `[${chain.name}] Cooldown period is now 10 seconds. Wait 10 seconds before withdrawing.`,
  );
}
