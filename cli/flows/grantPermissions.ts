import { runForgeScript } from "../helpers";
import { DeployedContracts, ChainConfig } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, createEnv } from "../flows";
import {
  DEPLOYER_PRIVATE_KEY,
  PERMISSION_ADDRESS,
  SIGNER_ONE_ADDRESS,
  //   SIGNER_TWO_PRIVATE_KEY,
} from "../config/config";

export async function executeGrantPermissions(
  chain: ChainConfig,
  deployed: DeployedContracts,
): Promise<void> {
  const allHtlcs = [...(chain.htlcs || []), ...(chain.nativeHtlcs || [])];
  if (!allHtlcs.length) {
    throw new Error(`[${chain.name}] No HTLCs configured`);
  }

  const nativeAmount = chain.nativeSpendLimit;
  if (!nativeAmount) {
    throw new Error(`[${chain.name}] nativeSpendLimit not configured`);
  }
  const baseEnv = buildBaseEnv(
    deployed,
    allHtlcs,
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
    {
      PERMISSION_ADDRESS,
      //   SIGNER_TWO_PRIVATE_KEY,
      NATIVE_AMOUNT: nativeAmount,
    },
  );

  const authSignature = await collectSignature({
    scriptPath: SCRIPT_PATHS.authorize,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.authorization,
    label: "authorization",
    signatureKey: "SIGNATURE_AUTH",
    context: chain.name,
  });

  if (!authSignature) {
    throw new Error(`[${chain.name}] authorization digest missing`);
  }

  runForgeScript({
    scriptPath: SCRIPT_PATHS.authorize,
    rpc: chain.rpc,
    env: createEnv({ ...baseEnv, SIGNATURE_AUTH: authSignature }),
    broadcast: true,
  });

  delete process.env.SIGNATURE_AUTH;
  console.log(`[${chain.name}] Authorization executed.`);

  const permSignature = await collectSignature({
    scriptPath: SCRIPT_PATHS.permissions,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.permissions,
    label: "permissions",
    signatureKey: "SIGNATURE_PERM",
    context: chain.name,
  });

  if (!permSignature) {
    throw new Error(`[${chain.name}] permissions digest missing`);
  }

  runForgeScript({
    scriptPath: SCRIPT_PATHS.permissions,
    rpc: chain.rpc,
    env: createEnv({ ...baseEnv, SIGNATURE_PERM: permSignature }),
    broadcast: true,
  });

  delete process.env.SIGNATURE_PERM;
  console.log(`[${chain.name}] Permissions granted.`);
}
