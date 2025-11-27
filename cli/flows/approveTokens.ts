import { runForgeScript } from "../helpers";
import { ChainConfig, DeployedContracts } from "../types";
import { DIGEST_PATTERNS, SCRIPT_PATHS } from "../config/constants";
import { buildBaseEnv, collectSignature, createEnv } from "./common";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";

export async function executeApproveTokens(
  chain: ChainConfig,
  deployed: DeployedContracts,
): Promise<void> {
  if (!chain.htlcs?.length) {
    console.log(`[${chain.name}] No approvals needed (no non-native HTLCs).`);
    return;
  }

  const baseEnv = buildBaseEnv(
    deployed,
    chain.htlcs,
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
  );

  const signature = await collectSignature({
    scriptPath: SCRIPT_PATHS.approve,
    rpc: chain.rpc,
    envOverrides: baseEnv,
    digestPattern: DIGEST_PATTERNS.approval,
    label: "approval",
    signatureKey: "SIGNATURE",
    context: chain.name,
  });

  if (!signature) {
    throw new Error(`[${chain.name}] approval digest missing`);
  }

  runForgeScript({
    scriptPath: SCRIPT_PATHS.approve,
    rpc: chain.rpc,
    env: createEnv({ ...baseEnv, SIGNATURE: signature }),
    broadcast: true,
  });

  delete process.env.SIGNATURE;
  console.log(`[${chain.name}] Token approvals broadcast.`);
}
