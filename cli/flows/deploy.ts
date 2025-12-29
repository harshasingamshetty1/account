import { ethers } from "ethers";
import {
  runForgeScript,
  getChainId,
  parseBroadcastArtifacts,
  parseKeyHash,
} from "../helpers";
import { ChainConfig, DeployedContracts } from "../types";
import { SCRIPT_PATHS } from "../config/constants";
import { DEPLOYER_PRIVATE_KEY, SIGNER_ONE_ADDRESS } from "../config/config";

export async function deployContracts(
  chain: ChainConfig,
): Promise<DeployedContracts> {
  console.log(`[${chain.name}] Deploying...`);

  if (!chain.fundAmount) {
    throw new Error(`Chain ${chain.name} is missing fundAmount`);
  }
  const fundAmountWei = ethers.parseEther(chain.fundAmount).toString();
  const env = buildDeployEnv(
    fundAmountWei,
    SIGNER_ONE_ADDRESS,
    DEPLOYER_PRIVATE_KEY,
  );

  const output = runForgeScript({
    scriptPath: SCRIPT_PATHS.deploy,
    rpc: chain.rpc,
    env,
    broadcast: true,
  });

  const chainId = await getChainId(chain.rpc);
  const scriptName = "DeployContracts.s.sol";
  const { multiSigSigner, gardenSolver } = parseBroadcastArtifacts(
    chainId,
    scriptName,
  );

  const signer1KeyHash = parseKeyHash(output, "Signer1 KeyHash");
  const multisigKeyHash = parseKeyHash(output, "Multisig KeyHash");

  return {
    chain: chain.name,
    multiSigSigner,
    gardenSolver,
    signer1Address: SIGNER_ONE_ADDRESS,
    signer1KeyHash,
    multisigKeyHash,
    deployedAt: new Date().toISOString(),
  };
}

function buildDeployEnv(
  fundAmountWei: string,
  signer1Address: string,
  deployerPrivateKey: string,
): NodeJS.ProcessEnv {
  return {
    ...process.env,
    DEPLOYER_PRIVATE_KEY: deployerPrivateKey,
    SIGNER_ONE_ADDRESS: signer1Address,
    FUND_AMOUNT_WEI: fundAmountWei,
    MULTISIG_THRESHOLD: "1",
  };
}
