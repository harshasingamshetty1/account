export interface ChainConfig {
  name: string;
  rpc: string;
  htlcs?: string[];
  nativeHtlcs?: string[];
  fundAmount?: string;
  nativeSpendLimit: string;
}

export interface Config {
  chains: ChainConfig[];
  whitelistAddress: string;
}

export interface DeployedContracts {
  chain: string;
  multiSigSigner: string;
  gardenSolver: string;
  signer1Address: string;
  signer1KeyHash: string;
  multisigKeyHash: string;
  deployedAt: string;
}

export interface DeploymentSummary {
  total: number;
  successful: number;
  failed: number;
  deployedAt: string;
}

export interface DeploymentResults {
  deployments: Record<string, DeployedContracts>;
  summary: DeploymentSummary;
}
