import { readFileSync, existsSync } from "fs";
import { join } from "path";

export async function getChainId(rpcUrl: string): Promise<number> {
  const { ethers } = await import("ethers");
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  return Number(network.chainId);
}

export function parseBroadcastArtifacts(
  chainId: number,
  scriptName: string,
): { multiSigSigner: string; gardenSolver: string } {
  const broadcastPath = join(
    __dirname,
    `../../broadcast/${scriptName}/${chainId}/run-latest.json`,
  );

  if (!existsSync(broadcastPath)) {
    throw new Error(
      `Broadcast artifact not found: ${broadcastPath}. Make sure the deployment completed.`,
    );
  }

  const broadcast = JSON.parse(readFileSync(broadcastPath, "utf-8"));
  const contracts: Record<string, string> = {};

  for (const tx of broadcast.transactions || []) {
    if (tx.transactionType === "CREATE" && tx.contractName) {
      contracts[tx.contractName] = tx.contractAddress;
    }
  }

  for (const receipt of broadcast.receipts || []) {
    if (receipt.contractAddress) {
      const match = broadcast.transactions?.find(
        (tx: any) => tx.hash === receipt.transactionHash,
      );
      if (match?.contractName) {
        contracts[match.contractName] = receipt.contractAddress;
      }
    }
  }

  const multiSigSigner = contracts["MultiSigSigner"];
  const gardenSolver = contracts["GardenSolver"];

  if (!multiSigSigner || !gardenSolver) {
    throw new Error(
      `Missing contract addresses in broadcast artifacts for ${scriptName}`,
    );
  }

  return { multiSigSigner, gardenSolver };
}

export function parseKeyHash(output: string, keyName: string): string {
  const patterns = [
    new RegExp(`${keyName}.*?KeyHash.*?:\\s+(0x[a-fA-F0-9]{64})`, "i"),
    new RegExp(`${keyName}.*?:\\s+(0x[a-fA-F0-9]{64})`, "i"),
  ];

  for (const pattern of patterns) {
    const match = output.match(pattern);
    if (match?.[1]) {
      return match[1];
    }
  }

  const lines = output.split("\n");
  for (const line of lines) {
    if (line.toLowerCase().includes(keyName.toLowerCase())) {
      const match = line.match(/(0x[a-fA-F0-9]{64})/);
      if (match) {
        return match[1];
      }
    }
  }

  throw new Error(`Could not find ${keyName} key hash in forge output`);
}
