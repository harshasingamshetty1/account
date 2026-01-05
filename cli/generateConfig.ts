#!/usr/bin/env tsx
import { readJson, writeJson } from "./helpers/file";
import { fetchGardenChains, groupHTLCsByChain } from "./api";
import { Config, ChainConfig } from "./types";

interface BaseConfig {
  apiUrl: string;
  rpcMapping: Record<string, string>; // chain name -> RPC URL
  defaults: {
    fundAmount?: string;
    nativeSpendLimit: string;
    whitelistAddress: string;
  };
}

async function main() {
  console.log("Loading base configuration...");

  const baseConfig: BaseConfig = readJson<BaseConfig>("config.staging.json");
  const chainsData = await fetchGardenChains(baseConfig.apiUrl);

  if (chainsData.length === 0) {
    throw new Error("No chain data returned from API");
  }

  const groupedData = groupHTLCsByChain(chainsData);

  const chains: ChainConfig[] = [];
  const missingRpc: string[] = [];

  for (const chainData of groupedData) {
    const rpc = baseConfig.rpcMapping[chainData.baseChainName] || "";

    if (!rpc) {
      missingRpc.push(chainData.baseChainName);
      console.warn(
        `⚠️  No RPC URL found for ${chainData.baseChainName}, leaving RPC field empty`,
      );
    }

    chains.push({
      name: chainData.baseChainName,
      rpc: rpc,
      htlcs: chainData.htlcs,
      nativeHtlcs: chainData.nativeHtlcs,
      fundAmount: baseConfig.defaults.fundAmount,
      nativeSpendLimit: baseConfig.defaults.nativeSpendLimit,
    });
  }

  const config: Config = {
    chains,
    whitelistAddress: baseConfig.defaults.whitelistAddress,
  };
  chains.forEach((chain) => {
    console.log(
      `  - ${chain.name}: ${chain.htlcs?.length || 0} ERC20 HTLCs, ${chain.nativeHtlcs?.length || 0} native HTLCs`,
    );
  });

  if (missingRpc.length > 0) {
    console.log(
      `\n⚠️  ${missingRpc.length} chains have empty RPC (not found in mapping):`,
    );
    missingRpc.forEach((name) => console.log(`  - ${name}`));
  }

  writeJson("config.json", config);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
