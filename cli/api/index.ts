import { ApiResponse, HTLCData, GroupedHTLCData } from "./types";

/**
 * Check if chain ID is supported (EVM only)
 */
function isSupportedChain(chainId: string): boolean {
  return chainId.startsWith("evm:");
}

/**
 * Fetches chain data from Garden Finance API
 * Only includes EVM chains
 */
export async function fetchGardenChains(apiUrl: string): Promise<HTLCData[]> {
  const response = await fetch(apiUrl);

  if (!response.ok) {
    throw new Error(
      `API request failed: ${response.status} ${response.statusText}`,
    );
  }

  const data = (await response.json()) as ApiResponse;

  if (data.status !== "Ok") {
    throw new Error(`API returned error status: ${data.status}`);
  }

  const result: HTLCData[] = [];

  for (const chain of data.result) {
    // Skip unsupported chains
    if (!isSupportedChain(chain.id)) {
      console.log(`Skipping unsupported chain: ${chain.chain} (${chain.id})`);
      continue;
    }

    for (const asset of chain.assets) {
      if (!asset.htlc) continue;

      const htlcs: string[] = [];
      const nativeHtlcs: string[] = [];

      if (asset.token === null) {
        nativeHtlcs.push(asset.htlc.address);
      } else {
        htlcs.push(asset.htlc.address);
      }

      if (htlcs.length > 0 || nativeHtlcs.length > 0) {
        result.push({
          chainName: asset.id, // e.g., "arbitrum_sepolia:ibtc"
          baseChainName: chain.chain, // e.g., "arbitrum_sepolia"
          htlcs,
          nativeHtlcs,
        });
      }
    }
  }

  return result;
}

/**
 * Groups HTLC data by base chain name, combining all HTLCs for each chain
 */
export function groupHTLCsByChain(chainsData: HTLCData[]): GroupedHTLCData[] {
  const grouped = new Map<string, GroupedHTLCData>();

  for (const chainData of chainsData) {
    const existing = grouped.get(chainData.baseChainName);

    if (existing) {
      for (const htlc of chainData.htlcs) {
        if (!existing.htlcs.includes(htlc)) {
          existing.htlcs.push(htlc);
        }
      }

      for (const nativeHtlc of chainData.nativeHtlcs) {
        if (!existing.nativeHtlcs.includes(nativeHtlc)) {
          existing.nativeHtlcs.push(nativeHtlc);
        }
      }
    } else {
      grouped.set(chainData.baseChainName, {
        baseChainName: chainData.baseChainName,
        htlcs: [...chainData.htlcs],
        nativeHtlcs: [...chainData.nativeHtlcs],
      });
    }
  }

  return Array.from(grouped.values());
}
