export interface ApiChain {
  chain: string;
  id: string; // e.g., "evm:421614", "starknet:...", "tron:...", etc.
  assets: Array<{
    id: string;
    htlc: { address: string; schema: string } | null;
    token: { address: string; schema: string } | null;
  }>;
}

export interface ApiResponse {
  status: string;
  result: ApiChain[];
}

export interface HTLCData {
  chainName: string; // e.g., "arbitrum_sepolia:ibtc"
  baseChainName: string; // e.g., "arbitrum_sepolia"
  htlcs: string[]; // ERC20 HTLC addresses (has token)
  nativeHtlcs: string[]; // Native HTLC addresses (no token)
}

export interface GroupedHTLCData {
  baseChainName: string; // e.g., "arbitrum_sepolia"
  htlcs: string[]; // All ERC20 HTLC addresses for this chain
  nativeHtlcs: string[]; // All native HTLC addresses for this chain
}
