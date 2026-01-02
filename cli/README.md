# CLI Docs

## Requirements

Install `tsx` globally:

```bash
npm install -g tsx
```

## Setup

### 1. Configure Environment

Read `env.example` and create your `.env` file:

```bash
DEPLOYER_PRIVATE_KEY=0x...
SIGNER_ONE_ADDRESS=0x...
PERMISSION_ADDRESS=0x...
SIGNER_TYPE=hardware or eoa
SIGNER_PRIVATE_KEY=0x (optional if not eoa)
```

**Signer Configuration:**

- **EOA**: Set `SIGNER_TYPE=eoa` and `SIGNER_PRIVATE_KEY=0x...` (requires private key)
- **Hardware**: Set `SIGNER_TYPE=hardware` or leave unset (uses Ledger, no private key needed)

**⚠️ Important:** `SIGNER_PRIVATE_KEY` must be the private key for `SIGNER_ONE_ADDRESS`, NOT `PERMISSION_ADDRESS`. Using the wrong private key will cause signature verification failures.

### 2. Update RPC URLs

Edit `config.staging.json` and update the `rpcMapping`,`api_url` with your RPC URLs:

```json
{
    "apiUrl": "https://testnet.api.garden.finance/v2/chains",
  "rpcMapping": {
    "arbitrum_sepolia": "https://your-rpc-url",
    "base_sepolia": "https://your-rpc-url",
    ...
  }
  other defaults for how much you want to prefund and set limits for the native token
  ...
}
```

### 3. Generate Config

Generate `config.json` from the API:

```bash
tsx generateConfig.ts
```

## Commands

**Note:** All amounts are in wei.

```yaml
# Deploy contracts to all chains
tsx deploy.ts

# will approvals,authorize and grants permissions to htlcs handles both native and non native automatically
tsx execute.ts (broken into parts in the flows)

# Withdraw (native if no tokenAddress, ERC20 if tokenAddress provided need the recipient to be whitelisted first to withdraw to that recipient)
tsx withdraw.ts <chainName> <recipient> <amountInWei> [tokenAddress]

# Whitelist address
tsx whitelist.ts <chainName> <recipient>

# Set spend limit (native if no tokenAddress, ERC20 if tokenAddress provided)
tsx setSpendLimit.ts <chainName> <spendLimitInWei> [tokenAddress]
```

**Examples:**

```yaml
tsx withdraw.ts arbitrum_sepolia 0xRecipient 1000000000000000
tsx withdraw.ts arbitrum_sepolia 0xRecipient 100000000 0xTokenAddress
tsx whitelist.ts arbitrum_sepolia 0xRecipient
tsx setSpendLimit.ts arbitrum_sepolia 1000000000000000000
```

## Important Notes

- **Chain names** must match the names in `deployed.json` or `config.json`
- **SIGNER_PRIVATE_KEY** must correspond to `SIGNER_ONE_ADDRESS`, NOT `PERMISSION_ADDRESS`
- All flow implementations are in the `flows/` directory
- Chain name format:  `arbitrum_sepolia`, `base_sepolia`
