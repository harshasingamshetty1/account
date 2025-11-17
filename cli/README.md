# CLI Deployment and Execution Scripts

This directory contains TypeScript scripts for deploying contracts and executing multisig operations.

## Setup

1. **Install dependencies**:

   ```bash
   npm install
   ```

2. **Configure private keys**:

   Copy the example config file:

   ```bash
   cp cli/config.ts.example cli/config.ts
   ```

   Then edit `cli/config.ts` and set your private keys:

   - Set `DEPLOYER_PRIVATE_KEY`
   - Set `SIGNER_ONE_PRIVATE_KEY`
   - Set `SIGNER_TWO_PRIVATE_KEY`
   - Set `SIGNER_THREE_PRIVATE_KEY`

   Or set them as environment variables:

   ```bash
   export DEPLOYER_PRIVATE_KEY=0x...
   export SIGNER_ONE_PRIVATE_KEY=0x...
   export SIGNER_TWO_PRIVATE_KEY=0x...
   export SIGNER_THREE_PRIVATE_KEY=0x...
   ```

3. **Configure chains** in `config.json`:
   - Add or modify chain configurations
   - Set RPC URLs
   - Add HTLC contract addresses

## Usage

### Step 1: Deploy Contracts

Deploy all contracts (Orchestrator, MultiSigSigner, GardenSolver) and save deployment info to `deployed.json`:

```bash
npm run deploy
# or
tsx cli/deploy.ts
```

This will:

- Deploy Orchestrator
- Deploy MultiSigSigner
- Deploy GardenSolver with 3 signers and 2-of-3 multisig threshold
- Fund GardenSolver with 10 ETH
- Save all addresses and key hashes to `deployed.json`

### Step 2: Execute Multisig Operations

After deployment, execute multisig operations:

```bash
npm run execute
# or
tsx cli/execute.ts
```

This will:

1. Approve tokens to all HTLC addresses (via multisig)
2. Grant HTLC permissions to signer1 (via multisig)
3. (Optional) Initiate HTLC order (commented out by default)

## File Structure

- `config.json` - Chain configuration (RPC URLs, HTLC addresses)
- `config.ts` - Private keys configuration
- `deploy.ts` - Deployment script
- `execute.ts` - Execution script for multisig operations
- `deployed.json` - Generated file with deployment addresses (created after running deploy.ts)

## Configuration

### config.json

```json
{
  "chains": [
    {
      "name": "sepolia",
      "rpc": "https://0xrpc.io/sep",
      "htlcs": [
        "0xd1E0Ba2b165726b3a6051b765d4564d030FDcf50",
        "0x730Be401ef981D199a0560C87DfdDaFd3EC1C493"
      ]
    }
  ]
}
```

### config.ts

Private keys can be set directly or via environment variables:

- `DEPLOYER_PRIVATE_KEY` - Private key for deploying contracts
- `SIGNER_ONE_PRIVATE_KEY` - Private key for signer 1
- `SIGNER_TWO_PRIVATE_KEY` - Private key for signer 2
- `SIGNER_THREE_PRIVATE_KEY` - Private key for signer 3

## Security Notes

⚠️ **Never commit `config.ts` with real private keys!**

- Use environment variables in production
- Add `config.ts` to `.gitignore` if it contains real keys
- Consider using a secrets manager for production deployments

## Troubleshooting

### "deployed.json not found"

Run `deploy.ts` first to create the deployment file.

### "Missing required private keys"

Ensure all private keys are set in `config.ts` or as environment variables.

### Forge script errors

Make sure you have:

- Forge installed and in PATH
- Sufficient balance in deployer account
- Correct RPC URL in config.json
