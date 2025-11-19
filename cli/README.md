# CLI Deployment and Execution

TypeScript scripts for deploying contracts and executing multisig operations across multiple chains.

## Installation

Install `tsx` globally to run TypeScript files directly:

```bash
npm i -g tsx
```

## Configuration

### config.json

Configure your chains with RPC URLs, HTLC addresses, and funding amounts:

```json
{
  "chains": [
    {
      "name": "sepolia",
      "rpc": "https://0xrpc.io/sep",
      "htlcs": [
        "0xd1E0Ba2b165726b3a6051b765d4564d030FDcf50",
        "0x730Be401ef981D199a0560C87DfdDaFd3EC1C493"
      ],
      "fundAmount": "0.001"
    }
  ]
}
```

### .env

Create a `.env` file in the `cli` directory with your keys and addresses. Environment variables are required for authentication and signing transactions.

**For deployment only:**

```env
DEPLOYER_PRIVATE_KEY=0x...
SIGNER_ONE_ADDRESS=0x...
SIGNER_TWO_ADDRESS=0x...
SIGNER_THREE_ADDRESS=0x...
```

**For full flow (deploy + execute):**

```env
DEPLOYER_PRIVATE_KEY=0x...
SIGNER_ONE_PRIVATE_KEY=0x...
SIGNER_TWO_PRIVATE_KEY=0x...
SIGNER_THREE_PRIVATE_KEY=0x...
PERMISSION_ADDRESS=0x...
```

Note: If you provide private keys, the deploy script will automatically derive addresses from them, so you don't need to set both.

## Usage

### Deploy Contracts

Deploy MultiSigSigner and GardenSolver contracts to all chains configured in `config.json`:

```bash
tsx cli/deploy.ts
```

This deploys contracts to each chain, funds GardenSolver with the specified amount, and saves deployment information to `deployed.json`.

### Execute Operations

After deployment, execute multisig operations (approve tokens, grant permissions) to all deployed chains:

```bash
tsx cli/execute.ts
```

Or execute for a specific chain:

```bash
tsx cli/execute.ts sepolia
```

This will approve tokens to HTLC contracts and grant permissions to the `PERMISSION_ADDRESS` for all configured HTLC addresses.
