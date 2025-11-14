# DeployGardenSolver Script Guide

This script provides a streamlined deployment of the GardenSolver smart contract account with multisig control.

## What Gets Deployed

1. **Orchestrator** - Core protocol orchestrator contract
2. **MultiSigSigner** - Multisig validation contract  
3. **GardenSolver** - Smart contract account with 2-of-3 multisig control

## Configuration

Before deploying, update the signer addresses in the script:

```solidity
address public signer1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Anvil Account #1
address public signer2 = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC; // Anvil Account #2
address public signer3 = 0x90F79bf6EB2c4f870365E785982E1f101E93b906; // Anvil Account #3
uint256 public threshold = 2; // 2-of-3 multisig
uint256 public initialFunding = 10 ether; // Initial ETH funding
```

## Deployment Commands

### Local Testing (Anvil)

1. Start Anvil:
```bash
anvil
```

2. Deploy:
```bash
forge script script/DeployGardenSolver.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Testnet Deployment

#### Base Sepolia
```bash
forge script script/DeployGardenSolver.s.sol \
  --rpc-url $BASE_SEPOLIA_RPC_URL \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY
```

#### Ethereum Sepolia
```bash
forge script script/DeployGardenSolver.s.sol \
  --rpc-url $SEPOLIA_RPC_URL \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

### Mainnet Deployment

⚠️ **WARNING**: Always test thoroughly on testnet first!

```bash
forge script script/DeployGardenSolver.s.sol \
  --rpc-url $MAINNET_RPC_URL \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --slow
```

## Script Output

The script provides comprehensive deployment information:

```
========================================
DEPLOYMENT CONFIGURATION
========================================
Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Signer 1: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
Signer 2: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
Signer 3: 0x90F79bf6EB2c4f870365E785982E1f101E93b906
Multisig Threshold: 2 of 3
Initial Funding: 10 ETH
========================================

========================================
DEPLOYING CONTRACTS
========================================

1. Orchestrator deployed: 0x...
2. MultiSigSigner deployed: 0x...
3. GardenSolver deployed: 0x...
   - Funded with: 10 ETH
   - Keys authorized: 3
   - Multisig threshold: 2 of 3

========================================
DEPLOYMENT SUMMARY
========================================
[Full deployment details including key hashes]
```

## Post-Deployment Steps

After successful deployment:

1. **Verify Contracts** (if on public network)
   - The `--verify` flag handles this automatically
   - Or manually verify on block explorer

2. **Configure Whitelist**
   - Use multisig to call `whitelistAddress()` for addresses that can withdraw
   - See `DeployMultiSigExecute.s.sol` for example

3. **Adjust Cooldown Period** (if needed)
   - Default: 1 day (86400 seconds)
   - Use multisig to call `changeCooldownPeriod()`

4. **Fund the Account**
   - Send ETH: Direct transfer to GardenSolver address
   - Send tokens: Use standard ERC20 transfer

## Security Considerations

- **Signer Keys**: Store private keys securely (hardware wallet recommended for mainnet)
- **Threshold**: 2-of-3 means any 2 signers can execute transactions
- **Cooldown Period**: Whitelisted addresses must wait before withdrawing (security feature)
- **Initial Funding**: Ensure deployer has sufficient ETH + gas

## Helper Functions

The script includes a helper function to compute key hashes:

```solidity
function computeKeyHash(address signerAddress) public view returns (bytes32)
```

Use this to verify key hashes after deployment.

## Troubleshooting

### "Insufficient funds" error
- Ensure deployer has enough ETH for deployment + initial funding
- Reduce `initialFunding` if needed

### "Transaction reverted" 
- Check that signer addresses are valid
- Verify threshold is ≤ number of signers

### Contract verification fails
- Add `--legacy` flag if on older EVM chains
- Check API key is valid
- Try manual verification with `forge verify-contract`

## Examples

See `DeployMultiSigExecute.s.sol` for examples of:
- Executing multisig operations
- Whitelisting addresses
- Changing security parameters
- Withdrawing tokens

## Related Scripts

- `DeployMultiSigExecute.s.sol` - Full deployment + execution example
- `DeploySolverMultisig.s.sol` - Alternative deployment approach
- `TestRestrictedAccount.s.sol` - Testing restricted account functionality
