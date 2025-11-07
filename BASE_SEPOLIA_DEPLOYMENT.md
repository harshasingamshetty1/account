# Base Sepolia Deployment Guide

## 🎯 Quick Start

This guide shows you how to deploy and test the Solver with 2-of-3 multisig on Base Sepolia testnet.

## 📋 Step 1: Run Setup to See Addresses

First, run the script to generate all addresses:

```bash
cd /Users/harsha/Documents/Github/catalog_github/account
forge script script/DeploySolverMultisig.s.sol:DeploySolverMultisig --rpc-url https://sepolia.base.org
```

**This will print addresses that need funding. Example output:**

```
========================================
REQUIRED: Fund These Addresses
========================================
1. Deployer (for deployment): 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
   Needs: ~0.1 ETH for contract deployments

2. Solver EOA (for transactions): 0x1234...
   Needs: ~0.05 ETH for setup + operations
========================================
```

## 💰 Step 2: Fund These 2 Addresses

**Go to Base Sepolia Faucet:**

- https://www.alchemy.com/faucets/base-sepolia
- OR https://faucet.quicknode.com/base/sepolia

**Fund:**

1. **Deployer Address** - Get ~0.1 ETH
2. **Solver EOA Address** - Get ~0.05 ETH

**That's it! Only 2 addresses need funding.**

## 🚀 Step 3: Run Full Deployment

Once funded, run the complete deployment:

```bash
# With default generated accounts
forge script script/DeploySolverMultisig.s.sol:DeploySolverMultisig \
  --rpc-url https://sepolia.base.org \
  --broadcast \
  --slow

# OR with your own deployer key
forge script script/DeploySolverMultisig.s.sol:DeploySolverMultisig \
  --rpc-url https://sepolia.base.org \
  --broadcast \
  --slow \
  --private-key YOUR_DEPLOYER_KEY
```

## 📊 What This Script Does

### Phase 1: Deploy Contracts

- ✅ Orchestrator
- ✅ IthacaAccount (implementation)
- ✅ MultiSigSigner

### Phase 2: Setup EIP-7702 Delegation

- ✅ Solver EOA delegates to IthacaAccount
- ✅ Solver can now use smart contract features

### Phase 3: Configure 2-of-3 Multisig

- ✅ Creates 3 signer keys
- ✅ Authorizes them on the account
- ✅ Creates multisig super admin key
- ✅ Initializes 2-of-3 threshold

### Phase 4: Test Multisig

- ✅ Creates a test bot key
- ✅ Uses multisig to revoke it
- ✅ Proves multisig works!

## 🔑 Generated Accounts

The script generates deterministic accounts (same every time):

| Account    | Purpose             | Needs Funding?     |
| ---------- | ------------------- | ------------------ |
| Deployer   | Deploy contracts    | ✅ YES (~0.1 ETH)  |
| Solver EOA | Main solver account | ✅ YES (~0.05 ETH) |
| Signer 1   | Multisig signer     | ❌ No              |
| Signer 2   | Multisig signer     | ❌ No              |
| Signer 3   | Multisig signer     | ❌ No              |

**Note:** Signers don't need funding because they only sign, they don't submit transactions!

## 📝 Expected Output

```
========================================
PHASE 1: Deploying Contracts
========================================

Deploying Orchestrator...
Orchestrator deployed at: 0xABC...

Deploying IthacaAccount implementation...
IthacaAccount deployed at: 0xDEF...

Deploying MultiSigSigner...
MultiSigSigner deployed at: 0x123...

[OK] All contracts deployed successfully!

========================================
PHASE 2: Setup Solver with EIP-7702 Delegation
========================================

Delegating solver EOA to IthacaAccount...
[OK] Solver EOA delegated to IthacaAccount

========================================
PHASE 3: Setup 2-of-3 Multisig Super Admin
========================================

Authorizing individual signers...
Signer 1 KeyHash: 0x...
Signer 2 KeyHash: 0x...
Signer 3 KeyHash: 0x...

Creating multisig super admin key...
Multisig KeyHash: 0x...

Initializing 2-of-3 multisig configuration...
[OK] Multisig configured: 2 of 3

[IMPORTANT] Original solver private key can now be destroyed!
[IMPORTANT] From now on, 2-of-3 multisig has FULL admin access

========================================
PHASE 4: Test Multisig - Revoke a Key
========================================

Creating a test bot key...
Bot KeyHash: 0x...

Using multisig to revoke bot key...
[OK] Multisig successfully revoked the key!
[OK] Key confirmed revoked

========================================
DEPLOYMENT SUMMARY
========================================

Deployed Contracts:
- Orchestrator: 0xABC...
- IthacaAccount: 0xDEF...
- MultiSigSigner: 0x123...

Solver Account:
- EOA Address: 0x456...
- Delegated to: IthacaAccount

Multisig Configuration:
- Threshold: 2 of 3
- Signer 1: 0x789...
- Signer 2: 0xABC...
- Signer 3: 0xDEF...

Private Keys (SAVE THESE!):
- Solver: 0x...
- Signer 1: 0x...
- Signer 2: 0x...
- Signer 3: 0x...

========================================
SUCCESS! Solver is secured with multisig!
========================================
```

## 🔐 Using the Multisig

After deployment, you can use the multisig to manage the solver:

### Example: Revoke a Key

```solidity
// 1. Create the revoke call
Call[] memory calls = [{
    to: solverEOA,
    value: 0,
    data: abi.encodeWithSelector(IthacaAccount.revoke.selector, keyToRevoke)
}];

// 2. Get digest
uint256 nonce = solver.getNonce(0);
bytes32 digest = solver.computeDigest(calls, nonce);

// 3. Sign with 2 of 3 signers
bytes memory sig1 = sign(signer1PrivateKey, digest);
bytes memory sig2 = sign(signer2PrivateKey, digest);

// 4. Execute
solver.execute(mode, abi.encode(calls, multisigSignature));
```

## 🎯 Verification

After deployment, verify on Base Sepolia Etherscan:

- https://sepolia.basescan.org/

Search for your contract addresses to see them live!

## ⚠️ Important Notes

1. **Save Private Keys**: The script prints all private keys - save them!
2. **Testnet Only**: This is for Base Sepolia testnet
3. **Real Mainnet**: For production, use hardware wallets for signers
4. **EIP-7702**: Works because Pectra upgrade is live!

## 🆘 Troubleshooting

### "Insufficient funds"

- Make sure both Deployer and Solver EOA have enough ETH
- Check balances: https://sepolia.basescan.org/

### "Transaction failed"

- Increase gas limit or try again
- Network might be congested

### "Contract already deployed"

- Normal if re-running script
- Contracts at same address are reused

## 📚 Next Steps

1. ✅ Test on Base Sepolia (this guide)
2. ✅ Verify multisig works
3. ✅ Deploy to mainnet (same process, different RPC)
4. ✅ Use hardware wallets for real signers

**You're ready to go!** 🚀
