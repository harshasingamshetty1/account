# Base Sepolia Restricted Account Test Guide

## 🎯 Overview

This guide shows you how to deploy and test the restricted account flow on Base Sepolia testnet. The test demonstrates:

1. ✅ Creating a restricted key with specific permissions
2. ✅ Allowing the key to call only a specific contract/function
3. ✅ Verifying the key CAN call the allowed function
4. ✅ Verifying the key CANNOT call unauthorized functions/contracts

## 📋 Prerequisites

- Foundry installed (`forge`, `cast`)
- Access to Base Sepolia testnet
- ETH on Base Sepolia (from faucet)

## 🚀 Step-by-Step Guide

### Step 1: Check Script and Get Addresses

First, run the script in simulation mode to see what addresses need funding:

```bash
cd /Users/harsha/Documents/Github/catalog_github/account

forge script script/TestRestrictedAccount.s.sol:TestRestrictedAccount \
  --rpc-url https://sepolia.base.org
```

**This will print addresses that need funding. Example output:**

```
========================================
REQUIRED: Fund These Addresses
========================================
1. Deployer (for deployment): 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
   Needs: ~0.1 ETH for contract deployments

2. Solver EOA (for setup): 0x1234...
   Needs: ~0.05 ETH for setup + test transactions
========================================
```

### Step 2: Fund the Addresses

**Go to Base Sepolia Faucet:**

- https://www.alchemy.com/faucets/base-sepolia
- OR https://faucet.quicknode.com/base/sepolia
- OR https://www.coinbase.com/faucets/base-ethereum-goerli-faucet

**Fund:**
1. **Deployer Address** - Get ~0.1 ETH
2. **Solver EOA Address** - Get ~0.05 ETH

**That's it! Only 2 addresses need funding.**

### Step 3: Set Environment Variable (Optional)

If you want to use your own deployer key instead of the default:

```bash
export DEPLOYER_PRIVATE_KEY=0xYourPrivateKeyHere
```

If not set, the script will use a deterministic default key.

### Step 4: Run the Full Test

Once funded, run the complete test:

```bash
# With default generated accounts
forge script script/TestRestrictedAccount.s.sol:TestRestrictedAccount \
  --rpc-url https://sepolia.base.org \
  --broadcast \
  --slow

# OR with your own deployer key
forge script script/TestRestrictedAccount.s.sol:TestRestrictedAccount \
  --rpc-url https://sepolia.base.org \
  --broadcast \
  --slow \
  --private-key $DEPLOYER_PRIVATE_KEY
```

## 📊 What This Script Does

### Phase 1: Deploy Contracts

- ✅ **Orchestrator** - Core account orchestration contract
- ✅ **IthacaAccount** - Smart account implementation
- ✅ **TestTarget** - Simple test contract with functions to call

### Phase 2: Setup Solver with EIP-7702 Delegation

- ✅ Solver EOA delegates to IthacaAccount using EIP-7702
- ✅ Solver can now use smart contract features

### Phase 3: Create and Authorize Restricted Key

- ✅ Creates a new secp256k1 key (restricted key)
- ✅ Authorizes it on the solver account
- ✅ Key is NOT a super admin (restricted permissions)

### Phase 4: Set Permissions

- ✅ Sets permission for restricted key to call:
  - **Contract**: TestTarget address
  - **Function**: `targetFunction(bytes)` selector only
- ✅ Verifies permission was set correctly

### Phase 5: Test Restricted Account Flow

**Test 1: ✅ Allowed Function Call**
- Restricted key calls `targetFunction` on TestTarget
- ✅ **SUCCESS** - Function is called

**Test 2: ❌ Unauthorized Function Call**
- Restricted key tries to call `otherFunction` on TestTarget
- ✅ **BLOCKED** - Reverts with `UnauthorizedCall` error

**Test 3: ❌ Unauthorized Contract Call**
- Restricted key tries to call `targetFunction` on different contract
- ✅ **BLOCKED** - Reverts with `UnauthorizedCall` error

## 📝 Expected Output

```
========================================
PHASE 1: Deploying Contracts
========================================

Deploying Orchestrator...
Orchestrator deployed at: 0xABC...

Deploying IthacaAccount implementation...
IthacaAccount deployed at: 0xDEF...

Deploying TestTarget contract...
TestTarget deployed at: 0x123...
Target function selector: 0x3c78f395

[OK] All contracts deployed successfully!

========================================
PHASE 2: Setup Solver with EIP-7702 Delegation
========================================

Delegating solver EOA to IthacaAccount...
Solver EOA: 0x456...
Delegated to: 0xDEF...

[OK] Solver EOA delegated to IthacaAccount

========================================
PHASE 3: Create and Authorize Restricted Key
========================================

Restricted Key Address: 0x789...
Restricted KeyHash: 0xABC...

Authorizing restricted key...
[OK] Restricted key authorized and verified

========================================
PHASE 4: Set Permissions
========================================

Setting permissions for restricted key:
  Contract: 0x123...
  Function: 0x3c78f395

[OK] Permissions set: restricted key can call targetFunction on test contract

========================================
PHASE 5: Test Restricted Account Flow
========================================

Test 1: Restricted key calls allowed function...
[OK] Restricted key successfully called allowed function!

Test 2: Restricted key tries to call different function (should fail)...
[OK] Restricted key correctly blocked from calling different function

Test 3: Restricted key tries to call on different contract (should fail)...
[OK] Restricted key correctly blocked from calling on different contract

[OK] All tests passed!

========================================
DEPLOYMENT SUMMARY
========================================

Deployed Contracts:
- Orchestrator: 0xABC...
- IthacaAccount: 0xDEF...
- TestTarget: 0x123...

Solver Account:
- EOA Address: 0x456...
- Delegated to: 0xDEF...

Restricted Key:
- KeyHash: 0xABC...
- Allowed Contract: 0x123...
- Allowed Function: 0x3c78f395

Private Keys (SAVE THESE!):
- Deployer: 0x...
- Solver EOA: 0x...
- Restricted Key: 0x...

========================================
SUCCESS! Restricted account tested!
========================================
```

## 🔍 Verification

After deployment, verify on Base Sepolia Explorer:

- https://sepolia.basescan.org/

Search for:
- Your contract addresses
- Solver EOA address
- Transaction hashes

## 🔐 Understanding the Test

### What Gets Tested

1. **Permission Setting**: Restricted key can only call specific function on specific contract
2. **Allowed Execution**: Restricted key successfully calls the allowed function
3. **Unauthorized Function**: Restricted key cannot call other functions (even on same contract)
4. **Unauthorized Contract**: Restricted key cannot call allowed function on different contract

### Key Concepts

- **Restricted Key**: A key that is NOT a super admin, with limited permissions
- **Permission Granularity**: Permissions are set per (keyHash, contract, functionSelector)
- **Authorization vs Execution**: The key authorizes the call, but the account contract executes it

## 🎓 How It Works

### Permission Flow

```
1. Restricted key signs a transaction
2. Account verifies signature matches restrictedKeyHash
3. Account checks canExecute(restrictedKeyHash, target, data)
4. If allowed → Execute the call
5. If not allowed → Revert with UnauthorizedCall
```

### Permission Storage

Permissions are stored as:
```solidity
mapping(keyHash => Set of (target, functionSelector))
```

The `canExecute` function checks:
1. Is keyHash a super admin? → Allow all
2. Is (target, functionSelector) in the allowed set? → Allow
3. Otherwise → Deny

## 🆘 Troubleshooting

### "Insufficient funds"

- Make sure both Deployer and Solver EOA have enough ETH
- Check balances: https://sepolia.basescan.org/
- Base Sepolia ETH is free from faucets

### "Transaction failed"

- Increase gas limit or try again
- Network might be congested
- Check that EIP-7702 is supported (Base Sepolia has it!)

### "Contract already deployed"

- Normal if re-running script
- Contracts at same address are reused
- You can use `--skip-simulation` to speed up

### "UnauthorizedCall not caught"

- The try-catch should handle this
- Check that the error selector matches
- Verify permissions were set correctly

## 📚 Next Steps

After successful test:

1. ✅ Verify all contracts on Basescan
2. ✅ Test with your own contracts
3. ✅ Experiment with different permission combinations
4. ✅ Deploy to mainnet (same process, different RPC)

## 🔗 Related Documentation

- `BASE_SEPOLIA_DEPLOYMENT.md` - General deployment guide
- `SOLVER_SETUP_GUIDE.md` - Multisig setup guide
- `test/SolverMultisigSetup.t.sol` - Unit tests

## 💡 Tips

1. **Save Private Keys**: The script prints all private keys - save them securely!
2. **Testnet Only**: This is for Base Sepolia testnet
3. **Gas Costs**: Each test transaction costs gas, so fund accordingly
4. **EIP-7702**: Works because Base Sepolia supports it!

**You're ready to test!** 🚀

