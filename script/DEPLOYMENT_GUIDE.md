# 🚀 IthacaAccount Standalone Deployment Guide

Complete step-by-step guide for deploying and testing **IthacaAccount** as a standalone smart contract (no EIP-7702 needed!) with multisig control and authorized signer execution on Anvil.

---

## 📋 Overview

This workflow demonstrates:

- ✅ **Deploy** standalone IthacaAccount smart contract with funds
- ✅ **Authorize** 3 signer keys during deployment
- ✅ **Configure** a 2-of-3 multisig with super admin privileges (automatically in constructor)
- ✅ **Grant** a non-super-admin signer permissions for token transfers
- ✅ **Execute** a token transfer as the authorized signer

**Key Difference:** This is a pure smart contract deployment - no EIP-7702 delegation required! 🎉

---

## 🔧 Prerequisites

- **Foundry** installed (`forge`, `cast`, `anvil`)
- **Repository** cloned with dependencies installed (`forge install`)
- **Terminal** access with `zsh` shell
- **Anvil** running locally on port 8545

---

## 👥 Account Reference

All accounts use **Anvil's default private keys** (deterministic and pre-funded with 10,000 ETH each):

| Role | Anvil Account | Address | Private Key |
|------|---------------|---------|-------------|
| **Deployer** | Account #0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| **Signer 1** | Account #2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |
| **Signer 2** | Account #3 | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` | `0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6` |
| **Signer 3** | Account #4 | `0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65` | `0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a` |

> 💡 **Note:** All accounts are pre-funded by Anvil with 10,000 ETH each—no manual funding required! 🎉

---


## 📝 Step-by-Step Instructions

### Step 1: Start Anvil 🟢

Start a local Ethereum testnet:

```bash
anvil
```

Keep this terminal running. Open a new terminal for subsequent commands.

---

### Step 2: Deploy Standalone Account 📦

Deploy the IthacaAccount as a standalone smart contract with all keys authorized and multisig configured:

```bash
cd /Users/0xmetapunk/Codes/account

forge script script/DeployTestExecute.s.sol:DeployTestExecute \
  --sig "deployContracts()" \
  --fork-url http://localhost:8545 \
  --broadcast
```

**What Happens:**

1. ✅ Orchestrator deployed
2. ✅ MultiSigSigner deployed  
3. ✅ IthacaAccount deployed with 10 ETH
4. ✅ 3 signer keys authorized (signer1, signer2, signer3)
5. ✅ Multisig key created and authorized as super admin
6. ✅ MultiSigSigner.initConfig() called with 2-of-3 threshold
7. ✅ TestToken deployed and 1M tokens minted to account

**Expected Output:**

```text
========================================
ANVIL DEFAULT ACCOUNTS
========================================
Deployer (Account #0): 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Signer 1 (Account #2): 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
Signer 2 (Account #3): 0x90F79bf6EB2c4f870365E785982E1f101E93b906
Signer 3 (Account #4): 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
========================================

========================================
STEP 1: Deploy Contracts
========================================

Orchestrator: 0x5FbDB2315678afecb367f032d93F642f64180aa3
MultiSigSigner: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
IthacaAccount (Standalone): 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
- Funded with: 10 ETH
- Keys authorized: 3 (signer1, signer2, signer3)
- Multisig configured: 2-of-3
TestToken: 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9
- Minted 1000000 TT to account

[OK] Contracts deployed!
```

> 📝 **Important:** All setup is complete in one step! No EIP-7702 delegation needed.

---

### Step 3: Execute Multisig Operations ⚙️

Now grant signer1 permissions to transfer tokens, using the multisig (2-of-3 approval):

```bash
forge script script/DeployTestExecute.s.sol:DeployTestExecute \
  --sig "executeWithMultisig()" \
  --fork-url http://localhost:8545 \
  --broadcast
```

**What Happens:**

1. ✅ Multisig (signer1 + signer2) signs transaction
2. ✅ Sets `canExecute` permission for signer1 on token.transfer
3. ✅ Sets spend limit for signer1 (100,000 TT)
4. ✅ Signer1 executes token transfer (1,000 TT to self)

**Expected Output:**

```text
========================================
STEP 2: Execute Multisig Operations
========================================

========================================
PHASE 4: Grant signer1 Permissions (Multisig)
========================================

[OK] signer1 granted canExecute + spend limit

========================================
PHASE 5: signer1 Executes Transfer
========================================

[OK] signer1 pulled 1000 TT
New signer1 balance: 1000000000000000000000

========================================
FINAL SUMMARY
========================================
Orchestrator: 0x5FbDB...
MultiSigSigner: 0x9fE46...
IthacaAccount (Standalone): 0xCf7Ed...
TestToken: 0xDc64a...

Multisig: 2 of 3
- Signer 1: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
- Signer 2: 0x90F79bf6EB2c4f870365E785982E1f101E93b906
- Signer 3: 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65

Token Balances:
- Account: 999000 TT
- Signer1: 1000 TT
========================================
```

---

### Step 4: Verify Results ✅

#### Check Account Balance

```bash
cast balance <ITHACA_ACCOUNT_ADDRESS> --rpc-url http://localhost:8545
```

Should show ~10 ETH (10000000000000000000 wei)

#### Check Token Balances

**Account balance:**

```bash
cast call <TEST_TOKEN_ADDRESS> \
  "balanceOf(address)(uint256)" \
  <ITHACA_ACCOUNT_ADDRESS> \
  --rpc-url http://localhost:8545
```

**Signer1 balance:**

```bash
cast call <TEST_TOKEN_ADDRESS> \
  "balanceOf(address)(uint256)" \
  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC \
  --rpc-url http://localhost:8545
```

Replace addresses with actual deployed addresses from Step 2 output.

---


## 🐛 Troubleshooting

### Issue: "Multisig init failed"

**Cause:** Constructor failed to initialize multisig config.

**Solution:**

1. Check that MultiSigSigner contract is deployed
2. Verify threshold ≤ number of signer keys (e.g., 2 ≤ 3 for 2-of-3)
3. Ensure signer keys are not marked as super admin

### Issue: "KeyTypeCannotBeSuperAdmin"

**Cause:** Trying to pass individual signer keys with `isSuperAdmin=true` when multisig is configured.

**Solution:**

Set all individual signer keys to `isSuperAdmin=false`. Only the multisig key should be super admin.

### Issue: "InvalidSignature" or "UnauthorizedKey"

**Cause:** Key not properly authorized, or multisig config incorrect.

**Solution:**

1. Verify all 3 signer keys were authorized in constructor
2. Check multisig threshold is correct (2-of-3)
3. Ensure at least 2 signers signed the transaction

### Anvil State Issues

If you encounter unexpected behavior (e.g., nonce mismatches, old state):

**Solution:** Restart Anvil and re-run all steps from Step 1.

```bash
# Press Ctrl+C in the Anvil terminal to stop
# Then restart
anvil
```

---

## 🏗️ Architecture Notes

### Standalone Smart Contract

- **No EIP-7702:** Pure smart contract deployment, works on any EVM chain
- **Constructor Setup:** All keys authorized and multisig configured in single transaction
- **Funded Account:** Can receive ETH/tokens directly, acts as complete smart contract wallet
- **Upgradability:** Would need proxy pattern for upgrades (not EIP-7702 re-delegation)

### Multisig Flow

1. **Authorization:** 3 signer keys + 1 multisig key authorized in constructor
2. **Super Admin:** The External multisig key has `isSuperAdmin=true`
3. **Config Storage:** MultiSigSigner stores config under `_configs[accountAddress][multisigKeyHash]`
4. **Aggregation:** 2-of-3 signers must sign for multisig operations
5. **Wrapped Signature:** Format is `abi.encode(bytes[] innerSigs) || multisigKeyHash || uint8(0)`

### Non-Super-Admin Execution

1. **Whitelist:** Signer1 can only call whitelisted target+function combinations
2. **Spend Limit:** Token transfers tracked and limited per period (100,000 TT Forever)
3. **Wrapped Signature:** Format is `r || s || v || signer1KeyHash || uint8(0)`
4. **Permissions:** Multisig must grant via `setCanExecute` and `setSpendLimit` first

---

## 🔑 Key Hash Computation

Key hashes identify authorized signers:

**Secp256k1 Key:**

```solidity
keccak256(abi.encodePacked(uint8(KeyType.Secp256k1), abi.encode(address)))
```

**External Key (Multisig):**

```solidity
keccak256(abi.encodePacked(uint8(KeyType.External), abi.encode(contractAddress)))
```

**Using `cast`:**

```bash
# Secp256k1 key hash
cast keccak $(cast abi-encode "f(uint8,bytes)" 2 $(cast abi-encode "f(address)" <ADDRESS>))

# External key hash
cast keccak $(cast abi-encode "f(uint8,bytes)" 3 $(cast abi-encode "f(address)" <CONTRACT_ADDRESS>))
```

---

## 🎯 Next Steps

- **Production Deployment:** Replace Anvil with testnet RPC URLs (e.g., Base Sepolia)
- **Security:** Use hardware wallets or secure key management for production private keys
- **Monitoring:** Set up event listeners for `Authorized`, `Revoked`, and `Executed` events
- **Testing:** Expand test scenarios (threshold changes, owner rotation, spend limit enforcement)

---

## 📚 References

- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-7821 Minimal Batch Executor](https://eips.ethereum.org/EIPS/eip-7821)
- [Foundry Book](https://book.getfoundry.sh/)
- [Cast Reference](https://book.getfoundry.sh/reference/cast/)
- [Anvil Reference](https://book.getfoundry.sh/reference/anvil/)

---

**Made with ❤️ for the Ethereum community**

```

#### Fund Signer1 (1 ETH)

```bash
cast send 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f \
  --value 1ether \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --rpc-url http://localhost:8545
```

#### Verify Balances

```bash
cast balance 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 --rpc-url http://localhost:8545
cast balance 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f --rpc-url http://localhost:8545
```

**Expected:** Solver shows ~10000000000000000000 (10 ETH), Signer1 shows ~1000000000000000000 (1 ETH).

### Step 4: Perform EIP-7702 Delegation

Upgrade the solver EOA to use IthacaAccount implementation via EIP-7702 authorization:

```bash
cast send 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 \
  --auth <ITHACA_IMPL_ADDRESS> \
  --private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 \
  --rpc-url http://localhost:8545
```

**Replace `<ITHACA_IMPL_ADDRESS>`** with the IthacaAccount Impl address from Step 2 (e.g., `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`).

**Example with address:**
```bash
cast send 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 \
  --auth 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 \
  --private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 \
  --rpc-url http://localhost:8545
```

### Step 5: Verify Delegation

Check that the solver EOA now contains EIP-7702 delegation bytecode:

```bash
cast code 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 --rpc-url http://localhost:8545
```

**Expected Output:**
```
0xef0100e7f1725e7734ce288f8367e1bb143e90bb3f0512
```

The `0xef01` prefix followed by the implementation address confirms successful delegation.

### Step 6: Continue Deployment (Setup & Execution)

Now run the remaining phases: deploy test token, setup multisig, grant permissions, and execute transfer.

**Set environment variables** with the deployed addresses from Step 2:

```bash
export ORCHESTRATOR=0x5FbDB2315678afecb367f032d93F642f64180aa3
export ITHACA_IMPL=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
export MULTISIG_SIGNER=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
```

**Run the continuation script:**

```bash
forge script script/DeployTestExecute.s.sol:DeployTestExecute \
  --sig "continueAfterDelegation()" \
  --fork-url http://localhost:8545 \
  --broadcast
```

**Expected Output:**
```
========================================
LOADED CONTRACT ADDRESSES
========================================
Orchestrator: 0x5FbDB...
IthacaAccount Impl: 0xe7f17...
MultiSigSigner: 0x9fE46...
========================================

========================================
PHASE 1: DEPLOY AND MINT TEST TOKEN
========================================
TestToken deployed at: 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
Minted 1000000000000000000000000 TT to solver

========================================
PHASE 2: SETUP MULTISIG
========================================
Authorized 4 keys (3 Secp256k1 + 1 External)
Initialized 2-of-3 multisig config

========================================
PHASE 3: GRANT SIGNER1 PERMISSIONS (VIA MULTISIG)
========================================
Multisig executed: setCanExecute + setSpendLimit for signer1

========================================
PHASE 4: SIGNER1 EXECUTES TOKEN TRANSFER
========================================
Signer1 transferred 100 TT to recipient

========================================
EXECUTION SUMMARY
========================================
Solver TT Balance: 999900000000000000000000
Recipient TT Balance: 100000000000000000000
========================================
```

### Step 7: Verify Results

#### Check Token Balances

**Solver balance (should be 1M TT - 100 TT):**
```bash
cast call <TEST_TOKEN_ADDRESS> "balanceOf(address)(uint256)" 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 --rpc-url http://localhost:8545
```

**Recipient balance (should be 100 TT):**
```bash
cast call <TEST_TOKEN_ADDRESS> "balanceOf(address)(uint256)" 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --rpc-url http://localhost:8545
```

Replace `<TEST_TOKEN_ADDRESS>` with the address printed in Phase 1 output.

#### Check Authorized Keys

```bash
cast call 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 \
  "isAuthorized(bytes32)(bool)" \
  <SIGNER1_KEY_HASH> \
  --rpc-url http://localhost:8545
```

To compute `signer1KeyHash`:
```bash
cast keccak $(cast abi-encode "f(uint8,bytes)" 2 $(cast abi-encode "f(address)" 0x06d9856C810232F1fddFB8acd4870B64457386B5))
```

**Expected:** `true` (0x0000000000000000000000000000000000000000000000000000000000000001)

## Troubleshooting

### "Insufficient funds for gas"

**Cause:** Solver EOA or Signer1 lacks ETH for transaction fees.

**Solution:** Repeat Step 3 to fund accounts.

### "call to non-contract address"

**Cause:** EIP-7702 delegation not yet performed, or delegation reverted.

**Solution:** 
1. Verify solver EOA has ETH: `cast balance 0xa0Ee... --rpc-url http://localhost:8545`
2. Re-run Step 4 delegation command
3. Verify with `cast code 0xa0Ee... --rpc-url http://localhost:8545` (should see `0xef01...`)

### "Set ORCHESTRATOR env var" error

**Cause:** Environment variables not set before running `continueAfterDelegation()`.

**Solution:** Run the export commands in Step 6 with actual deployed addresses from Step 2.

### "InvalidSignature" or "UnauthorizedKey"

**Cause:** Key not properly authorized, or multisig config incorrect.

**Solution:**
1. Check multisig setup logs in Phase 2 output
2. Verify 3 Secp256k1 keys + 1 External key authorized
3. Confirm 2-of-3 threshold set correctly

### Anvil State Issues

If you encounter unexpected behavior (e.g., nonce mismatches, old state persisting):

**Solution:** Restart Anvil and re-run all steps from Step 1.

```bash
# In the Anvil terminal, press Ctrl+C to stop
# Then restart
anvil
```

## Architecture Notes

### EIP-7702 Delegation

- **Type-4 Transaction:** The `cast send --auth` command creates an EIP-7702 authorization transaction
- **Delegation Pointer:** The solver EOA's code becomes `0xef01 || <impl_address>`, not a full code copy
- **Execution Context:** When a transaction targets the solver EOA, the EVM delegates execution to the implementation contract while preserving the EOA's storage and balance

### Multisig Flow

1. **Authorization:** Each signer's key (Secp256k1 or External) is authorized on the solver account
2. **Super Admin:** The External multisig key has `isSuperAdmin=true`, allowing it to call admin functions like `setCanExecute` and `setSpendLimit`
3. **Aggregation:** When executing with the multisig key, the MultiSigSigner contract validates inner signatures from 2-of-3 configured owners (signer1, signer2, signer3)
4. **Wrapped Signature:** Outer signature format is `abi.encode(bytes[] innerSigs) || multisigKeyHash || uint8(0)`

### Non-Super-Admin Execution

1. **Whitelist:** Signer1 (non-super-admin) can only call whitelisted target+function combinations
2. **Spend Limit:** Token transfers are tracked and limited per period (e.g., 1000 TT per Forever period)
3. **Wrapped Signature:** Signer1's signature format is `r || s || v || signer1KeyHash || uint8(0)`
4. **Permissions:** The multisig must first grant permissions via `setCanExecute` and `setSpendLimit` before signer1 can execute

## Key Hash Computation

Key hashes identify authorized signers:

**Secp256k1 Key:**
```solidity
keccak256(abi.encodePacked(uint8(KeyType.Secp256k1), abi.encode(address)))
```

**External Key (Multisig):**
```solidity
keccak256(abi.encodePacked(uint8(KeyType.External), abi.encode(contractAddress)))
```

In `cast`:
```bash
# Secp256k1 key hash
cast keccak $(cast abi-encode "f(uint8,bytes)" 2 $(cast abi-encode "f(address)" <ADDRESS>))

# External key hash
cast keccak $(cast abi-encode "f(uint8,bytes)" 3 $(cast abi-encode "f(address)" <CONTRACT_ADDRESS>))
```

## Next Steps

- **Production Deployment:** Replace Anvil with testnet RPC URLs (e.g., Base Sepolia)
- **Security:** Use hardware wallets or secure key management for solver EOA and signer private keys
- **Monitoring:** Set up event listeners for `Authorized`, `Revoked`, and `Executed` events
- **Testing:** Expand test scenarios (e.g., threshold changes, owner rotation, spend limit enforcement)

## References

- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-7821 Minimal Batch Executor](https://eips.ethereum.org/EIPS/eip-7821)
- [Foundry Book](https://book.getfoundry.sh/)
- [Cast Reference](https://book.getfoundry.sh/reference/cast/)
