# Solver Multisig Setup Guide

## Overview
This guide demonstrates how to set up a secure Solver account using IthacaAccount with a 2-of-3 multisig as the super admin, eliminating single key risk.

## Test Results ✅

All tests passing:
- `test_SolverWithMultisigSuperAdmin()` - Main flow test
- `test_RegularKeyCannotCallRevoke()` - Security test
- `test_MultisigCanAuthorizeNewKeys()` - Functionality test

## Architecture

```
Solver EOA (Your funds stay here!)
├── EIP-7702 Delegated to IthacaAccount
├── Original EOA Key (🔒 Destroy after setup)
└── Super Admin: 2-of-3 Multisig
    ├── Signer 1 (Hardware Wallet)
    ├── Signer 2 (Hardware Wallet)
    └── Signer 3 (Hardware Wallet)
    └── Can call: authorize(), revoke(), setCanExecute(), etc.
```

## Setup Flow

### Phase 1: Create Solver EOA
```solidity
// Create a fresh EOA for your solver
address solverEOA = /* generate new EOA */;

// Delegate to IthacaAccount using EIP-7702
// (In Foundry tests, we simulate with vm.etch)
```

### Phase 2: Fund the Solver
```solidity
// Send funds directly to the EOA address
// The funds stay at the EOA, NOT in a separate contract!
payable(solverEOA).transfer(100 ether);
USDC.transfer(solverEOA, 1_000_000e6);
```

### Phase 3: Setup Multisig Signers
```solidity
// Create 3 individual signer keys (hardware wallets)
Key memory signer1Key = Key({
    expiry: 0,
    keyType: KeyType.Secp256k1,
    isSuperAdmin: false,  // Individual signers are NOT super admins
    publicKey: abi.encode(signer1Address)
});
// Repeat for signer2 and signer3

// Authorize all signers using original EOA key
solver.authorize(signer1Key);
solver.authorize(signer2Key);
solver.authorize(signer3Key);
```

### Phase 4: Create Multisig Super Admin
```solidity
// Deploy MultiSigSigner contract (once, can be shared)
MultiSigSigner multiSigSigner = new MultiSigSigner();

// Create the multisig super admin key
Key memory multisigKey = Key({
    expiry: 0,
    keyType: KeyType.External,  // External type for custom validation
    isSuperAdmin: true,          // THIS is the super admin!
    publicKey: abi.encodePacked(
        address(multiSigSigner),  // First 20 bytes
        bytes12(0)                // Last 12 bytes (salt)
    )
});

bytes32 multisigKeyHash = solver.authorize(multisigKey);
```

### Phase 5: Initialize Multisig Config
```solidity
// IMPORTANT: Must be called FROM the solver account!
vm.prank(solverEOA);
multiSigSigner.initConfig(
    multisigKeyHash,
    2,  // Threshold: 2 of 3
    [signer1Hash, signer2Hash, signer3Hash]
);
```

### Phase 6: Destroy Original Private Key
```
🔥 At this point, you can safely destroy/secure the original private key
🔥 From now on, ONLY the 2-of-3 multisig can call admin functions
```

## Usage Examples

### Revoke a Compromised Key (Using Multisig)
```solidity
// Create the revoke call
Call[] memory calls = new Call[](1);
calls[0] = Call({
    to: solverEOA,
    value: 0,
    data: abi.encodeWithSelector(IthacaAccount.revoke.selector, compromisedKeyHash)
});

// Get signatures from 2 of 3 signers
uint256 nonce = solver.getNonce(0);
bytes32 digest = solver.computeDigest(calls, nonce);

bytes[] memory innerSignatures = new bytes[](2);
innerSignatures[0] = signWithHardwareWallet1(digest);
innerSignatures[1] = signWithHardwareWallet2(digest);

// Wrap the multisig signature
bytes memory multisigSig = abi.encodePacked(
    abi.encode(innerSignatures),
    multisigKeyHash,
    uint8(0)
);

// Execute (anyone can submit, security is in the signature!)
solver.execute(
    ERC7821_BATCH_EXECUTION_MODE,
    abi.encode(calls, abi.encodePacked(nonce, multisigSig))
);
```

### Authorize a New Key (Using Multisig)
```solidity
Key memory newKey = /* create new key */;

Call[] memory calls = new Call[](1);
calls[0] = Call({
    to: solverEOA,
    value: 0,
    data: abi.encodeWithSelector(IthacaAccount.authorize.selector, newKey)
});

// Get 2-of-3 signatures and execute (same pattern as above)
```

## Key Security Features

✅ **No Single Point of Failure**: Requires 2 of 3 signers
✅ **Original Key Can Be Destroyed**: Not needed after setup
✅ **Funds Stay in EOA**: No need to transfer to a contract
✅ **Full Admin Access**: Multisig can call all `onlyThis` functions
✅ **Hardware Wallet Compatible**: Each signer can be a hardware wallet

## How It Works (The Magic!)

The key insight is that `onlyThis` functions check `msg.sender == address(this)`, NOT who signed the transaction.

When the multisig uses `execute()`:
1. Signature is validated (multisig requirement checked)
2. Internal calls are made FROM the contract TO itself
3. These internal calls have `msg.sender = address(this)`
4. The `onlyThis` modifier passes! ✅

## Running the Tests

```bash
# Run all solver multisig tests
forge test --match-contract SolverMultisigSetupTest -vv

# Run just the main flow test
forge test --match-test test_SolverWithMultisigSuperAdmin -vv
```

## Test File Location
`test/SolverMultisigSetup.t.sol`

## Important Notes

1. **initConfig Must Be Called From Solver**: Use `vm.prank(solverEOA)` or execute via the account itself
2. **MultiSigSigner Uses msg.sender**: The config is stored per account address
3. **Hardware Wallets Recommended**: For maximum security, use hardware wallets for all 3 signers
4. **Test Thoroughly**: Before destroying the original key, test all multisig operations

## Security Best Practices

1. ✅ Use hardware wallets for all multisig signers
2. ✅ Store signers in different physical locations
3. ✅ Test multisig functionality before destroying original key
4. ✅ Keep one backup of original key in secure cold storage (emergency only)
5. ✅ Consider 3-of-5 for higher value solvers

## Congratulations! 🎉

You now have a production-ready, secure Solver account with no single point of failure!

