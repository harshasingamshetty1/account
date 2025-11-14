# MultiSig Execute Script Documentation

## Overview

The `DeployMultiSigExecute.s.sol` script provides a comprehensive demonstration of GardenSolver's multisig capabilities, including deployment, configuration, dynamic key management, and multisig threshold upgrades. This script showcases the complete lifecycle of a multisig-controlled smart contract account.

## Quick Start

### One-Click Execution (Recommended)
```bash
forge script script/DeployMultiSigExecute.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Split Execution (For Testing)
```bash
# Step 1: Deploy contracts
forge script script/DeployMultiSigExecute.s.sol --sig "deployContracts()" --rpc-url http://localhost:8545 --broadcast

# Step 2: Execute multisig operations
forge script script/DeployMultiSigExecute.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast
```

## Architecture

### Contracts Deployed

1. **Orchestrator** - Account factory and upgrade manager
2. **MultiSigSigner** - Threshold signature validator (ERC-1271)
3. **GardenSolver** - Smart contract account with solver capabilities
4. **ExperimentERC20** - Test token for demonstrating withdrawals

### Initial Configuration

- **Account Type**: GardenSolver (standalone smart contract account)
- **Initial Funding**: 10 ETH
- **Test Tokens**: 1,000,000 TT (TestToken)
- **Multisig Threshold**: 2-of-3 (upgraded to 2-of-4 in Phase 6)
- **Initial Signers**: signer1, signer2, signer3
- **Default Cooldown**: 1 day (86400 seconds)

## Execution Phases

### Phase 1: Compute Key Hashes

**Purpose**: Calculate and verify all key hashes for signature operations

**Process**:
- Reconstructs Key structs for all signers
- Computes key hashes using `IthacaAccount.hash()`
- Stores hashes for use in subsequent phases
- Verifies keys match deployed account state

**Key Types**:
- **Secp256k1 Keys**: Regular ECDSA keys (signer1, signer2, signer3, signer4)
- **External Key**: MultiSigSigner contract (super-admin)

### Phase 2: Whitelist Address

**Purpose**: Authorize signer3 for withdrawal operations

**Process**:
1. Create ERC7821 Call to `whitelistAddress(signer3)`
2. Get current nonce from account
3. Compute digest for signatures
4. Generate signatures from signer1 and signer2 (2-of-3 threshold)
5. Combine into multisig signature format
6. Execute via `account.execute(calls, signature)`

**Security Features**:
- Whitelisting timestamp recorded
- Cooldown period starts immediately
- Only whitelisted addresses can receive withdrawals

**Code Flow**:
```solidity
ERC7821.Call[] → computeDigest() → sign() × 2 → encode() → execute()
```

### Phase 3: Modify Cooldown Period

**Purpose**: Reduce cooldown period for testing (1 day → 1 second)

**Process**:
1. Create Call to `changeCooldownPeriod(1)`
2. Generate 2-of-3 multisig signature
3. Execute parameter change

**Important Notes**:
- Contract enforces non-zero cooldown (`GardenSolver__ZeroValue` check)
- Minimum allowed value: 1 second
- In production, maintain appropriate cooldown for security

**Security Implications**:
- Cooldown provides protection against unauthorized withdrawals
- Time window allows for detection and response to malicious actions
- Balance security vs. operational efficiency

### Phase 4: Verify Configuration

**Purpose**: Query and display account state (view-only)

**Checks Performed**:
- ✅ Signer3 whitelisted status
- ✅ Whitelisting timestamp
- ✅ Current cooldown period
- ✅ Withdrawal availability calculation

**Cooldown Calculation**:
```
withdrawal_available_after = whitelisting_timestamp + cooldown_period
```

**Output Example**:
```
Signer3 whitelisted: true
Whitelisting timestamp: 1763115696
Current cooldown period: 1 seconds
Current block timestamp: 1763115696
Withdrawal available after: 1763115697
[INFO] Cooldown in progress - withdrawal available in 1 seconds
```

### Phase 5: Authorize New Key

**Purpose**: Add signer4 as an authorized key (dynamic key management)

**Process**:
1. Construct Key struct for signer4
   ```solidity
   IthacaAccount.Key({
       expiry: 0,
       keyType: KeyType.Secp256k1,
       isSuperAdmin: false,
       publicKey: abi.encode(signer4Address)
   })
   ```
2. Create Call to `authorize(signer4Key)`
3. Use existing 2-of-3 multisig to execute
4. Compute and store `signer4KeyHash`

**Key Characteristics**:
- Type: Secp256k1 (ECDSA)
- Super Admin: False (regular key)
- Expiry: 0 (no expiration)
- Can sign transactions independently
- **NOT** automatically added to multisig

### Phase 6: Add Signer to Multisig

**Purpose**: Upgrade multisig from 2-of-3 to 2-of-4

**Process**:
1. Create Call to `MultiSigSigner.addOwner(multisigKeyHash, signer4KeyHash)`
2. Use existing 2-of-3 multisig to authorize upgrade
3. Execute through account

**Configuration Changes**:
```
Before: 2-of-3 (signer1, signer2, signer3)
After:  2-of-4 (signer1, signer2, signer3, signer4)
```

**Valid Signature Combinations After Upgrade**:
- signer1 + signer2 ✅
- signer1 + signer3 ✅
- signer1 + signer4 ✅ (NEW)
- signer2 + signer3 ✅
- signer2 + signer4 ✅ (NEW)
- signer3 + signer4 ✅ (NEW)

**Benefits**:
- Increased flexibility
- No threshold change (still 2 signatures required)
- Backward compatible (old combinations still work)
- Enhanced security through redundancy

### Phase 7: Withdraw with New Multisig (Optional)

**Purpose**: Demonstrate new multisig combination (signer1 + signer4)

**Process**:
1. Verify signer3 whitelist status
2. Check cooldown period elapsed
3. Create withdrawal Call
4. Generate signatures from **signer1 + signer4** (demonstrating new flexibility)
5. Execute withdrawal

**Current Status**: ⏸️ Skipped in main execution

**Reason**: Requires waiting for cooldown period to elapse

**To Execute Manually**:
```bash
# Wait for cooldown period, then run Phase 7 separately
# Or manually advance blockchain time in testing
cast rpc evm_increaseTime 2 --rpc-url http://localhost:8545
cast rpc evm_mine --rpc-url http://localhost:8545
```

## Key Concepts

### Key Management

#### Key Structure
```solidity
struct Key {
    uint256 expiry;           // Unix timestamp, 0 = no expiry
    KeyType keyType;          // Secp256k1 or External
    bool isSuperAdmin;        // Can modify keys (External only)
    bytes publicKey;          // Encoded public key or address
}
```

#### Key Types

1. **Secp256k1 Keys**
   - Standard ECDSA keys
   - Used by individual signers
   - Cannot be super-admin
   - Example: signer1, signer2, signer3, signer4

2. **External Keys**
   - Smart contract addresses
   - Validate via ERC-1271
   - Can be super-admin
   - Example: MultiSigSigner contract

#### Key Hashes

Key hashes uniquely identify keys in the system:
```solidity
keyHash = keccak256(abi.encode(
    key.expiry,
    key.keyType,
    key.isSuperAdmin,
    key.publicKey
))
```

### Multisig Signature Format

#### Individual Signature (Secp256k1)
```
[r: 32 bytes][s: 32 bytes][v: 1 byte][keyHash: 32 bytes][keyType: 1 byte]
Total: 98 bytes per signature
```

#### Multisig Signature
```
[innerSignatures: dynamic][multisigKeyHash: 32 bytes][keyType: 1 byte]

innerSignatures = abi.encode(bytes[] signatures)
```

#### Example (2-of-3 multisig)
```solidity
bytes[] memory innerSigs = new bytes[](2);
innerSigs[0] = signature1; // 98 bytes
innerSigs[1] = signature2; // 98 bytes

bytes memory multisigSig = abi.encodePacked(
    abi.encode(innerSigs),
    multisigKeyHash,
    uint8(0)  // keyType: regular (not sessionKey)
);
```

### Nonce Management

**Purpose**: Prevent replay attacks

**Format**: 
```solidity
uint256 nonce = (nonceSpace << 128) | sequence
```

**Nonce Space 0**: Default execution space used in this script

**Sequence**: Increments with each transaction

**Usage**:
```solidity
uint256 nonce = account.getNonce(0);        // Get current nonce
bytes32 digest = account.computeDigest(calls, nonce);  // Include in signature
// ... generate signatures ...
account.execute(calls, abi.encodePacked(nonce, signature));  // Prepend to signature
```

### Cooldown Mechanism

**Purpose**: Security delay between whitelisting and withdrawal

**Enforcement**:
```solidity
require(
    block.timestamp >= whitelistingTimestamps[recipient] + cooldownPeriod,
    GardenSolver__TargetNotWhitelisted()
);
```

**Configurable**: Multisig can modify via `changeCooldownPeriod()`

**Minimum**: 1 second (enforces non-zero value)

**Default**: 1 day (86400 seconds)

## Signature Generation Process

### Step 1: Create Calls
```solidity
ERC7821.Call[] memory calls = new ERC7821.Call[](1);
calls[0] = ERC7821.Call({
    to: targetContract,
    value: 0,
    data: abi.encodeWithSelector(functionSelector, args...)
});
```

### Step 2: Compute Digest
```solidity
uint256 nonce = account.getNonce(0);
bytes32 digest = account.computeDigest(calls, nonce);
```

The digest includes:
- Chain ID
- Account address
- Nonce
- Call data (to, value, data for each call)

### Step 3: Sign Digest
```solidity
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
bytes memory signature = abi.encodePacked(r, s, v, keyHash, uint8(0));
```

### Step 4: Combine for Multisig
```solidity
bytes[] memory innerSignatures = new bytes[](2);
innerSignatures[0] = signature1;
innerSignatures[1] = signature2;

bytes memory multisigSig = abi.encodePacked(
    abi.encode(innerSignatures),
    multisigKeyHash,
    uint8(0)
);
```

### Step 5: Execute
```solidity
vm.startBroadcast();
account.execute(calls, abi.encodePacked(nonce, multisigSig));
vm.stopBroadcast();
```

## Testing Accounts (Anvil)

| Account | Role | Address | Private Key |
|---------|------|---------|-------------|
| #0 | Deployer | `0xf39Fd...92266` | `0xac0974...f2ff80` |
| #2 | Signer 1 | `0x3C44Cd...293BC` | `0x5de411...ab365a` |
| #3 | Signer 2 | `0x90F79b...3b906` | `0x7c8521...1b007a6` |
| #4 | Signer 3 | `0x15d34A...2C6A65` | `0x47e179...34926a` |
| #5 | Signer 4 | `0x996550...B0A4dc` | `0x8b3a35...edffba` |

**Note**: These are Anvil's deterministic default accounts for testing only. **Never use these keys on mainnet.**

## Security Considerations

### 1. Threshold Requirements
- Minimum 2 signatures required for all operations
- No single point of failure
- Compromising 1 key doesn't compromise account

### 2. Cooldown Protection
- Time delay between whitelisting and withdrawal
- Allows detection of unauthorized whitelist additions
- Provides window for emergency response

### 3. Nonce Management
- Prevents signature replay attacks
- Each transaction invalidates its nonce
- Sequential execution enforced per nonce space

### 4. Key Expiration
- Keys can have expiration timestamps
- Expired keys automatically invalid
- Allows time-limited access

### 5. Super Admin Keys
- Only External keys can be super-admin
- Super-admins can modify key set
- Multisig control over sensitive operations

## Common Operations

### Adding a New Signer

**Requires 2 Phases**:

1. **Authorize Key** (Phase 5)
   - Adds key to account's key registry
   - Key can sign transactions independently
   - Uses existing multisig to authorize

2. **Add to Multisig** (Phase 6)
   - Adds key to multisig configuration
   - Updates valid signature combinations
   - Uses existing multisig to authorize

### Removing a Signer

```solidity
// Phase 1: Remove from multisig
Call: MultiSigSigner.removeOwner(multisigKeyHash, signerKeyHash)
Authorization: Existing multisig

// Phase 2: Deauthorize key (optional)
Call: IthacaAccount.deauthorize(keyHash)
Authorization: Super-admin key (multisig)
```

### Changing Threshold

```solidity
Call: MultiSigSigner.changeThreshold(multisigKeyHash, newThreshold)
Authorization: Existing multisig
Note: newThreshold must be <= number of owners
```

### Whitelisting Address

```solidity
Call: GardenSolver.whitelistAddress(recipient)
Authorization: Multisig
Effect: Starts cooldown timer
```

### Withdrawing Funds

```solidity
Call: GardenSolver.withdraw(recipient, token, amount)
Authorization: Multisig
Requirements:
  - Recipient must be whitelisted
  - Cooldown period must have elapsed
```

## Troubleshooting

### Issue: `GardenSolver__TargetNotWhitelisted()`

**Cause**: Cooldown period hasn't elapsed

**Solution**:
```bash
# Check cooldown status
cast call <ACCOUNT> "cooldownPeriod()" --rpc-url localhost:8545
cast call <ACCOUNT> "whitelistingTimestamps(address)(uint256)" <RECIPIENT> --rpc-url localhost:8545

# Wait for cooldown or advance time (testing only)
cast rpc evm_increaseTime <SECONDS> --rpc-url localhost:8545
cast rpc evm_mine --rpc-url localhost:8545
```

### Issue: `GardenSolver__ZeroValue()`

**Cause**: Trying to set cooldown to 0

**Solution**: Use minimum value of 1 second
```solidity
changeCooldownPeriod(1) // ✅ Valid
changeCooldownPeriod(0) // ❌ Reverts
```

### Issue: `MultiSigSigner__ThresholdNotMet()`

**Cause**: Insufficient valid signatures

**Solutions**:
- Verify all signers are in multisig configuration
- Check signature order matches signer order
- Ensure key hashes are computed correctly
- Verify nonce is current

### Issue: `IthacaAccount__InvalidNonce()`

**Cause**: Nonce mismatch or reuse

**Solution**:
```bash
# Query current nonce
cast call <ACCOUNT> "getNonce(uint256)(uint256)" 0 --rpc-url localhost:8545
```

## Advanced Usage

### Custom Nonce Spaces

```solidity
// Execute in different nonce space
uint256 customNonce = account.getNonce(1); // Space 1
bytes32 digest = account.computeDigest(calls, customNonce);
// ... generate signatures ...
account.execute(calls, abi.encodePacked(customNonce, signature));
```

**Use Cases**:
- Parallel execution of independent operations
- Session-based transactions
- Batch operations with different permissions

### Batch Operations

```solidity
// Execute multiple calls in one transaction
ERC7821.Call[] memory calls = new ERC7821.Call[](3);
calls[0] = Call({...}); // Whitelist address
calls[1] = Call({...}); // Change cooldown
calls[2] = Call({...}); // Approve token

// All succeed or all revert (atomic)
account.execute(calls, signature);
```

### Session Keys (Future)

```solidity
// Grant temporary signing authority
Key memory sessionKey = Key({
    expiry: block.timestamp + 1 days,
    keyType: KeyType.Secp256k1,
    isSuperAdmin: false,
    publicKey: abi.encode(sessionAddress)
});

account.authorize(sessionKey); // Via multisig
```