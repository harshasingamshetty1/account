# EIP-7702 Delegation & Restricted Key Test - Success Summary

## Overview
Successfully delegated an EOA account to the IthacaAccount implementation using EIP-7702 on Base Sepolia, then authorized and executed calls with a restricted key.

## Account Details
- **EOA Address**: `0x29FB8276DdA3Fe8a841552CA6BF7518D0Fa9eE25`
- **Delegated Implementation**: `0x6b40BC85123Bf9CC1c6FFAC34296D58473382108` (IthacaAccount)
- **Restricted Key Address**: `0x51A26C2236C70f160fF961e5461c87213564b3c5`
- **Restricted Key Hash**: `0x3c05214ea15b85b7e48237aa72ff9fbf95b582eeba266365835bb2558366c5cd`
- **Test Contract**: `0x098Fd27df763E5361Da026412d1C8702AcB56c98`

## Transaction History

### 1. EIP-7702 Delegation (Manual via cast)
```bash
cast send \
  --private-key 0x... \
  --rpc-url https://sepolia.base.org \
  --auth 0x6b40BC85123Bf9CC1c6FFAC34296D58473382108 \
  0x0000000000000000000000000000000000000000 \
  --value 0 \
  --gas-limit 100000 \
  --gas-price 1gwei
```
**Status**: ✅ Success  
**Transaction**: `0xc47643fc6a918830534183a064e4fb8fa7dfee767e138745a18b09f66a55c3ac`  
**Block**: 33501748  
**Gas Used**: 36,800  

**Verification**:
```bash
cast code 0x29FB8276DdA3Fe8a841552CA6BF7518D0Fa9eE25 --rpc-url https://sepolia.base.org
# Returns: 0xef01006b40bc85123bf9cc1c6ffac34296d58473382108
```

### 2. Authorize Restricted Key
**Status**: ✅ Success  
**Transaction**: `0xe194559c3379d8a70375006172a60d4e39f479d2d38f3c657bc8076f30d3c9e9`  
**Block**: 33502323  
**Nonce**: 10  
**Gas Used**: 39,415  

Called `authorize()` on the delegated account to register the restricted key.

### 3. Execute Call with Restricted Key
**Status**: ✅ Success  
**Transaction**: `0x7aca75a5e8ecaec6a760f82f49ea42d504c6b62449a023688957b876e1ed9d7d`  
**Block**: (latest)  
**Nonce**: 11  

Called `execute()` on the delegated account using the restricted key to invoke `targetFunction()` on the test contract.

**Verification**:
```bash
cast call 0x098Fd27df763E5361Da026412d1C8702AcB56c98 "callCount()(uint256)" --rpc-url https://sepolia.base.org
# Returns: 1
```

## Key Findings

### 1. EIP-7702 Authorization Signing
**Issue Found**: The initial signing code used `v` (27 or 28) instead of `y_parity` (0 or 1).

**Fix Applied**:
```solidity
(uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, ethSignedHash);
uint8 yParity = v - 27; // Convert recovery id to y_parity (0 or 1)
bytes memory authTuple = abi.encode(CHAIN_ID, ITHACA_IMPL, eoaNonce, yParity, r, s);
```

### 2. Cast Send Syntax
The correct syntax for EIP-7702 delegation in Foundry nightly:
```bash
cast send \
  --private-key <KEY> \
  --rpc-url <RPC> \
  --auth <IMPLEMENTATION_ADDRESS> \
  0x0000000000000000000000000000000000000000 \
  --value 0 \
  --gas-limit 100000 \
  --gas-price 1gwei
```

**Note**: 
- Requires Foundry nightly (`foundryup -b nightly`)
- `--auth` flag accepts either an address or hex-encoded signed authorization
- Gas limit must be higher than standard 21000 (EIP-7702 has higher intrinsic gas)

### 3. Nonce Management
**Issue**: Base Sepolia RPC error: `gapped-nonce tx from delegated accounts`

**Cause**: Attempted to replay a transaction with a nonce that was already used.

**Solution**: Skip already-completed transactions in the script.

## Commands Reference

### Check Delegation Status
```bash
cast code 0x29FB8276DdA3Fe8a841552CA6BF7518D0Fa9eE25 --rpc-url https://sepolia.base.org
```

### Check Account Nonce
```bash
cast nonce 0x29FB8276DdA3Fe8a841552CA6BF7518D0Fa9eE25 --rpc-url https://sepolia.base.org
```

### Check Authorized Key
```bash
cast call 0x29FB8276DdA3Fe8a841552CA6BF7518D0Fa9eE25 \
  "getKey(bytes32)(uint40,uint8,bool,bytes)" \
  0x3c05214ea15b85b7e48237aa72ff9fbf95b582eeba266365835bb2558366c5cd \
  --rpc-url https://sepolia.base.org
```

### Check Test Contract State
```bash
cast call 0x098Fd27df763E5361Da026412d1C8702AcB56c98 \
  "callCount()(uint256)" \
  --rpc-url https://sepolia.base.org
```

## Next Steps

1. **Set Permissions**: Enable the restricted key to call specific functions on specific contracts via `setCanExecute()`.

2. **Test Unauthorized Calls**: Verify that the restricted key cannot call unauthorized functions or contracts.

3. **Test Key Expiry**: Verify that expired keys are rejected.

4. **Production Deployment**: Deploy on mainnet networks with proper security review.

## Network Information
- **Network**: Base Sepolia
- **Chain ID**: 84532
- **RPC**: https://sepolia.base.org
- **Explorer**: https://sepolia.basescan.org/

## Files Modified
- `script/TestRestrictedAccount.s.sol` - Fixed authorization generation and execution flow
- Successfully ran with `--broadcast` flag on live testnet

## Conclusion
✅ EIP-7702 delegation is working correctly on Base Sepolia  
✅ Restricted key authorization is functional  
✅ Restricted key can execute authorized calls  
✅ Ready for permission testing and further integration

