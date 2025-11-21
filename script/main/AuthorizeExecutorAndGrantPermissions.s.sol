// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {GuardedExecutor} from "../../src/GuardedExecutor.sol";

/// @title AuthorizeExecutorAndGrantPermissions
/// @notice Script to authorize executor key and grant HTLC permissions via hardware wallet
/// @dev Usage (Multi-step workflow for hardware wallets):
///
///      Step 1 - Get authorization digest to sign:
///      forge script script/main/AuthorizeExecutorAndGrantPermissions.s.sol --rpc-url $RPC_URL
///
///      Step 2 - Sign the authorization digest with Ledger:
///      cast wallet sign --ledger <AUTH_DIGEST_FROM_STEP_1>
///      export SIGNATURE_AUTH=<SIGNATURE_FROM_STEP_2>
///
///      Step 3 - Run again to get permissions digest:
///      forge script script/main/AuthorizeExecutorAndGrantPermissions.s.sol --rpc-url $RPC_URL --broadcast
///
///      Step 4 - Sign the permissions digest with Ledger:
///      cast wallet sign --ledger <PERM_DIGEST_FROM_STEP_3>
///      export SIGNATURE_PERM=<SIGNATURE_FROM_STEP_4>
///
///      Step 5 - Final broadcast:
///      forge script script/main/AuthorizeExecutorAndGrantPermissions.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - HTLC_ADDRESSES: Comma-separated list of HTLC addresses (or single address)
///      - PERMISSION_ADDRESS: Address of executor to authorize and grant permissions to
///      - SIGNER_ADDRESS: Address of the signer (hardware wallet address)
///      - SIGNATURE_AUTH: (Optional) Signature for authorization step
///      - SIGNATURE_PERM: (Optional) Signature for permissions step
///      - DEPLOYER_PRIVATE_KEY: Private key to broadcast transaction (required)
contract AuthorizeExecutorAndGrantPermissions is Script {
    function run() public {
        // Load configuration from environment variables
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");
        address executorAddress = vm.envAddress("PERMISSION_ADDRESS");

        address signer;
        try vm.envAddress("SIGNER_ADDRESS") returns (address addr) {
            signer = addr;
        } catch {
            revert("SIGNER_ADDRESS environment variable is required");
        }

        // Parse HTLC addresses (comma-separated or single)
        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);

        console.log("\n========================================");
        console.log("Authorize Executor & Grant HTLC Permissions");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("Executor Address:", executorAddress);
        console.log("Signer Address:", signer);
        console.log("HTLC Addresses:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
        }
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute key hashes
        IthacaAccount.Key memory executorKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(executorAddress)
        });
        IthacaAccount.Key memory signerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer)
        });

        bytes32 executorKeyHash = solver.hash(executorKey);
        bytes32 signerKeyHash = solver.hash(signerKey);

        // Get multisig key hash from environment (from deployed.json)
        bytes32 multisigKeyHash;
        try vm.envBytes32("MULTISIG_KEY_HASH") returns (bytes32 hash) {
            multisigKeyHash = hash;
        } catch {
            // Compute multisig key hash if not provided
            address multiSigSigner = vm.envAddress("MULTISIG_SIGNER");
            IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
                expiry: 0,
                keyType: IthacaAccount.KeyType.External,
                isSuperAdmin: true,
                publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
            });
            multisigKeyHash = solver.hash(multisigKey);
        }

        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("");

        // Compute function selectors for HTLC functions
        bytes4 initiateSel = bytes4(
            keccak256("initiate(address,uint256,uint256,bytes32)")
        );
        bytes4 redeemSel = bytes4(keccak256("redeem(bytes32,bytes)"));
        bytes4 refundSel = bytes4(keccak256("refund(bytes32)"));
        bytes4 instantRefundSel = bytes4(
            keccak256("instantRefund(bytes32,bytes)")
        );

        // Step 1: Authorize executor key
        console.log("Step 1: Authorizing executor key...");
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0] = ERC7821.Call({
            to: gardenSolver,
            value: 0,
            data: abi.encodeWithSelector(
                IthacaAccount.authorize.selector,
                executorKey
            )
        });

        // Get current nonce and compute digest
        uint256 authNonce = solver.getNonce(0);
        bytes32 authDigest = solver.computeDigest(authCalls, authNonce);

        console.log("\n========================================");
        console.log("STEP 1: AUTHORIZATION - SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(authDigest));
        console.log("Signer address:", signer);
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("========================================\n");

        bytes memory authSignature;
        bool authSignatureReady;
        string memory authSigHex;
        bool authSignatureProvided;
        try vm.envString("SIGNATURE_AUTH") returns (string memory sigHexValue) {
            authSigHex = sigHexValue;
            authSignatureProvided = true;
        } catch {}

        if (authSignatureProvided) {
            // Parse the signature: format is 0x + 130 hex chars
            bytes memory sigBytes = vm.parseBytes(authSigHex);
            require(sigBytes.length == 65, "Signature must be 65 bytes");

            uint8 v;
            bytes32 r;
            bytes32 s;
            assembly {
                r := mload(add(sigBytes, 0x20))
                s := mload(add(sigBytes, 0x40))
                v := byte(0, mload(add(sigBytes, 0x60)))
            }

            // Calculate the EIP-191 "Prefixed" Hash
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", authDigest)
            );

            // Recover the address using the PREFIXED hash
            address recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);
            address recoveredAddressAlt = address(0);

            // Handle EIP-2093 malleability (v=27 vs v=28)
            if (recoveredAddress != signer) {
                uint8 vAlt = (v == 27) ? 28 : 27;
                recoveredAddressAlt = ecrecover(
                    ethSignedMessageHash,
                    vAlt,
                    r,
                    s
                );
            }

            bool isMatch = (recoveredAddress == signer) ||
                (recoveredAddressAlt == signer);

            // Fix 'v' if the alternate was the correct one
            if (recoveredAddressAlt == signer && recoveredAddress != signer) {
                v = (v == 27) ? 28 : 27;
            }

            require(
                isMatch,
                "Signature verification failed: Signer does not match (EIP-191 check)."
            );

            // Pack the signer signature: r + s + v + signerKeyHash + prehashFlag(0)
            bytes memory signerSig = abi.encodePacked(
                r,
                s,
                v,
                signerKeyHash,
                uint8(0)
            );

            // Wrap in multisig format: abi.encode(bytes[] innerSigs) || multisigKeyHash || uint8(0)
            // Since threshold = 1, we only need 1 signature
            bytes[] memory innerSignatures = new bytes[](1);
            innerSignatures[0] = signerSig;

            // Pack multisig signature: abi.encode(innerSignatures) || multisigKeyHash || uint8(0)
            authSignature = abi.encodePacked(
                abi.encode(innerSignatures),
                multisigKeyHash,
                uint8(0)
            );
            authSignatureReady = true;
        }

        if (!authSignatureReady) {
            console.log("\n========================================");
            console.log("STEP 1: GET DIGEST TO SIGN (AUTHORIZATION)");
            console.log("========================================");
            console.log("Please sign the digest with your Ledger:");
            console.log("1. Copy the digest above.");
            console.log("2. Run this command (NO --raw flag):");
            console.log("");
            console.log(
                "   cast wallet sign --ledger",
                vm.toString(authDigest)
            );
            console.log("");
            console.log("3. Export the result:");
            console.log("   export SIGNATURE_AUTH=<result>");
            console.log("4. Run this script again with --broadcast");
            console.log("========================================\n");
            return;
        }

        // Execute authorization
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(authCalls, abi.encodePacked(authNonce, authSignature));
        console.log("[OK] Executor key authorized!\n");

        // Step 2: Grant permissions to executor
        console.log("Step 2: Granting HTLC permissions to executor...");

        // Create calls for all HTLC addresses (3 functions per HTLC) + 1 for native token spend limit
        uint256 numCalls = htlcAddresses.length * 4 + 1;
        ERC7821.Call[] memory permissionCalls = new ERC7821.Call[](numCalls);

        uint256 callIndex = 0;
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            address htlc = htlcAddresses[i];

            // Grant permission to call initiate()
            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    initiateSel,
                    true
                )
            });

            // Grant permission to call redeem()
            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    redeemSel,
                    true
                )
            });

            // Grant permission to call refund()
            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    refundSel,
                    true
                )
            });

            // Grant permission to call instantRefund()
            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    instantRefundSel,
                    true
                )
            });
        }

        // for native
        permissionCalls[callIndex++] = ERC7821.Call({
            to: gardenSolver,
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setSpendLimit.selector,
                executorKeyHash,
                address(0), // Native token
                GuardedExecutor.SpendPeriod.Forever,
                100 ether // 100 ETH limit
            )
        });

        // Get current nonce and compute digest
        uint256 permNonce = solver.getNonce(0);
        bytes32 permDigest = solver.computeDigest(permissionCalls, permNonce);

        console.log("\n========================================");
        console.log("STEP 2: PERMISSIONS - SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(permDigest));
        console.log("Signer address:", signer);
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("========================================\n");

        bytes memory permSignature;
        bool permSignatureReady;
        string memory permSigHex;
        bool permSignatureProvided;
        try vm.envString("SIGNATURE_PERM") returns (string memory sigHexValue) {
            permSigHex = sigHexValue;
            permSignatureProvided = true;
        } catch {}

        if (permSignatureProvided) {
            // Parse the signature: format is 0x + 130 hex chars
            bytes memory sigBytes = vm.parseBytes(permSigHex);
            require(sigBytes.length == 65, "Signature must be 65 bytes");

            uint8 v;
            bytes32 r;
            bytes32 s;
            assembly {
                r := mload(add(sigBytes, 0x20))
                s := mload(add(sigBytes, 0x40))
                v := byte(0, mload(add(sigBytes, 0x60)))
            }

            // Calculate the EIP-191 "Prefixed" Hash
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", permDigest)
            );

            // Recover the address using the PREFIXED hash
            address recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);
            address recoveredAddressAlt = address(0);

            // Handle EIP-2093 malleability (v=27 vs v=28)
            if (recoveredAddress != signer) {
                uint8 vAlt = (v == 27) ? 28 : 27;
                recoveredAddressAlt = ecrecover(
                    ethSignedMessageHash,
                    vAlt,
                    r,
                    s
                );
            }

            bool isMatch = (recoveredAddress == signer) ||
                (recoveredAddressAlt == signer);

            // Fix 'v' if the alternate was the correct one
            if (recoveredAddressAlt == signer && recoveredAddress != signer) {
                v = (v == 27) ? 28 : 27;
            }

            require(
                isMatch,
                "Signature verification failed: Signer does not match (EIP-191 check)."
            );

            // Pack the signer signature: r + s + v + signerKeyHash + prehashFlag(0)
            bytes memory signerSig = abi.encodePacked(
                r,
                s,
                v,
                signerKeyHash,
                uint8(0)
            );

            // Wrap in multisig format: abi.encode(bytes[] innerSigs) || multisigKeyHash || uint8(0)
            // Since threshold = 1, we only need 1 signature
            bytes[] memory innerSignatures = new bytes[](1);
            innerSignatures[0] = signerSig;

            // Pack multisig signature: abi.encode(innerSignatures) || multisigKeyHash || uint8(0)
            permSignature = abi.encodePacked(
                abi.encode(innerSignatures),
                multisigKeyHash,
                uint8(0)
            );
            permSignatureReady = true;
        }

        if (!permSignatureReady) {
            console.log("\n========================================");
            console.log("STEP 2: GET DIGEST TO SIGN (PERMISSIONS)");
            console.log("========================================");
            console.log("Please sign the digest with your Ledger:");
            console.log("1. Copy the digest above.");
            console.log("2. Run this command (NO --raw flag):");
            console.log("");
            console.log(
                "   cast wallet sign --ledger",
                vm.toString(permDigest)
            );
            console.log("");
            console.log("3. Export the result:");
            console.log("   export SIGNATURE_PERM=<result>");
            console.log("4. Run this script again with --broadcast");
            console.log("========================================\n");
            return;
        }

        // Execute permissions grant
        solver.execute(
            permissionCalls,
            abi.encodePacked(permNonce, permSignature)
        );
        vm.stopBroadcast();

        console.log("\n[OK] All operations completed successfully!");
        console.log("Executor:", executorAddress);
        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
        console.log("Permissions granted for:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    - initiate(address,uint256,uint256,bytes32)");
            console.log("    - redeem(bytes32,bytes)");
            console.log("    - refund(bytes32)");
        }
        console.log("Spend permissions:");
        console.log("  - Native token (address(0)): 100 ETH (Forever period)");
        console.log("========================================\n");
    }

    /// @notice Parse comma-separated addresses or single address
    function _parseAddresses(
        string memory addressesStr
    ) internal view returns (address[] memory) {
        // Check if it contains comma
        bytes memory strBytes = bytes(addressesStr);
        bool hasComma = false;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1(",")) {
                hasComma = true;
                break;
            }
        }

        if (!hasComma) {
            // Single address
            address[] memory singleResult = new address[](1);
            singleResult[0] = vm.parseAddress(addressesStr);
            return singleResult;
        }

        // Multiple addresses - count commas first
        uint256 commaCount = 0;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1(",")) {
                commaCount++;
            }
        }

        address[] memory result = new address[](commaCount + 1);
        uint256 count = 0;
        uint256 start = 0;

        for (uint256 i = 0; i <= strBytes.length; i++) {
            if (i == strBytes.length || strBytes[i] == bytes1(",")) {
                if (i > start) {
                    bytes memory addrBytes = new bytes(i - start);
                    for (uint256 j = start; j < i; j++) {
                        addrBytes[j - start] = strBytes[j];
                    }
                    result[count++] = vm.parseAddress(string(addrBytes));
                }
                start = i + 1;
            }
        }

        // Resize array to actual count
        address[] memory finalResult = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            finalResult[i] = result[i];
        }
        return finalResult;
    }
}
