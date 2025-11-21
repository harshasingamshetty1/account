// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

interface IHTLC {
    function token() external view returns (address);
}

/// @title ApproveHTLCToken
/// @notice Production script to approve tokens from GardenSolver to HTLC contract(s) via hardware wallet
/// @dev Usage (Two-step workflow for hardware wallets):
///
///      Step 1 - Get digest to sign:
///      forge script script/main/ApproveHTLCToken.s.sol --rpc-url $RPC_URL
///
///      Step 2 - Sign the digest with Ledger (Standard Message Signing):
///      cast wallet sign --ledger <DIGEST_FROM_STEP_1>
///      (Note: Do NOT use --raw. Let Ledger sign it as a message)
///
///      Step 3 - Set signature and broadcast:
///      export SIGNATURE=<SIGNATURE_FROM_STEP_2>
///      forge script script/main/ApproveHTLCToken.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - HTLC_ADDRESSES: Comma-separated list of HTLC addresses (or single address)
///                        Each HTLC's token will be fetched and approved to that HTLC
///      - SIGNER_ADDRESS: Address of the signer (hardware wallet address)
///      - SIGNATURE: (Optional) Signature from hardware wallet (for Step 3)
///      - DEPLOYER_PRIVATE_KEY: Private key to broadcast transaction (required)
contract ApproveHTLCToken is Script {
    function run() public {
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");

        // Parse HTLC addresses (comma-separated or single)
        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);
        require(htlcAddresses.length > 0, "No HTLC addresses provided");

        // Fetch token from each HTLC contract
        address[] memory tokens = new address[](htlcAddresses.length);
        console.log("\nFetching tokens from HTLC contracts:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            IHTLC htlcContract = IHTLC(htlcAddresses[i]);
            tokens[i] = htlcContract.token();
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
        }

        address signer;
        try vm.envAddress("SIGNER_ADDRESS") returns (address addr) {
            signer = addr;
        } catch {
            revert("SIGNER_ADDRESS environment variable is required");
        }

        console.log("\n========================================");
        console.log("Approve Tokens to HTLCs (Hardware Wallet)");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("HTLC Addresses and Tokens:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
        }
        console.log("Signer:", signer);
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

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

        // Also compute signer key hash for reference
        IthacaAccount.Key memory signerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer)
        });
        bytes32 signerKeyHash = solver.hash(signerKey);

        // Create approval calls - each HTLC gets approval for its own token
        ERC7821.Call[] memory calls = new ERC7821.Call[](htlcAddresses.length);
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            calls[i] = ERC7821.Call({
                to: tokens[i], // Use the token specific to this HTLC
                value: 0,
                data: abi.encodeWithSignature(
                    "approve(address,uint256)",
                    htlcAddresses[i], // Approve to this specific HTLC
                    type(uint256).max
                )
            });
        }

        // Get nonce and compute digest
        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);

        console.log("\n========================================");
        console.log("SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(digest));
        console.log("Signer address:", signer);
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("========================================\n");

        bytes memory signature;
        bool signatureReady;
        uint8 v;
        bytes32 r;
        bytes32 s;

        string memory sigHex;
        bool signatureProvided;
        try vm.envString("SIGNATURE") returns (string memory sigHexValue) {
            sigHex = sigHexValue;
            signatureProvided = true;
        } catch {}

        if (signatureProvided) {
            // Parse the signature: format is 0x + 130 hex chars
            bytes memory sigBytes = vm.parseBytes(sigHex);
            require(sigBytes.length == 65, "Signature must be 65 bytes");

            assembly {
                r := mload(add(sigBytes, 0x20))
                s := mload(add(sigBytes, 0x40))
                v := byte(0, mload(add(sigBytes, 0x60)))
            }

            // Calculate the EIP-191 "Prefixed" Hash
            // This mimics what the Ledger triggers internally when you do 'sign message'
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
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

            // Logging for debugging
            console.log("\n========================================");
            console.log("SIGNATURE VERIFICATION");
            console.log("========================================");
            console.log("Original Digest:", vm.toString(digest));
            console.log(
                "Prefixed Hash (EIP-191):",
                vm.toString(ethSignedMessageHash)
            );
            console.log("----------------------------------------");
            console.log("Expected Signer:", signer);
            console.log(
                "Recovered Signer:",
                isMatch ? signer : recoveredAddress
            );
            console.log("Match Success:", isMatch ? "YES" : "NO");
            console.log("========================================\n");

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
            signature = abi.encodePacked(
                abi.encode(innerSignatures),
                multisigKeyHash,
                uint8(0)
            );
            signatureReady = true;
        }

        if (!signatureReady) {
            console.log("\n========================================");
            console.log("STEP 1: GET DIGEST TO SIGN");
            console.log("========================================");
            console.log("Please sign the digest with your Ledger:");
            console.log("1. Copy the digest above.");
            console.log("2. Run this command (NO --raw flag):");
            console.log("");
            console.log("   cast wallet sign --ledger", vm.toString(digest));
            console.log("");
            console.log("3. Export the result:");
            console.log("   export SIGNATURE=<result>");
            console.log("4. Run this script again with --broadcast");
            console.log("========================================\n");
            return;
        }

        // Execute
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(calls, abi.encodePacked(nonce, signature));
        vm.stopBroadcast();

        // Verify approvals - check each HTLC's token allowance
        console.log("\n[OK] Tokens approved successfully!");
        console.log("Allowances:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            (bool success, bytes memory data) = tokens[i].staticcall(
                abi.encodeWithSignature(
                    "allowance(address,address)",
                    gardenSolver,
                    htlcAddresses[i]
                )
            );
            require(success, "Failed to check allowance");
            uint256 allowance = abi.decode(data, (uint256));
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
            console.log("    Allowance:", allowance);
        }
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
