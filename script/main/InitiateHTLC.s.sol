// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title InitiateHTLC
/// @notice Production script to initiate an HTLC order via signer1
/// @dev Usage (Two-step workflow for hardware wallets):
///
///      Step 1 - Get digest to sign:
///      forge script script/main/InitiateHTLC.s.sol --rpc-url $RPC_URL
///
///      Step 2 - Sign the digest with Ledger (Standard Message Signing):
///      cast wallet sign --ledger <DIGEST_FROM_STEP_1>
///      (Note: Do NOT use --raw. Let Ledger sign it as a message)
///
///      Step 3 - Set signature and broadcast:
///      export SIGNATURE=<SIGNATURE_FROM_STEP_2>
///      forge script script/main/InitiateHTLC.s.sol --rpc-url $RPC_URL --broadcast --ledger
contract InitiateHTLC is Script {
    function run() public {
        // ... [Configuration loading remains the same] ...
        address gardenSolver = address(
            0x8dc5F8D658f12375CA9710B8D5fB6d94d7B3AaCB
        );
        address htlc = address(0xd1E0Ba2b165726b3a6051b765d4564d030FDcf50);
        address redeemer = address(0x07309CeF4FA8F6f34b23940eec887957c7C230bC);
        uint256 timelock = 10000;
        uint256 amount = 1;
        bytes32 secretHash = keccak256("secret_again");

        address signer1;
        try vm.envAddress("SIGNER_ADDRESS") returns (address addr) {
            signer1 = addr;
        } catch {
            signer1 = address(0xD5c78816dD92E81a075129C1D6a6dC5F0D0FF1c8);
        }

        console.log("\n========================================");
        console.log("Initiate HTLC Order");
        console.log("========================================");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        bytes32 signer1KeyHash = solver.hash(signer1Key);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: htlc,
            value: 0,
            data: abi.encodeWithSignature(
                "initiate(address,uint256,uint256,bytes32)",
                redeemer,
                timelock,
                amount,
                secretHash
            )
        });

        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);

        console.log("\n========================================");
        console.log("SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(digest));
        console.log("Signer address:", signer1);
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

            // --- FIX STARTS HERE ---

            // 1. Calculate the EIP-191 "Prefixed" Hash
            // This mimics what the Ledger triggers internally when you do 'sign message'
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
            );

            // 2. Recover the address using the PREFIXED hash
            address recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);
            address recoveredAddressAlt = address(0);

            // Handle EIP-2093 malleability (v=27 vs v=28)
            if (recoveredAddress != signer1) {
                uint8 vAlt = (v == 27) ? 28 : 27;
                recoveredAddressAlt = ecrecover(
                    ethSignedMessageHash,
                    vAlt,
                    r,
                    s
                );
            }

            bool isMatch = (recoveredAddress == signer1) ||
                (recoveredAddressAlt == signer1);

            // Fix 'v' if the alternate was the correct one
            if (recoveredAddressAlt == signer1 && recoveredAddress != signer1) {
                v = (v == 27) ? 28 : 27;
            }

            // --- LOGGING FOR DEBUGGING ---
            console.log("\n========================================");
            console.log("SIGNATURE VERIFICATION");
            console.log("========================================");
            console.log("Original Digest:", vm.toString(digest));
            console.log(
                "Prefixed Hash (EIP-191):",
                vm.toString(ethSignedMessageHash)
            );
            console.log("----------------------------------------");
            console.log("Expected Signer:", signer1);
            console.log(
                "Recovered Signer:",
                isMatch ? signer1 : recoveredAddress
            );
            console.log("Match Success:", isMatch ? "YES" : "NO");
            console.log("========================================\n");

            require(
                isMatch,
                "Signature verification failed: Signer does not match (EIP-191 check)."
            );

            // Pack the signature: r + s + v + keyHash + prehashFlag(0)
            // We use uint8(0) because SignatureCheckerLib on-chain will see the
            // raw signature fails, apply the prefix itself, and then it will pass.
            signature = abi.encodePacked(r, s, v, signer1KeyHash, uint8(0));
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

        vm.startBroadcast();
        solver.execute(calls, abi.encodePacked(nonce, signature));
        vm.stopBroadcast();

        // Compute order ID (same as HTLC contract does)
        bytes32 orderID = keccak256(
            abi.encode(
                block.chainid,
                secretHash,
                gardenSolver, // initiator
                redeemer,
                timelock,
                amount,
                htlc
            )
        );

        console.log("\nHTLC order initiated successfully!");
        console.log("Order ID:", vm.toString(orderID));
        console.log("Secret Hash:", vm.toString(secretHash));
        console.log("Amount:", amount);
        console.log("Redeemer:", redeemer);
        console.log("Timelock:", timelock);
        console.log("========================================\n");
    }
}
