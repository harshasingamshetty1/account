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
///      Step 2 - Sign the digest with Ledger:
///      cast wallet sign --ledger <DIGEST_FROM_STEP_1>
///
///      Step 3 - Set signature and broadcast:
///      export SIGNATURE=<SIGNATURE_FROM_STEP_2>
///      forge script script/main/InitiateHTLC.s.sol --rpc-url $RPC_URL --broadcast --ledger
///
///      Required environment variables:
///      - SIGNATURE: Full signature hex string from 'cast wallet sign --ledger' (0x + 130 hex chars)
///                   If not provided, script will output digest and exit (for step 1)
contract InitiateHTLC is Script {
    function run() public {
        // Load configuration from environment variables
        address gardenSolver = address(
            0x1DBb9E08655Aaf36B05502020e3cA1eA376932c5
        );
        address htlc = address(0x6eb1809A719F494065c35eeeF3ff1c03d4Ffa786);
        address redeemer = address(0x07309CeF4FA8F6f34b23940eec887957c7C230bC);
        uint256 timelock = 10000;
        uint256 amount = 1;
        bytes32 secretHash = keccak256("secret");

        // Load signer address (required for hardware wallets)
        address signer1;
        try vm.envAddress("SIGNER_ADDRESS") returns (address addr) {
            signer1 = addr;
        } catch {
            // Default fallback
            signer1 = address(0xD5c78816dD92E81a075129C1D6a6dC5F0D0FF1c8);
        }

        console.log("\n========================================");
        console.log("Initiate HTLC Order");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("HTLC:", htlc);
        console.log("Redeemer:", redeemer);
        console.log("Timelock:", timelock);
        console.log("Amount:", amount);
        console.log("Secret Hash:", vm.toString(secretHash));
        console.log("Signer 1:", signer1);
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute signer1 key hash
        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        bytes32 signer1KeyHash = solver.hash(signer1Key);

        // Create the initiate call
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: htlc,
            value: 1,
            data: abi.encodeWithSignature(
                "initiate(address,uint256,uint256,bytes32)",
                redeemer,
                timelock,
                amount,
                secretHash
            )
        });

        console.log("data:", vm.toString(calls[0].data));

        // Get nonce and compute digest
        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);

        console.log("\n========================================");
        console.log("SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(digest));
        console.log("Signer address:", signer1);
        console.log("Nonce:", nonce);
        console.log("========================================\n");

        // Resolve signature input (hardware wallet signature only)
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
            // Parse the signature: format is 0x + 130 hex chars (65 bytes: r=32, s=32, v=1)
            bytes memory sigBytes = vm.parseBytes(sigHex);
            require(sigBytes.length == 65, "Signature must be 65 bytes");

            assembly {
                r := mload(add(sigBytes, 0x20))
                s := mload(add(sigBytes, 0x40))
                v := byte(0, mload(add(sigBytes, 0x60)))
            }

            console.log("Raw signature hex:", sigHex);
            console.log("Parsed signature length:", sigBytes.length);

            bytes memory reconstructed = abi.encodePacked(r, s, v);
            bool extractionValid = true;
            for (uint256 i = 0; i < 65 && i < sigBytes.length; i++) {
                if (reconstructed[i] != sigBytes[i]) {
                    extractionValid = false;
                    break;
                }
            }
            console.log(
                "Extraction verification:",
                extractionValid ? "PASSED" : "FAILED"
            );

            address recoveredAddress = ecrecover(digest, v, r, s);
            address recoveredAddressAlt = address(0);

            if (recoveredAddress != signer1) {
                uint8 vAlt = (v == 27) ? 28 : 27;
                recoveredAddressAlt = ecrecover(digest, vAlt, r, s);
            }

            console.log("\n========================================");
            console.log("SIGNATURE VERIFICATION");
            console.log("========================================");
            console.log("Raw digest:", vm.toString(digest));
            console.log("Given/Expected signer address:", signer1);
            console.log("Recovered address (v=", v, "):", recoveredAddress);
            if (recoveredAddressAlt != address(0)) {
                console.log(
                    "Recovered address (v=",
                    (v == 27) ? 28 : 27,
                    "):",
                    recoveredAddressAlt
                );
            }
            console.log("Signature r:", vm.toString(r));
            console.log("Signature s:", vm.toString(s));
            console.log("Signature v:", v);

            bool isMatch = (recoveredAddress == signer1) ||
                (recoveredAddressAlt == signer1);
            console.log("Match (EIP-191):", isMatch ? "YES" : "NO");

    

            address recoveredRaw = ecrecover(digest, v, r, s);
            address recoveredRawAlt = address(0);
            if (recoveredRaw != signer1) {
                uint8 vAlt = (v == 27) ? 28 : 27;
                recoveredRawAlt = ecrecover(digest, vAlt, r, s);
            }

            bool rawMatch = (recoveredRaw == signer1) ||
                (recoveredRawAlt == signer1);
            console.log("\n--- Contract Verification (Raw Digest) ---");
            console.log("  ^ THIS is what the contract actually checks!");
            console.log(
                "Recovered address from raw digest (v=",
                v,
                "):",
                recoveredRaw
            );
            if (recoveredRawAlt != address(0)) {
                console.log(
                    "Recovered address from raw digest (v=",
                    (v == 27) ? 28 : 27,
                    "):",
                    recoveredRawAlt
                );
            }
            console.log(
                "Will pass contract verification:",
                rawMatch ? "YES" : "NO"
            );

            if (!isMatch) {
                console.log(
                    "\nWARNING: Signature does not match expected signer!"
                );
                console.log("Please verify:");
                console.log("  - Ledger address matches:", signer1);
                console.log("  - You signed the exact digest shown above");
                console.log(
                    "  - Use 'cast wallet address -l' to verify Ledger address"
                );
            }

            if (!rawMatch) {
                console.log("\n========================================");
                console.log("CRITICAL: Signature mismatch detected!");
                console.log("========================================");
                console.log("EXPLANATION:");
                console.log(
                    "  - Your signature was signed with EIP-191 prefix (Ledger default)"
                );
                console.log(
                    "  - EIP-191 verification passes because signature matches EIP-191 digest"
                );
                console.log(
                    "  - BUT the contract verifies against RAW digest (no prefix)"
                );
                console.log(
                    "  - Since you signed EIP-191 digest, it won't work for raw digest"
                );
                console.log("\nSOLUTION:");
                console.log(
                    "  You MUST sign the RAW digest (without EIP-191 prefix):"
                );
                console.log(
                    "  cast wallet sign --ledger --raw",
                    vm.toString(digest)
                );
                console.log(
                    "\n  Then set SIGNATURE and run again with --broadcast"
                );
                console.log("========================================");
            }

            console.log("========================================\n");

            require(
                isMatch,
                "Signature does not match expected signer address"
            );

            require(
                rawMatch,
                "Signature mismatch: You signed with EIP-191 prefix, but contract needs raw digest signature. Use: cast wallet sign --ledger --raw <digest>"
            );

            if (recoveredRawAlt == signer1 && recoveredRaw != signer1) {
                v = (v == 27) ? 28 : 27;
                console.log("Using alternate v value for contract:", v);
            } else if (
                recoveredAddressAlt == signer1 && recoveredAddress != signer1
            ) {
                uint8 testV = (v == 27) ? 28 : 27;
                address testRecovered = ecrecover(digest, testV, r, s);
                if (testRecovered == signer1) {
                    v = testV;
                    console.log("Using alternate v value for contract:", v);
                }
            }

            signature = abi.encodePacked(r, s, v, signer1KeyHash, uint8(0));
            signatureReady = true;

            console.log("Signature verified! Proceeding with execution...\n");
        }

        if (!signatureReady) {
            console.log("\n========================================");
            console.log("STEP 1: GET DIGEST TO SIGN");
            console.log("========================================");
            console.log("No SIGNATURE environment variable found.");
            console.log(
                "Please sign the RAW digest shown above with your Ledger:"
            );
            console.log(
                "  cast wallet sign --ledger --raw",
                vm.toString(digest)
            );
            console.log(
                "\nThen set the signature and run again with --broadcast:"
            );
            console.log("  export SIGNATURE=<signature_from_cast>");
            console.log(
                "  forge script script/main/InitiateHTLC.s.sol --rpc-url $RPC_URL --broadcast --ledger"
            );
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
