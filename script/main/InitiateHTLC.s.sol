// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title InitiateHTLC
/// @notice Production script to initiate an HTLC order via signer1
/// @dev Usage:
///      forge script script/InitiateHTLC.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - HTLC_ADDRESS: Address of HTLC contract
///      - REDEEMER_ADDRESS: Address that can redeem the HTLC
///      - TIMELOCK: Block number timelock for the HTLC
///      - AMOUNT: Amount of tokens to lock (in raw units, account for decimals)
///      - SECRET_HASH: bytes32 hash of the secret (keccak256 of secret)
///      - SIGNER_ADDRESS: Address of signer 1 (for hardware wallets)
///      - SIGNER_PRIVATE_KEY: Private key of signer 1 (optional, for software wallets)
///      - SIGNATURE: Full signature hex string from 'cast wallet sign --ledger' (0x + 130 hex chars)
///      - SIGNATURE_R, SIGNATURE_S, SIGNATURE_V: Alternative - pre-signed signature components
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
        bytes32 secretHash = bytes32(vm.randomBytes(32));

        // Load signer address (required for hardware wallets)
        address signer1;
        try vm.envAddress("SIGNER_ADDRESS") returns (address addr) {
            signer1 = addr;
        } catch {
            // Fallback: try to derive from private key if provided
            try vm.envUint("SIGNER_PRIVATE_KEY") returns (uint256 privateKey) {
                signer1 = vm.addr(privateKey);
            } catch {
                // Default fallback
                signer1 = address(0xD5c78816dD92E81a075129C1D6a6dC5F0D0FF1c8);
            }
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
            value: 0,
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
        console.log("========================================\n");

        // Try to get pre-signed signature from environment (for hardware wallets)
        uint8 v;
        bytes32 r;
        bytes32 s;

        // First try: Get full signature string from cast wallet sign --ledger
        try vm.envString("SIGNATURE") returns (string memory sigHex) {
            // Parse the signature: format is 0x + 130 hex chars (65 bytes: r=32, s=32, v=1)
            bytes memory sigBytes = vm.parseBytes(sigHex);
            require(sigBytes.length == 65, "Signature must be 65 bytes");

            // Extract r, s, v from signature bytes
            // sigBytes layout: [length][r (32 bytes)][s (32 bytes)][v (1 byte)]
            assembly {
                // r is at offset 32 (skip length word)
                r := mload(add(sigBytes, 32))
                // s is at offset 64 (skip length + r)
                s := mload(add(sigBytes, 64))
                // v is at offset 96, but we need just the first byte
                v := byte(0, mload(add(sigBytes, 96)))
            }

            console.log("Using signature from SIGNATURE environment variable");
        } catch {
            // Second try: Get separate R, S, V components
            try vm.envBytes32("SIGNATURE_R") returns (bytes32 rEnv) {
                r = rEnv;
                s = vm.envBytes32("SIGNATURE_S");
                v = uint8(vm.envUint("SIGNATURE_V"));
                console.log(
                    "Using signature from SIGNATURE_R/S/V environment variables"
                );
            } catch {
                // Third try: Sign with private key if available
                try vm.envUint("SIGNER_PRIVATE_KEY") returns (
                    uint256 privateKey
                ) {
                    (v, r, s) = vm.sign(privateKey, digest);
                    console.log("Signed using private key from environment");
                } catch {
                    // Last resort: try to use signer from broadcast (may not work with Ledger for message signing)
                    console.log(
                        "WARNING: Attempting to sign with broadcast signer..."
                    );
                    console.log(
                        "If using Ledger, you must provide SIGNATURE environment variable"
                    );
                    (v, r, s) = vm.sign(digest);
                }
            }
        }

        // Recover address from signature for debugging
        address recoveredAddress = ecrecover(digest, v, r, s);
        console.log("\n========================================");
        console.log("SIGNATURE VERIFICATION");
        console.log("========================================");
        console.log("Expected signer:", signer1);
        console.log("Recovered address:", recoveredAddress);
        console.log("Match:", recoveredAddress == signer1 ? "YES" : "NO");
        console.log("========================================\n");

        bytes memory signature = abi.encodePacked(
            r,
            s,
            v,
            signer1KeyHash,
            uint8(0)
        );

        // Execute
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
